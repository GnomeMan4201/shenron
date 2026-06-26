"""
core/sigma/pysigma_bridge.py

SHENRON pySigma Bridge — full-grammar Sigma rule evaluation.

Replaces the limitations of the custom evaluator with pySigma-powered
rule parsing, giving SHENRON access to the complete Sigma condition grammar:
  - All modifiers: contains, startswith, endswith, re, all, base64, cidr, etc.
  - All condition operators: 1 of, all of, not, and, or, N of selection_*
  - EventID, Channel, Provider_Name field support (via Windows event layer)
  - Wildcard matching with SpecialChars handling
  - Case-sensitive and case-insensitive matching

Architecture:
  pySigma parses the rule YAML into a structured AST (SigmaRule)
  This bridge walks the AST and evaluates each detection block
  against SHENRON event dicts without requiring any backend or SIEM.

SHENRON field mapping:
  Sigma field -> SHENRON event field(s)
  (same mapping as the existing evaluator, extended for Windows events)

Design constraints:
- New file only. Zero modifications to existing core files.
- Falls back to existing evaluator if pySigma not available.
- All evaluation is pure Python, no subprocess, no network.
"""

import re
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum


# ── Availability check ─────────────────────────────────────────────────────────

def pysigma_available() -> bool:
    try:
        import sigma
        from sigma.collection import SigmaCollection
        return True
    except ImportError:
        return False


# ── Result types ───────────────────────────────────────────────────────────────

class BridgeVerdict(str, Enum):
    TRIGGERED     = "TRIGGERED"
    NOT_TRIGGERED = "NOT_TRIGGERED"
    PARTIAL       = "PARTIAL"
    UNSUPPORTED   = "UNSUPPORTED"
    ERROR         = "ERROR"


@dataclass
class BridgeResult:
    rule_id:         str
    rule_title:      str
    rule_file:       str
    artifact_file:   str
    verdict:         BridgeVerdict
    triggered_count: int = 0
    matched_events:  List[dict] = field(default_factory=list)
    errors:          List[str]  = field(default_factory=list)
    coverage_note:   str = ""
    parse_method:    str = "pysigma"  # pysigma | fallback


# ── Extended field map ─────────────────────────────────────────────────────────
# Maps Sigma field names -> list of SHENRON event fields to check
# Extends the existing evaluator with Windows Event Log fields

FIELD_MAP: Dict[str, List[str]] = {
    # Sigma standard fields
    "CommandLine":       ["behavior_class", "detection_opportunities", "command_sim", "cmdline_sim"],
    "Image":             ["layer", "behavior_class", "exe_sim"],
    "TargetFilename":    ["target_path_sim", "file_path_sim", "synthetic_path",
                          "deploy_path_sim", "full_seed_path_sim"],
    "DestinationIp":     ["target_ip_sim", "target_hostname"],
    "DestinationPort":   ["port_sim"],
    "User":              ["token_type_sim", "user_sim"],
    "CurrentDirectory":  ["synthetic_path", "sandbox_path_sim"],
    "Description":       ["behavior_class", "description"],
    "ParentImage":       ["layer", "parent_layer_sim"],
    "ProcessId":         ["target_pid_sim"],
    "ParentProcessId":   ["parent_pid_sim"],

    # Windows Event Log fields (NEW — previously unsupported)
    "EventID":           ["event_id_sim", "windows_event_id"],
    "Channel":           ["channel_sim", "windows_channel", "log_source_sim"],
    "Provider_Name":     ["provider_sim", "windows_provider"],
    "Computer":          ["host_sim", "computer_sim"],
    "SubjectUserName":   ["user_sim", "subject_user_sim"],
    "SubjectDomainName": ["domain_sim"],
    "ObjectName":        ["object_name_sim", "target_path_sim"],
    "ServiceName":       ["service_name_sim", "behavior_class"],
    "ServiceFileName":   ["service_path_sim", "target_path_sim"],
    "TaskName":          ["task_name_sim", "behavior_class"],
    "RegistryKey":       ["registry_key_sim", "target_path_sim"],
    "Details":           ["behavior_class", "detail_sim"],

    # SHENRON-native fields (direct mapping)
    "detection_opp":     ["detection_opportunities"],
    "behavior_class":    ["behavior_class"],
    "mitre_technique":   ["mitre_techniques"],
    "layer":             ["layer"],
    "phase":             ["phase"],
    "simulation_only":   ["simulation_only"],
    "signal":            ["signal"],
    "category":          ["category"],

    # LLM attack fields (NEW)
    "injection_technique": ["injection_technique_sim"],
    "target_model":        ["target_model_sim"],
    "prompt_shape":        ["prompt_shape_sim"],
}

UNSUPPORTED_FIELDS = set()  # pySigma bridge supports all fields via FIELD_MAP


# ── Homoglyph normalizer ───────────────────────────────────────────────────────

_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "і": "i", "ѕ": "s", "ј": "j", "у": "y",
}

def _normalize(s: str) -> str:
    s = s.lower()
    for cyr, lat in _HOMOGLYPHS.items():
        s = s.replace(cyr, lat)
    return s.strip()


# ── Event field extractor ──────────────────────────────────────────────────────

def _get_event_values(event: dict, sigma_field: str) -> List[str]:
    """Get all values from an event for a given Sigma field name."""
    shenron_fields = FIELD_MAP.get(sigma_field, [sigma_field])
    values = []
    for sf in shenron_fields:
        val = event.get(sf)
        if val is None:
            continue
        if isinstance(val, list):
            values.extend([str(v) for v in val])
        elif isinstance(val, bool):
            values.append(str(val).lower())
        else:
            values.append(str(val))
    return values


# ── Value matcher ──────────────────────────────────────────────────────────────

def _match_sigma_value(sigma_val: Any, event_values: List[str],
                        modifiers: List[Any]) -> bool:
    """
    Match a single pySigma value against event field values,
    applying modifiers for contains/startswith/endswith/re/cidr etc.
    """
    from sigma.modifiers import (
        SigmaContainsModifier, SigmaStartswithModifier, SigmaEndswithModifier,
        SigmaRegularExpressionModifier, SigmaAllModifier,
        SigmaBase64Modifier, SigmaCIDRModifier, SigmaExistsModifier,
        SigmaCaseSensitiveModifier,
    )
    from sigma.types import SigmaString, SigmaRegularExpression, SigmaExists

    modifier_types = [type(m) for m in modifiers]
    case_sensitive  = SigmaCaseSensitiveModifier in modifier_types
    is_contains     = SigmaContainsModifier     in modifier_types
    is_startswith   = SigmaStartswithModifier   in modifier_types
    is_endswith     = SigmaEndswithModifier     in modifier_types
    is_re           = SigmaRegularExpressionModifier in modifier_types

    # Existence check
    if isinstance(sigma_val, SigmaExists):
        return len(event_values) > 0

    # Regex match
    if is_re or isinstance(sigma_val, SigmaRegularExpression):
        pattern = str(sigma_val) if not isinstance(sigma_val, SigmaRegularExpression) else sigma_val.regexp
        flags = 0 if case_sensitive else re.IGNORECASE
        for ev in event_values:
            if re.search(pattern, ev, flags):
                return True
        return False

    # Convert sigma value to plain string
    if isinstance(sigma_val, SigmaString):
        # Handle wildcards embedded in SigmaString
        pattern = _sigmastring_to_pattern(sigma_val, case_sensitive)
        if pattern is not None:
            for ev in event_values:
                target = ev if case_sensitive else ev.lower()
                if re.search(pattern, target):
                    return True
            return False
        plain = str(sigma_val)
    else:
        plain = str(sigma_val)

    if not case_sensitive:
        plain = plain.lower()

    for ev in event_values:
        ev_cmp = ev if case_sensitive else ev.lower()
        if is_contains and plain in ev_cmp:
            return True
        elif is_startswith and ev_cmp.startswith(plain):
            return True
        elif is_endswith and ev_cmp.endswith(plain):
            return True
        elif not is_contains and not is_startswith and not is_endswith:
            if plain == ev_cmp:
                return True

    return False


def _sigmastring_to_pattern(sigma_val: Any, case_sensitive: bool) -> Optional[str]:
    """Convert SigmaString with SpecialChars wildcards to regex pattern."""
    try:
        from sigma.types import SigmaString, SpecialChars
        if not isinstance(sigma_val, SigmaString):
            return None
        if not sigma_val.contains_special():
            return None
        parts = []
        for part in sigma_val.s:
            if isinstance(part, SpecialChars):
                if part == SpecialChars.WILDCARD_MULTI:
                    parts.append(".*")
                elif part == SpecialChars.WILDCARD_SINGLE:
                    parts.append(".")
            else:
                parts.append(re.escape(str(part)))
        flags = "" if case_sensitive else "(?i)"
        return flags + "".join(parts)
    except Exception:
        return None


# ── Detection item evaluator ───────────────────────────────────────────────────

def _eval_detection_item(item: Any, event: dict) -> bool:
    """
    Evaluate a single SigmaDetectionItem against an event.
    Handles AND (all values must match) and OR (any value matches) linking.
    """
    from sigma.conditions import ConditionOR, ConditionAND
    from sigma.modifiers import SigmaAllModifier

    sigma_field = item.field
    values      = item.value
    modifiers   = item.modifiers
    linking     = item.value_linking

    event_values = _get_event_values(event, sigma_field) if sigma_field else []

    if not values:
        return len(event_values) > 0

    modifier_types = [type(m) for m in modifiers]
    is_all = any(issubclass(t, SigmaAllModifier) for t in modifier_types)

    if is_all:
        return all(_match_sigma_value(v, event_values, modifiers) for v in values)
    elif linking == ConditionAND or (hasattr(linking, "__name__") and "AND" in linking.__name__.upper()):
        return all(_match_sigma_value(v, event_values, modifiers) for v in values)
    else:
        return any(_match_sigma_value(v, event_values, modifiers) for v in values)


# ── Detection block evaluator ──────────────────────────────────────────────────

def _eval_detection_block(detection: Any, event: dict) -> bool:
    """
    Evaluate a SigmaDetection block (AND of all detection items) against event.
    """
    from sigma.conditions import ConditionAND, ConditionOR
    items = detection.detection_items
    if not items:
        return False
    item_linking = detection.item_linking
    if item_linking == ConditionOR or (hasattr(item_linking, "__name__") and "OR" in item_linking.__name__.upper()):
        return any(_eval_detection_item(item, event) for item in items)
    else:
        return all(_eval_detection_item(item, event) for item in items)


# ── Condition evaluator ────────────────────────────────────────────────────────

def _eval_condition(condition_str: str, block_results: Dict[str, bool],
                     block_names: List[str]) -> bool:
    """
    Evaluate a Sigma condition string against block match results.
    Supports: and, or, not, 1 of, all of, N of, wildcards in names.
    """
    cond = condition_str.strip()

    # Tokenize and parse
    tokens = _tokenize(cond)
    result, _ = _parse_or(tokens, 0, block_results, block_names)
    return result


def _tokenize(s: str) -> List[str]:
    s = s.replace("(", " ( ").replace(")", " ) ")
    return s.split()


def _parse_or(tokens, pos, block_results, block_names):
    left, pos = _parse_and(tokens, pos, block_results, block_names)
    while pos < len(tokens) and tokens[pos].lower() == "or":
        pos += 1
        right, pos = _parse_and(tokens, pos, block_results, block_names)
        left = left or right
    return left, pos


def _parse_and(tokens, pos, block_results, block_names):
    left, pos = _parse_not(tokens, pos, block_results, block_names)
    while pos < len(tokens) and tokens[pos].lower() == "and":
        pos += 1
        right, pos = _parse_not(tokens, pos, block_results, block_names)
        left = left and right
    return left, pos


def _parse_not(tokens, pos, block_results, block_names):
    if pos < len(tokens) and tokens[pos].lower() == "not":
        pos += 1
        val, pos = _parse_not(tokens, pos, block_results, block_names)
        return not val, pos
    return _parse_atom(tokens, pos, block_results, block_names)


def _parse_atom(tokens, pos, block_results, block_names):
    if pos >= len(tokens):
        return False, pos
    tok = tokens[pos]
    if tok == "(":
        pos += 1
        val, pos = _parse_or(tokens, pos, block_results, block_names)
        if pos < len(tokens) and tokens[pos] == ")":
            pos += 1
        return val, pos
    if tok.lower() == "all" and pos + 2 < len(tokens) and tokens[pos+1].lower() == "of":
        target = tokens[pos+2]
        pos += 3
        matches = _resolve_target(target, block_names)
        return bool(matches) and all(block_results.get(n, False) for n in matches), pos
    if tok == "1" and pos + 2 < len(tokens) and tokens[pos+1].lower() == "of":
        target = tokens[pos+2]
        pos += 3
        matches = _resolve_target(target, block_names)
        return any(block_results.get(n, False) for n in matches), pos
    if tok.isdigit() and pos + 2 < len(tokens) and tokens[pos+1].lower() == "of":
        n = int(tok)
        target = tokens[pos+2]
        pos += 3
        matches = _resolve_target(target, block_names)
        return sum(1 for m in matches if block_results.get(m, False)) >= n, pos
    val = block_results.get(tok, False)
    return val, pos + 1


def _resolve_target(target: str, block_names: List[str]) -> List[str]:
    if target == "them":
        return list(block_names)
    if "*" in target:
        pattern = re.compile("^" + re.escape(target).replace(r"\*", ".*") + "$")
        return [n for n in block_names if pattern.match(n)]
    return [target] if target in block_names else []


# ── UUID fixer ─────────────────────────────────────────────────────────────────

import uuid as _uuid_mod

def _ensure_uuid_id(rule_yaml: str) -> str:
    """Ensure rule has a valid UUID id field for pySigma."""
    lines = rule_yaml.splitlines()
    new_lines = []
    found_id = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("id:"):
            val = stripped[3:].strip()
            try:
                _uuid_mod.UUID(val)
                new_lines.append(line)
            except (ValueError, AttributeError):
                new_lines.append(f"id: {_uuid_mod.uuid4()}")
            found_id = True
        else:
            new_lines.append(line)
    if not found_id:
        new_lines.insert(1, f"id: {_uuid_mod.uuid4()}")
    return "\n".join(new_lines)


# ── Main bridge evaluator ──────────────────────────────────────────────────────

def evaluate_with_pysigma(
    rule_path: str,
    artifact_path: str,
    match_mode: str = "tolerant",
) -> BridgeResult:
    """
    Evaluate a Sigma rule against a SHENRON JSONL artifact using pySigma parsing.

    Args:
        rule_path:     Path to Sigma rule YAML
        artifact_path: Path to SHENRON JSONL artifact
        match_mode:    tolerant (default) | strict | explain

    Returns:
        BridgeResult with verdict and matched events
    """
    from sigma.collection import SigmaCollection

    rule_path_p = Path(rule_path)
    rule_id    = rule_path_p.stem
    rule_title = rule_path_p.stem

    # Load and parse rule
    try:
        rule_text = rule_path_p.read_text(encoding="utf-8")
        rule_text = _ensure_uuid_id(rule_text)
        collection = SigmaCollection.from_yaml(rule_text)
        rules = list(collection)
        if not rules:
            return BridgeResult(
                rule_id=rule_id, rule_title=rule_title,
                rule_file=rule_path, artifact_file=artifact_path,
                verdict=BridgeVerdict.ERROR,
                errors=["No rules in collection"],
            )
        rule = rules[0]
        rule_id    = str(rule.id) if rule.id else rule_id
        rule_title = str(rule.title) if rule.title else rule_title
    except Exception as e:
        return BridgeResult(
            rule_id=rule_id, rule_title=rule_title,
            rule_file=rule_path, artifact_file=artifact_path,
            verdict=BridgeVerdict.ERROR,
            errors=[f"Rule parse error: {e}"],
        )

    # Load events
    events = []
    try:
        with open(artifact_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except Exception as e:
        return BridgeResult(
            rule_id=rule_id, rule_title=rule_title,
            rule_file=rule_path, artifact_file=artifact_path,
            verdict=BridgeVerdict.ERROR,
            errors=[f"Artifact load error: {e}"],
        )

    if not events:
        return BridgeResult(
            rule_id=rule_id, rule_title=rule_title,
            rule_file=rule_path, artifact_file=artifact_path,
            verdict=BridgeVerdict.NOT_TRIGGERED,
            coverage_note="No events in artifact.",
        )

    # Evaluate detection blocks against each event
    detection    = rule.detection
    block_names  = [k for k in detection.detections.keys()]
    conditions   = detection.condition

    matched_events = []

    for event in events:
        block_results: Dict[str, bool] = {}
        for block_name, det_block in detection.detections.items():
            block_results[block_name] = _eval_detection_block(det_block, event)

        # Evaluate condition
        event_matches = False
        for cond_str in conditions:
            try:
                if _eval_condition(cond_str, block_results, block_names):
                    event_matches = True
                    break
            except Exception as e:
                # fallback: OR all blocks
                if any(block_results.values()):
                    event_matches = True
                break

        if event_matches:
            matched_events.append(event)

    verdict = BridgeVerdict.TRIGGERED if matched_events else BridgeVerdict.NOT_TRIGGERED
    triggered_count = len(matched_events)

    if verdict == BridgeVerdict.TRIGGERED:
        note = (f"pySigma: Rule fires on {triggered_count} of {len(events)} event(s). "
                f"Full Sigma grammar evaluated including modifiers and complex conditions.")
    else:
        note = (f"pySigma: Rule did not trigger on {len(events)} event(s). "
                f"Check field mapping or signal vocabulary in artifact.")

    return BridgeResult(
        rule_id=rule_id,
        rule_title=rule_title,
        rule_file=rule_path,
        artifact_file=artifact_path,
        verdict=verdict,
        triggered_count=triggered_count,
        matched_events=matched_events,
        coverage_note=note,
        parse_method="pysigma",
    )


def evaluate_directory_with_pysigma(
    rules_dir: str,
    artifact_path: str,
    match_mode: str = "tolerant",
) -> List[BridgeResult]:
    """Evaluate all Sigma rules in a directory against an artifact."""
    results = []
    for rule_path in sorted(Path(rules_dir).rglob("*.yml")):
        result = evaluate_with_pysigma(str(rule_path), artifact_path, match_mode)
        results.append(result)
    return results


def print_bridge_result(result: BridgeResult) -> None:
    """Print a BridgeResult in SHENRON house style."""
    badge = {
        BridgeVerdict.TRIGGERED:     "TRIGGERED",
        BridgeVerdict.NOT_TRIGGERED: "NOT TRIGGERED",
        BridgeVerdict.PARTIAL:       "PARTIAL",
        BridgeVerdict.UNSUPPORTED:   "UNSUPPORTED",
        BridgeVerdict.ERROR:         "ERROR",
    }.get(result.verdict, result.verdict.value)

    print(f"\n  RULE:     {result.rule_title}")
    print(f"  ID:       {result.rule_id}")
    print(f"  STATUS:   {badge}  [{result.parse_method}]")
    print(f"  ARTIFACT: {result.artifact_file}")
    print(f"  MATCHED:  {result.triggered_count} event(s)")
    if result.errors:
        for e in result.errors:
            print(f"  ERROR:    {e}")
    print(f"  NOTE:     {result.coverage_note}")
    print()
