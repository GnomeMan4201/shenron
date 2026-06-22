"""
SHENRON Sigma rule evaluator.

Field mapping (Sigma -> SHENRON artifact):
  CommandLine     -> behavior_class, detection_opportunities
  Image           -> layer, behavior_class
  EventID         -> (not emitted — unsupported)
  TargetFilename  -> target_path_sim, file_path_sim, synthetic_path
  DestinationIp   -> target_ip_sim
  DestinationPort -> port_sim
  User            -> token_type_sim
  detection_opp   -> detection_opportunities (SHENRON-native)
  behavior_class  -> behavior_class (SHENRON-native)
  mitre_technique -> mitre_techniques (SHENRON-native)
  layer           -> layer (SHENRON-native)
  phase           -> phase (SHENRON-native)
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from core.sigma.model import (
    FieldMatch, DetectionMatch, SigmaResult,
    MatchStatus, RuleVerdict,
)
from core.sigma.loader import load_sigma_rule, load_artifacts


FIELD_MAP = {
    "CommandLine":       ["behavior_class", "detection_opportunities", "command_sim"],
    "Image":             ["layer", "behavior_class"],
    "TargetFilename":    ["target_path_sim", "file_path_sim", "synthetic_path",
                          "deploy_path_sim", "full_seed_path_sim"],
    "DestinationIp":     ["target_ip_sim", "target_hostname"],
    "DestinationPort":   ["port_sim"],
    "User":              ["token_type_sim"],
    "CurrentDirectory":  ["synthetic_path", "sandbox_path_sim"],
    "Description":       ["behavior_class"],
    "ParentImage":       ["layer"],
    "ProcessId":         ["target_pid_sim"],
    "Hashes":            [],
    "EventID":           [],
    "Channel":           [],
    "Provider_Name":     [],
    # SHENRON-native
    "detection_opp":     ["detection_opportunities"],
    "behavior_class":    ["behavior_class"],
    "mitre_technique":   ["mitre_techniques"],
    "layer":             ["layer"],
    "phase":             ["phase"],
    "simulation_only":   ["simulation_only"],
}

UNSUPPORTED_FIELDS = {"EventID", "Hashes", "Channel", "Provider_Name"}


def _normalize(s: str) -> str:
    import unicodedata
    s = unicodedata.normalize("NFKD", s)
    s = s.encode("ascii", "ignore").decode("ascii")
    return s.lower().strip().replace("-", "_").replace(" ", "_")


def _get_artifact_values(art: dict, shenron_fields: list) -> list:
    values = []
    for f in shenron_fields:
        val = art.get(f)
        if val is None:
            continue
        if isinstance(val, list):
            values.extend([str(v) for v in val])
        elif isinstance(val, bool):
            values.append(str(val).lower())
        else:
            values.append(str(val))
    return values


def _value_matches(expected: str, actual_values: list,
                   match_mode: str = "strict") -> tuple:
    """
    Returns (matched: bool, reason: str).
    match_mode:
      strict   — exact normalized match or wildcard only (default)
      tolerant — exact, substring, token-overlap, wildcard
      explain  — tolerant matching with detailed per-field reason string
    """
    exp_norm = _normalize(expected)

    # Wildcard matching — all modes
    if "*" in exp_norm or "?" in exp_norm:
        pattern = re.escape(exp_norm).replace(r"\*", ".*").replace(r"\?", ".")
        for av in actual_values:
            if re.search(pattern, _normalize(av)):
                reason = f"wildcard match: {exp_norm!r} matched {_normalize(av)!r}"
                return True, reason
        return False, f"wildcard {exp_norm!r} did not match any of {actual_values[:3]}"

    # Strict mode — exact normalized only
    if match_mode == "strict":
        for av in actual_values:
            if exp_norm == _normalize(av):
                return True, f"exact match: {exp_norm!r}"
        return False, f"strict: {exp_norm!r} not an exact match in {actual_values[:3]}"

    # Tolerant / explain modes
    for av in actual_values:
        av_norm = _normalize(av)
        if exp_norm == av_norm:
            reason = f"exact match: {exp_norm!r}"
            return True, reason
        if exp_norm in av_norm:
            reason = f"substring match: {exp_norm!r} in {av_norm!r}"
            return True, reason
        if av_norm in exp_norm:
            reason = f"substring match: {av_norm!r} in {exp_norm!r}"
            return True, reason
        exp_tokens = set(exp_norm.split("_"))
        av_tokens  = set(av_norm.split("_"))
        overlap = exp_tokens & av_tokens
        if exp_tokens and len(overlap) / len(exp_tokens) >= 0.6:
            reason = f"token overlap: {overlap} ({len(overlap)}/{len(exp_tokens)} tokens)"
            return True, reason

    return False, f"no match for {exp_norm!r} in {actual_values[:3]}"


def _evaluate_detection_block(detection_name: str, detection_def,
                               artifacts: list,
                               match_mode: str = "strict") -> DetectionMatch:
    result = DetectionMatch(detection_name=detection_name,
                            status=MatchStatus.NOT_TRIGGERED)

    if not isinstance(detection_def, dict) or not detection_def:
        result.status = MatchStatus.UNSUPPORTED
        result.reason = "Empty or non-dict detection block"
        return result

    field_requirements = []
    unsupported = []

    for sigma_field, expected_value in detection_def.items():
        shenron_fields = FIELD_MAP.get(sigma_field, [])
        if sigma_field in UNSUPPORTED_FIELDS or not shenron_fields:
            unsupported.append(sigma_field)
            continue
        if isinstance(expected_value, list):
            values = [str(ev) for ev in expected_value if ev]
            if values:
                field_requirements.append((sigma_field, values, shenron_fields))
        elif isinstance(expected_value, str) and expected_value:
            field_requirements.append((sigma_field, [expected_value], shenron_fields))

    if not field_requirements:
        result.status = MatchStatus.UNSUPPORTED
        result.reason = f"All fields unsupported: {unsupported or list(detection_def.keys())}"
        return result

    matched_artifacts = []
    # field_requirements: (sigma_field, [values], shenron_fields)
    # list of values = OR semantics (any one matching is sufficient)
    field_match_map = {
        (sf, vals[0] if len(vals) == 1 else f"any({','.join(vals[:2])}...)"):
            FieldMatch(field=sf,
                       expected=vals[0] if len(vals) == 1 else f"any of {vals[:3]}")
        for sf, vals, _ in field_requirements
    }

    for art in artifacts:
        art_field_results = []
        for sigma_field, expected_values, shenron_fields in field_requirements:
            actual = _get_artifact_values(art, shenron_fields)
            matched = False
            match_reason = f"no match for any of {expected_values[:2]} in {actual[:2]}"
            for ev in expected_values:
                m, reason = _value_matches(ev, actual, match_mode)
                if m:
                    matched = True
                    match_reason = reason
                    break
            art_field_results.append(matched)
            key = (sigma_field,
                   expected_values[0] if len(expected_values) == 1
                   else f"any({','.join(expected_values[:2])}...)")
            fm = field_match_map[key]
            fm.artifact_count += 1
            fm.match_reason = match_reason
            if matched:
                fm.matched = True
                if actual not in fm.found_in:
                    fm.found_in.extend(actual[:2])

        if all(art_field_results):
            matched_artifacts.append(art)

    result.field_matches     = list(field_match_map.values())
    result.matched_artifacts = matched_artifacts

    matched_fields = sum(1 for fm in result.field_matches if fm.matched)
    total_fields   = len(result.field_matches)
    missing        = [fm.field for fm in result.field_matches if not fm.matched]

    if matched_artifacts:
        if unsupported:
            result.status = MatchStatus.PARTIAL
            result.reason = (f"TRIGGERED on {len(matched_artifacts)} artifact(s). "
                             f"Unsupported fields skipped: {unsupported}")
        else:
            result.status = MatchStatus.TRIGGERED
            result.reason = f"TRIGGERED on {len(matched_artifacts)} artifact(s)"
    elif matched_fields > 0:
        result.status = MatchStatus.PARTIAL
        result.reason = (f"{matched_fields}/{total_fields} fields matched. "
                         f"No artifact satisfied ALL conditions. Missing: {missing}")
    else:
        result.status = MatchStatus.NOT_TRIGGERED
        result.reason = f"No field matches. Fields checked: {[sf for sf,_,_ in field_requirements]}"

    return result


# ── Condition parser ──────────────────────────────────────────────────────────

def _tokenize_condition(condition: str) -> list:
    """Tokenize a Sigma condition string into a list of tokens."""
    # Insert spaces around parens so they split cleanly
    condition = condition.replace("(", " ( ").replace(")", " ) ")
    return condition.split()


def _parse_condition(tokens: list, pos: int = 0):
    """
    Recursive-descent parser for Sigma condition expressions.
    Grammar:
        expr     := or_expr
        or_expr  := and_expr ('or' and_expr)*
        and_expr := not_expr ('and' not_expr)*
        not_expr := 'not' not_expr | atom
        atom     := '(' expr ')' | QUANTIFIER 'of' TARGET | NAME
    Returns (ast_node, new_pos).
    AST node is one of:
        {"op": "or",  "operands": [...]}
        {"op": "and", "operands": [...]}
        {"op": "not", "operand": ...}
        {"op": "ref", "name": str}           # bare selection name
        {"op": "1of",  "target": str}         # 1 of them / 1 of selection_*
        {"op": "allof", "target": str}        # all of them / all of selection_*
        {"op": "Nof",  "n": int, "target": str}
    """
    node, pos = _parse_or(tokens, pos)
    return node, pos


def _parse_or(tokens, pos):
    left, pos = _parse_and(tokens, pos)
    while pos < len(tokens) and tokens[pos].lower() == "or":
        pos += 1
        right, pos = _parse_and(tokens, pos)
        if left.get("op") == "or":
            left["operands"].append(right)
        else:
            left = {"op": "or", "operands": [left, right]}
    return left, pos


def _parse_and(tokens, pos):
    left, pos = _parse_not(tokens, pos)
    while pos < len(tokens) and tokens[pos].lower() == "and":
        pos += 1
        right, pos = _parse_not(tokens, pos)
        if left.get("op") == "and":
            left["operands"].append(right)
        else:
            left = {"op": "and", "operands": [left, right]}
    return left, pos


def _parse_not(tokens, pos):
    if pos < len(tokens) and tokens[pos].lower() == "not":
        pos += 1
        operand, pos = _parse_not(tokens, pos)
        return {"op": "not", "operand": operand}, pos
    return _parse_atom(tokens, pos)


def _parse_atom(tokens, pos):
    if pos >= len(tokens):
        return {"op": "ref", "name": ""}, pos

    tok = tokens[pos]

    # Grouped expression
    if tok == "(":
        pos += 1
        node, pos = _parse_or(tokens, pos)
        if pos < len(tokens) and tokens[pos] == ")":
            pos += 1
        return node, pos

    # Quantifier: "1 of ...", "all of ...", "N of ..."
    if tok.lower() == "all" and pos + 2 < len(tokens) and tokens[pos + 1].lower() == "of":
        target = tokens[pos + 2]
        return {"op": "allof", "target": target}, pos + 3

    if tok == "1" and pos + 2 < len(tokens) and tokens[pos + 1].lower() == "of":
        target = tokens[pos + 2]
        return {"op": "1of", "target": target}, pos + 3

    # Numeric quantifier e.g. "3 of selection_*"
    if tok.isdigit() and pos + 2 < len(tokens) and tokens[pos + 1].lower() == "of":
        target = tokens[pos + 2]
        return {"op": "Nof", "n": int(tok), "target": target}, pos + 3

    # Bare name
    return {"op": "ref", "name": tok}, pos + 1


def _resolve_target(target: str, block_names: list) -> list:
    """
    Expand a condition target ('them', 'selection_*', 'filter') to a list of
    matching block names.
    """
    if target == "them":
        return list(block_names)
    if "*" in target:
        pattern = re.compile("^" + re.escape(target).replace(r"\*", ".*") + "$")
        return [n for n in block_names if pattern.match(n)]
    if target in block_names:
        return [target]
    return []


def _eval_ast(node: dict, block_results: dict, block_names: list) -> bool:
    """
    Evaluate the AST against a dict of {block_name: bool} match results.
    """
    op = node["op"]

    if op == "ref":
        name = node["name"]
        return block_results.get(name, False)

    if op == "not":
        return not _eval_ast(node["operand"], block_results, block_names)

    if op == "and":
        return all(_eval_ast(o, block_results, block_names) for o in node["operands"])

    if op == "or":
        return any(_eval_ast(o, block_results, block_names) for o in node["operands"])

    if op == "1of":
        targets = _resolve_target(node["target"], block_names)
        return any(block_results.get(t, False) for t in targets)

    if op == "allof":
        targets = _resolve_target(node["target"], block_names)
        return bool(targets) and all(block_results.get(t, False) for t in targets)

    if op == "Nof":
        targets = _resolve_target(node["target"], block_names)
        return sum(1 for t in targets if block_results.get(t, False)) >= node["n"]

    return False


# ── Main evaluator ────────────────────────────────────────────────────────────

def evaluate_sigma_rule(rule_path, artifact_path,
                        match_mode: str = "strict") -> SigmaResult:
    rule      = load_sigma_rule(rule_path)
    artifacts = load_artifacts(artifact_path)

    rule_id    = rule.get("id", Path(str(rule_path)).stem)
    rule_title = rule.get("title", rule_id)
    detection  = rule.get("detection", {})

    condition_str = None
    detection_blocks = {}

    for det_name, det_def in detection.items():
        if det_name == "condition":
            condition_str = str(det_def).strip()
        else:
            detection_blocks[det_name] = det_def

    detections    = []
    missed_fields = []

    # Evaluate each named block independently
    block_names = list(detection_blocks.keys())
    for block_name, block_def in detection_blocks.items():
        dm = _evaluate_detection_block(block_name, block_def, artifacts, match_mode)
        detections.append(dm)
        for fm in dm.field_matches:
            if not fm.matched and fm.field not in missed_fields:
                missed_fields.append(fm.field)

    # Apply condition expression to get the final verdict
    # Each block is "triggered" if any artifact fully satisfied it
    block_triggered = {
        dm.detection_name: dm.status == MatchStatus.TRIGGERED
        for dm in detections
    }

    condition_met = None  # None means no condition string present
    condition_parse_error = None

    if condition_str:
        try:
            tokens = _tokenize_condition(condition_str)
            ast_node, _ = _parse_condition(tokens)
            condition_met = _eval_ast(ast_node, block_triggered, block_names)
        except Exception as exc:
            condition_parse_error = str(exc)
            # Fallback: OR all blocks (preserves old behaviour on parse failure)
            condition_met = any(block_triggered.values())

    # Derive verdict from condition result
    triggered = [d for d in detections if d.status == MatchStatus.TRIGGERED]
    partial   = [d for d in detections if d.status == MatchStatus.PARTIAL]
    unsup     = [d for d in detections if d.status == MatchStatus.UNSUPPORTED]

    if condition_met is True:
        verdict = RuleVerdict.TRIGGERED
    elif condition_met is False:
        # Condition evaluated but was not satisfied
        verdict = RuleVerdict.NOT_TRIGGERED
    else:
        # No condition string — fall back to block-level aggregation
        if triggered:
            verdict = RuleVerdict.TRIGGERED
        elif partial:
            verdict = RuleVerdict.PARTIAL
        elif unsup and len(unsup) == len(detections):
            verdict = RuleVerdict.UNSUPPORTED
        else:
            verdict = RuleVerdict.NOT_TRIGGERED

    triggered_count = sum(len(d.matched_artifacts) for d in triggered + partial)

    if verdict == RuleVerdict.TRIGGERED:
        note = (f"Rule fires on {triggered_count} synthetic artifact(s). "
                "Detection rule is reachable from SHENRON telemetry.")
    elif verdict == RuleVerdict.PARTIAL:
        note = ("Rule partially matches. Some detection fields present in artifact "
                "but not all conditions simultaneously satisfied. "
                "Check field mapping or add missing signals to scenario.")
    elif verdict == RuleVerdict.UNSUPPORTED:
        note = ("Rule uses fields SHENRON does not currently emit "
                "(e.g. EventID, Hashes, Channel). "
                "Map rule to SHENRON-native fields: behavior_class, "
                "detection_opp, mitre_technique, layer, phase.")
    else:
        note = ("Rule does not trigger on this artifact. "
                "Either the artifact does not contain matching telemetry, "
                "or the rule targets fields not present in this layer category.")

    if condition_parse_error:
        note += f" (condition parse warning: {condition_parse_error} — fallback OR applied)"

    return SigmaResult(
        rule_id         = rule_id,
        rule_title      = rule_title,
        rule_file       = str(rule_path),
        artifact_file   = str(artifact_path),
        verdict         = verdict,
        detections      = detections,
        triggered_count = triggered_count,
        missed_fields   = missed_fields,
        coverage_note   = note,
        timestamp       = datetime.now(timezone.utc).isoformat(),
    )


def print_result(result: SigmaResult, match_mode: str = "strict"):
    badge = {
        RuleVerdict.TRIGGERED:     "TRIGGERED",
        RuleVerdict.NOT_TRIGGERED: "NOT TRIGGERED",
        RuleVerdict.PARTIAL:       "PARTIAL",
        RuleVerdict.UNSUPPORTED:   "UNSUPPORTED",
        RuleVerdict.ERROR:         "ERROR",
    }.get(result.verdict, result.verdict.value)

    print(f"\n  RULE:     {result.rule_title}")
    print(f"  ID:       {result.rule_id}")
    print(f"  STATUS:   {badge}")
    print(f"  ARTIFACT: {result.artifact_file}")
    print()

    for d in result.detections:
        print(f"  Detection [{d.detection_name}]: {d.status.value}")
        for fm in d.field_matches:
            mark = "+" if fm.matched else "-"
            if match_mode == "explain" and fm.match_reason:
                print(f"    {mark} {fm.field}: {fm.expected!r} — {fm.match_reason}")
            else:
                print(f"    {mark} {fm.field}: {fm.expected!r}")
        if d.matched_artifacts:
            print(f"    [{len(d.matched_artifacts)} artifact(s) triggered]")
        print()

    if result.missed_fields:
        print(f"  Missed fields: {result.missed_fields}")

    print(f"  Coverage note:")
    for line in result.coverage_note.split(". "):
        if line.strip():
            print(f"    {line.strip()}.")
    print()
