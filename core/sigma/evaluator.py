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
                   match_mode: str = "tolerant") -> tuple:
    """
    Returns (matched: bool, reason: str).
    match_mode:
      tolerant — exact, substring, token-overlap, wildcard (default, backward-compatible)
      strict   — exact normalized match or wildcard only
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
                               match_mode: str = "tolerant") -> DetectionMatch:
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
            for ev in expected_value:
                field_requirements.append((sigma_field, str(ev), shenron_fields))
        elif isinstance(expected_value, str) and expected_value:
            field_requirements.append((sigma_field, expected_value, shenron_fields))

    if not field_requirements:
        result.status = MatchStatus.UNSUPPORTED
        result.reason = f"All fields unsupported: {unsupported or list(detection_def.keys())}"
        return result

    matched_artifacts = []
    field_match_map = {(sf, ev): FieldMatch(field=sf, expected=ev)
                       for sf, ev, _ in field_requirements}

    for art in artifacts:
        art_field_results = []
        for sigma_field, expected, shenron_fields in field_requirements:
            actual = _get_artifact_values(art, shenron_fields)
            matched, match_reason = _value_matches(expected, actual, match_mode)
            art_field_results.append(matched)
            fm = field_match_map[(sigma_field, expected)]
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


def evaluate_sigma_rule(rule_path, artifact_path,
                        match_mode: str = "tolerant") -> SigmaResult:
    rule      = load_sigma_rule(rule_path)
    artifacts = load_artifacts(artifact_path)

    rule_id    = rule.get("id", Path(str(rule_path)).stem)
    rule_title = rule.get("title", rule_id)
    detection  = rule.get("detection", {})

    detections    = []
    missed_fields = []

    for det_name, det_def in detection.items():
        if det_name == "condition":
            continue
        dm = _evaluate_detection_block(det_name, det_def, artifacts, match_mode)
        detections.append(dm)
        for fm in dm.field_matches:
            if not fm.matched and fm.field not in missed_fields:
                missed_fields.append(fm.field)

    triggered = [d for d in detections if d.status == MatchStatus.TRIGGERED]
    partial   = [d for d in detections if d.status == MatchStatus.PARTIAL]
    unsup     = [d for d in detections if d.status == MatchStatus.UNSUPPORTED]

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


def print_result(result: SigmaResult, match_mode: str = "tolerant"):
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
