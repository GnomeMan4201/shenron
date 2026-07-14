"""
tests/test_pysigma_bridge.py

Tests for core/sigma/pysigma_bridge.py — pySigma-powered Sigma rule evaluation.
"""
import json
import tempfile
from pathlib import Path
import pytest
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.sigma.pysigma_bridge import (
    evaluate_with_pysigma,
    evaluate_directory_with_pysigma,
    print_bridge_result,
    pysigma_available,
    BridgeVerdict,
    BridgeResult,
    FIELD_MAP,
    _normalize,
    _get_event_values,
    _match_sigma_value,
    _eval_condition,
    _ensure_uuid_id,
)

DEMO_ARTIFACT = Path(__file__).parent.parent / "artifacts" / "demo" / "shenron_demo_run.jsonl"
LLM_ARTIFACT  = Path(__file__).parent.parent / "artifacts" / "llm_manipulation" / "scenario_run.jsonl"
SIGMA_DIR     = Path(__file__).parent.parent / "sigma" / "rules"
C2_RULE       = Path(__file__).parent.parent / "sigma" / "rules" / "c2" / "shenron_beacon.yml"
LLM_RULE      = Path(__file__).parent.parent / "sigma" / "rules" / "llm" / "shenron_llm_manipulation.yml"

SAMPLE_EVENT = {
    "artifact_id": "test-001",
    "session_id": "sess-abc",
    "layer": "beacon_emitter_cloak",
    "phase": "OBSERVE",
    "behavior_class": "periodic_beacon_to_external_host",
    "detection_opportunities": ["periodic_beacon_to_external_host"],
    "mitre_techniques": ["T1071", "T1132"],
    "signal": "beacon_signal",
    "simulation_only": True,
    "executable": False,
    "timestamp": "2026-06-25T00:00:00+00:00",
}


# -- Availability --------------------------------------------------------------

def test_pysigma_available():
    assert pysigma_available() is True


# -- Field map -----------------------------------------------------------------

def test_field_map_has_eventid():
    assert "EventID" in FIELD_MAP

def test_field_map_has_channel():
    assert "Channel" in FIELD_MAP

def test_field_map_has_provider():
    assert "Provider_Name" in FIELD_MAP

def test_field_map_has_shenron_native():
    assert "behavior_class" in FIELD_MAP
    assert "mitre_technique" in FIELD_MAP
    assert "layer" in FIELD_MAP
    assert "phase" in FIELD_MAP

def test_field_map_has_llm_fields():
    assert "injection_technique" in FIELD_MAP
    assert "target_model" in FIELD_MAP


# -- Normalizer ----------------------------------------------------------------

def test_normalize_lowercase():
    assert _normalize("BEACON") == "beacon"

def test_normalize_homoglyphs():
    assert _normalize("\u0430") == "a"  # Cyrillic a -> Latin a

def test_normalize_strips():
    assert _normalize("  beacon  ") == "beacon"


# -- Field extractor -----------------------------------------------------------

def test_get_event_values_direct():
    vals = _get_event_values(SAMPLE_EVENT, "layer")
    assert "beacon_emitter_cloak" in vals

def test_get_event_values_list_field():
    vals = _get_event_values(SAMPLE_EVENT, "mitre_technique")
    assert "T1071" in vals
    assert "T1132" in vals

def test_get_event_values_mapped_field():
    vals = _get_event_values(SAMPLE_EVENT, "CommandLine")
    assert len(vals) > 0

def test_get_event_values_missing_field():
    vals = _get_event_values(SAMPLE_EVENT, "EventID")
    assert vals == []

def test_get_event_values_unmapped_tries_direct():
    event = {"custom_field": "custom_value"}
    vals = _get_event_values(event, "custom_field")
    assert "custom_value" in vals


# -- UUID fixer ----------------------------------------------------------------

def test_ensure_uuid_id_valid_uuid():
    rule = "title: Test\nid: 12345678-1234-1234-1234-123456789012\nstatus: test"
    result = _ensure_uuid_id(rule)
    assert "12345678-1234-1234-1234-123456789012" in result

def test_ensure_uuid_id_fixes_invalid():
    rule = "title: Test\nid: shenron-c2-001\nstatus: test"
    result = _ensure_uuid_id(rule)
    assert "shenron-c2-001" not in result

def test_ensure_uuid_id_adds_missing():
    rule = "title: Test\nstatus: test"
    result = _ensure_uuid_id(rule)
    assert "id:" in result

def test_ensure_uuid_id_preserves_other_lines():
    rule = "title: My Rule\nid: bad-id\nstatus: test\nlevel: high"
    result = _ensure_uuid_id(rule)
    assert "My Rule" in result
    assert "level: high" in result


# -- Condition evaluator -------------------------------------------------------

def test_eval_condition_simple():
    assert _eval_condition("selection", {"selection": True}, ["selection"]) is True

def test_eval_condition_and():
    br = {"sel_a": True, "sel_b": True}
    assert _eval_condition("sel_a and sel_b", br, list(br)) is True

def test_eval_condition_or():
    br = {"sel_a": True, "sel_b": False}
    assert _eval_condition("sel_a or sel_b", br, list(br)) is True

def test_eval_condition_not():
    br = {"selection": False}
    assert _eval_condition("not selection", br, list(br)) is True

def test_eval_condition_1of():
    br = {"sel_a": True, "sel_b": False}
    assert _eval_condition("1 of sel_*", br, list(br)) is True

def test_eval_condition_all_of():
    br = {"sel_a": True, "sel_b": True}
    assert _eval_condition("all of sel_*", br, list(br)) is True

def test_eval_condition_all_of_fails():
    br = {"sel_a": True, "sel_b": False}
    assert _eval_condition("all of sel_*", br, list(br)) is False

def test_eval_condition_complex():
    br = {"sel_layer": True, "sel_tech": True, "filter_benign": False}
    result = _eval_condition(
        "(sel_layer and sel_tech) and not filter_benign",
        br, list(br)
    )
    assert result is True

def test_eval_condition_them():
    br = {"a": True, "b": True}
    assert _eval_condition("1 of them", br, list(br)) is True


# -- Rule evaluation -----------------------------------------------------------

def test_evaluate_c2_rule_triggered():
    result = evaluate_with_pysigma(str(C2_RULE), str(DEMO_ARTIFACT))
    assert result.verdict == BridgeVerdict.TRIGGERED
    assert result.triggered_count > 0
    assert result.parse_method == "pysigma"

def test_evaluate_llm_rule_on_llm_artifact():
    if not LLM_ARTIFACT.exists():
        pytest.skip("LLM artifact not present")
    result = evaluate_with_pysigma(str(LLM_RULE), str(LLM_ARTIFACT))
    assert result.verdict == BridgeVerdict.TRIGGERED
    assert result.triggered_count == 12

def test_evaluate_nonexistent_rule():
    result = evaluate_with_pysigma("/nonexistent/rule.yml", str(DEMO_ARTIFACT))
    assert result.verdict == BridgeVerdict.ERROR
    assert len(result.errors) > 0

def test_evaluate_nonexistent_artifact():
    result = evaluate_with_pysigma(str(C2_RULE), "/nonexistent/artifact.jsonl")
    assert result.verdict == BridgeVerdict.ERROR

def test_evaluate_returns_bridge_result():
    result = evaluate_with_pysigma(str(C2_RULE), str(DEMO_ARTIFACT))
    assert isinstance(result, BridgeResult)

def test_evaluate_result_has_rule_title():
    result = evaluate_with_pysigma(str(C2_RULE), str(DEMO_ARTIFACT))
    assert result.rule_title == "SHENRON C2 Beacon Detection"

def test_evaluate_result_has_matched_events():
    result = evaluate_with_pysigma(str(C2_RULE), str(DEMO_ARTIFACT))
    assert isinstance(result.matched_events, list)
    if result.verdict == BridgeVerdict.TRIGGERED:
        assert len(result.matched_events) == result.triggered_count

def test_evaluate_result_coverage_note():
    result = evaluate_with_pysigma(str(C2_RULE), str(DEMO_ARTIFACT))
    assert "pySigma" in result.coverage_note

def test_evaluate_with_temp_rule_and_event():
    rule_text = """
title: Temp Test Rule
id: 12345678-1234-1234-1234-123456789012
status: test
logsource:
    product: shenron
    category: simulation
detection:
    selection:
        layer: beacon_emitter_cloak
    condition: selection
falsepositives: []
level: high
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as rf:
        rf.write(rule_text)
        rule_path = rf.name

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as af:
        af.write(json.dumps(SAMPLE_EVENT) + "\n")
        artifact_path = af.name

    try:
        result = evaluate_with_pysigma(rule_path, artifact_path)
        assert result.verdict == BridgeVerdict.TRIGGERED
        assert result.triggered_count == 1
    finally:
        import os
        os.unlink(rule_path)
        os.unlink(artifact_path)

def test_evaluate_contains_modifier():
    rule_text = """
title: Contains Test
id: 12345678-1234-1234-1234-123456789013
status: test
logsource:
    product: shenron
detection:
    selection:
        behavior_class|contains: beacon
    condition: selection
falsepositives: []
level: medium
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as rf:
        rf.write(rule_text)
        rule_path = rf.name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as af:
        af.write(json.dumps(SAMPLE_EVENT) + "\n")
        artifact_path = af.name
    try:
        result = evaluate_with_pysigma(rule_path, artifact_path)
        assert result.verdict == BridgeVerdict.TRIGGERED
    finally:
        import os
        os.unlink(rule_path)
        os.unlink(artifact_path)

def test_evaluate_multi_value_or():
    rule_text = """
title: Multi Value OR
id: 12345678-1234-1234-1234-123456789014
status: test
logsource:
    product: shenron
detection:
    selection:
        mitre_techniques:
            - T1071
            - T9999
    condition: selection
falsepositives: []
level: medium
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as rf:
        rf.write(rule_text)
        rule_path = rf.name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as af:
        af.write(json.dumps(SAMPLE_EVENT) + "\n")
        artifact_path = af.name
    try:
        result = evaluate_with_pysigma(rule_path, artifact_path)
        assert result.verdict == BridgeVerdict.TRIGGERED
    finally:
        import os
        os.unlink(rule_path)
        os.unlink(artifact_path)


# -- Directory evaluation ------------------------------------------------------

def test_evaluate_directory_returns_list():
    results = evaluate_directory_with_pysigma(str(SIGMA_DIR), str(DEMO_ARTIFACT))
    assert isinstance(results, list)
    assert len(results) > 0

def test_evaluate_directory_all_have_verdict():
    results = evaluate_directory_with_pysigma(str(SIGMA_DIR), str(DEMO_ARTIFACT))
    for r in results:
        assert r.verdict in BridgeVerdict.__members__.values()

def test_evaluate_directory_no_errors():
    results = evaluate_directory_with_pysigma(str(SIGMA_DIR), str(DEMO_ARTIFACT))
    errors = [r for r in results if r.verdict == BridgeVerdict.ERROR]
    assert len(errors) == 0, f"Errors: {[(r.rule_title, r.errors) for r in errors]}"

def test_evaluate_directory_count():
    results = evaluate_directory_with_pysigma(str(SIGMA_DIR), str(DEMO_ARTIFACT))
    assert len(results) == 28
