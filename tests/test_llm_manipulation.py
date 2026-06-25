"""
tests/test_llm_manipulation.py

Tests for the LLM manipulation telemetry module:
  - core/layers/llm_prompt_injector.py
  - core/scenarios/llm_manipulation.py
  - sigma/rules/llm/shenron_llm_manipulation.yml
  - assumptions/examples/llm_manipulation_coverage_v2.yaml
"""
import json
import tempfile
from pathlib import Path
import pytest
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.layers.llm_prompt_injector import (
    simulate_prompt_injection,
    INJECTION_TECHNIQUES,
    INJECTION_PHASES,
    TARGET_MODELS,
    _build_injection_event,
    _sim_token_count,
    _sim_response_latency,
    _sim_entropy,
)
from core.scenarios.llm_manipulation import (
    run_llm_manipulation_scenario,
    LLMManipulationResult,
    SCENARIO_MITRE_COVERAGE,
    SCENARIO_DETECTION_OPPORTUNITIES,
)

LLM_SIGMA_RULE   = Path(__file__).parent.parent / "sigma" / "rules" / "llm" / "shenron_llm_manipulation.yml"
LLM_ASSUMPTION   = Path(__file__).parent.parent / "assumptions" / "examples" / "llm_manipulation_coverage_v2.yaml"
LLM_ARTIFACT     = Path(__file__).parent.parent / "artifacts" / "llm_manipulation" / "scenario_run.jsonl"


# -- Injection technique catalog -----------------------------------------------

def test_injection_techniques_nonempty():
    assert len(INJECTION_TECHNIQUES) > 0

def test_injection_techniques_have_required_keys():
    required = {"technique", "description", "signal", "mitre", "detection", "prompt_shape_sim", "severity"}
    for t in INJECTION_TECHNIQUES:
        assert required.issubset(t.keys()), f"Missing keys in {t['technique']}"

def test_injection_techniques_have_mitre():
    for t in INJECTION_TECHNIQUES:
        assert len(t["mitre"]) > 0

def test_injection_techniques_have_detection_opps():
    for t in INJECTION_TECHNIQUES:
        assert len(t["detection"]) > 0

def test_injection_techniques_severity_valid():
    valid = {"HIGH", "MEDIUM", "LOW"}
    for t in INJECTION_TECHNIQUES:
        assert t["severity"] in valid

def test_injection_phases_nonempty():
    assert len(INJECTION_PHASES) > 0

def test_target_models_nonempty():
    assert len(TARGET_MODELS) > 0


# -- Simulation helpers --------------------------------------------------------

def test_sim_token_count_positive():
    assert _sim_token_count() > 0

def test_sim_token_count_base():
    count = _sim_token_count(base=1000)
    assert count >= 1000

def test_sim_response_latency_positive():
    assert _sim_response_latency() > 0.0

def test_sim_entropy_range():
    e = _sim_entropy()
    assert 0.0 < e < 10.0

def test_build_injection_event_returns_dict():
    import random
    technique = INJECTION_TECHNIQUES[0]
    ev = _build_injection_event("sess-001", technique, "INJECT", 1, "gpt-4-sim")
    assert isinstance(ev, dict)

def test_build_injection_event_required_fields():
    technique = INJECTION_TECHNIQUES[0]
    ev = _build_injection_event("sess-001", technique, "INJECT", 1, "gpt-4-sim")
    required = {"artifact_id", "session_id", "layer", "phase", "mitre_techniques",
                "behavior_class", "detection_opportunities", "simulation_only", "safety"}
    assert required.issubset(ev.keys())

def test_build_injection_event_simulation_only():
    technique = INJECTION_TECHNIQUES[0]
    ev = _build_injection_event("sess-001", technique, "INJECT", 1, "gpt-4-sim")
    assert ev["simulation_only"] is True
    assert ev["executable"] is False
    assert ev["payload_present"] is False

def test_build_injection_event_safety_contract():
    technique = INJECTION_TECHNIQUES[0]
    ev = _build_injection_event("sess-001", technique, "INJECT", 1, "gpt-4-sim")
    safety = ev["safety"]
    assert safety["simulation_only"] is True
    assert safety["executable"] is False
    assert safety["network_connection"] is False


# -- Prompt injection simulation -----------------------------------------------

def test_simulate_returns_tuple():
    result = simulate_prompt_injection(n_techniques=2, seed=42)
    assert isinstance(result, tuple)
    assert len(result) == 2

def test_simulate_session_id_is_string():
    session_id, events = simulate_prompt_injection(n_techniques=2, seed=42)
    assert isinstance(session_id, str)
    assert len(session_id) > 0

def test_simulate_events_list():
    _, events = simulate_prompt_injection(n_techniques=2, seed=42)
    assert isinstance(events, list)
    assert len(events) > 0

def test_simulate_event_count():
    _, events = simulate_prompt_injection(n_techniques=3, seed=42)
    # recon + 3 techniques + exfil = 5
    assert len(events) == 5

def test_simulate_all_simulation_only():
    _, events = simulate_prompt_injection(n_techniques=2, seed=42)
    assert all(e["simulation_only"] is True for e in events)

def test_simulate_no_executable():
    _, events = simulate_prompt_injection(n_techniques=2, seed=42)
    assert all(e["executable"] is False for e in events)

def test_simulate_no_payload():
    _, events = simulate_prompt_injection(n_techniques=2, seed=42)
    assert all(e["payload_present"] is False for e in events)

def test_simulate_all_have_mitre():
    _, events = simulate_prompt_injection(n_techniques=2, seed=42)
    assert all(len(e.get("mitre_techniques", [])) > 0 for e in events)

def test_simulate_all_have_detection_opps():
    _, events = simulate_prompt_injection(n_techniques=2, seed=42)
    assert all(len(e.get("detection_opportunities", [])) > 0 for e in events)

def test_simulate_layer_correct():
    _, events = simulate_prompt_injection(n_techniques=2, seed=42)
    assert all(e["layer"] == "llm_prompt_injector" for e in events)

def test_simulate_has_recon_phase():
    _, events = simulate_prompt_injection(n_techniques=2, seed=42)
    phases = {e["phase"] for e in events}
    assert "RECONNAISSANCE" in phases

def test_simulate_has_exfil_phase():
    _, events = simulate_prompt_injection(n_techniques=2, seed=42)
    phases = {e["phase"] for e in events}
    assert "EXFILTRATION_SIM" in phases

def test_simulate_unique_artifact_ids():
    _, events = simulate_prompt_injection(n_techniques=3, seed=42)
    ids = [e["artifact_id"] for e in events]
    assert len(ids) == len(set(ids))

def test_simulate_technique_coverage():
    _, events = simulate_prompt_injection(n_techniques=5, seed=42)
    all_techs = set()
    for e in events:
        all_techs.update(e.get("mitre_techniques", []))
    assert "T1059.007" in all_techs
    assert "T1190" in all_techs


# -- Scenario module -----------------------------------------------------------

def test_scenario_coverage_nonempty():
    assert len(SCENARIO_MITRE_COVERAGE) > 0
    assert len(SCENARIO_DETECTION_OPPORTUNITIES) > 0

def test_run_scenario_returns_result():
    result = run_llm_manipulation_scenario(
        n_injection_techniques=2, seed=42, verbose=False
    )
    assert isinstance(result, LLMManipulationResult)

def test_run_scenario_has_events():
    result = run_llm_manipulation_scenario(
        n_injection_techniques=2, seed=42, verbose=False
    )
    assert result.event_count > 0
    assert len(result.events) == result.event_count

def test_run_scenario_phases_complete():
    result = run_llm_manipulation_scenario(
        n_injection_techniques=2, seed=42, verbose=False
    )
    assert "RECONNAISSANCE" in result.phases_completed
    assert "INJECT" in result.phases_completed
    assert "MANIPULATE" in result.phases_completed
    assert "OBFUSCATE" in result.phases_completed
    assert "EXFILTRATE" in result.phases_completed

def test_run_scenario_mitre_coverage():
    result = run_llm_manipulation_scenario(
        n_injection_techniques=2, seed=42, verbose=False
    )
    assert "T1059.007" in result.mitre_techniques
    assert "T1027" in result.mitre_techniques
    assert "T1048" in result.mitre_techniques

def test_run_scenario_detection_opps():
    result = run_llm_manipulation_scenario(
        n_injection_techniques=2, seed=42, verbose=False
    )
    assert len(result.detection_opportunities) >= 10

def test_run_scenario_all_safety_intact():
    result = run_llm_manipulation_scenario(
        n_injection_techniques=2, seed=42, verbose=False
    )
    for ev in result.events:
        assert ev.get("simulation_only") is not False

def test_run_scenario_write_artifact():
    with tempfile.TemporaryDirectory() as d:
        out = f"{d}/llm_test.jsonl"
        result = run_llm_manipulation_scenario(
            n_injection_techniques=2, seed=42,
            write_artifact=True, output_path=out, verbose=False
        )
        assert Path(out).exists()
        assert result.artifact_path == out

def test_run_scenario_artifact_valid_jsonl():
    with tempfile.TemporaryDirectory() as d:
        out = f"{d}/llm_test.jsonl"
        result = run_llm_manipulation_scenario(
            n_injection_techniques=2, seed=42,
            write_artifact=True, output_path=out, verbose=False
        )
        with open(out) as f:
            lines = [json.loads(l) for l in f if l.strip()]
        assert len(lines) == result.event_count

def test_run_scenario_to_dict():
    result = run_llm_manipulation_scenario(
        n_injection_techniques=2, seed=42, verbose=False
    )
    d = result.to_dict()
    assert "scenario_id" in d
    assert "mitre_techniques" in d
    assert "phases_completed" in d

def test_run_scenario_to_jsonl():
    result = run_llm_manipulation_scenario(
        n_injection_techniques=2, seed=42, verbose=False
    )
    jsonl = result.to_jsonl()
    lines = [l for l in jsonl.split("\n") if l.strip()]
    assert len(lines) == result.event_count

def test_run_scenario_summary_string():
    result = run_llm_manipulation_scenario(
        n_injection_techniques=2, seed=42, verbose=False
    )
    summary = result.summary()
    assert "LLM-SCENARIO" in summary
    assert str(result.event_count) in summary


# -- Sigma rule validation -----------------------------------------------------

def test_sigma_rule_exists():
    assert LLM_SIGMA_RULE.exists()

def test_sigma_rule_valid_yaml():
    import yaml
    with open(LLM_SIGMA_RULE) as f:
        data = yaml.safe_load(f)
    assert "title" in data
    assert "detection" in data
    assert "condition" in data.get("detection", {})

def test_sigma_rule_triggered_on_artifact():
    if not LLM_ARTIFACT.exists():
        pytest.skip("LLM artifact not generated yet")
    from core.sigma.evaluator import evaluate_sigma_rule
    from core.sigma.model import RuleVerdict
    result = evaluate_sigma_rule(str(LLM_SIGMA_RULE), str(LLM_ARTIFACT), match_mode="tolerant")
    assert result.verdict == RuleVerdict.TRIGGERED

def test_sigma_rule_all_blocks_triggered():
    if not LLM_ARTIFACT.exists():
        pytest.skip("LLM artifact not generated yet")
    from core.sigma.evaluator import evaluate_sigma_rule
    from core.sigma.model import MatchStatus
    result = evaluate_sigma_rule(str(LLM_SIGMA_RULE), str(LLM_ARTIFACT), match_mode="tolerant")
    triggered = [d for d in result.detections if d.status == MatchStatus.TRIGGERED]
    assert len(triggered) >= 4


# -- Assumption validation -----------------------------------------------------

def test_assumption_v2_exists():
    assert LLM_ASSUMPTION.exists()

def test_assumption_v2_valid_yaml():
    import yaml
    with open(LLM_ASSUMPTION) as f:
        data = yaml.safe_load(f)
    assert "id" in data
    assert "claims" in data
    assert len(data["claims"]) > 0

def test_assumption_v2_supported_on_artifact():
    if not LLM_ARTIFACT.exists():
        pytest.skip("LLM artifact not generated yet")
    from core.assumptions.validator import validate_assumption
    from core.assumptions.model import AssumptionStatus
    result = validate_assumption(str(LLM_ASSUMPTION), str(LLM_ARTIFACT))
    assert result.status == AssumptionStatus.SUPPORTED

def test_assumption_v2_no_unsupported_claims():
    if not LLM_ARTIFACT.exists():
        pytest.skip("LLM artifact not generated yet")
    from core.assumptions.validator import validate_assumption
    result = validate_assumption(str(LLM_ASSUMPTION), str(LLM_ARTIFACT))
    assert result.unsupported_count == 0

def test_assumption_v2_no_oos_violations():
    if not LLM_ARTIFACT.exists():
        pytest.skip("LLM artifact not generated yet")
    from core.assumptions.validator import validate_assumption
    result = validate_assumption(str(LLM_ASSUMPTION), str(LLM_ARTIFACT))
    assert len(result.out_of_scope_violations) == 0
