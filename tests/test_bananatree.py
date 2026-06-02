#!/usr/bin/env python3
"""bananaTREE integration tests."""
import json, sys, pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.bananatree.cycle import Phase, BananaTreeCycle, SAFETY_CONTRACT
from core.bananatree.taxonomy import get_phase, build_phase_summary, CATEGORY_PHASE_MAP
from core.scenarios.runner import (
    load_scenario, validate_layers, run_scenario,
    ScenarioValidationError
)
from core.engine.layer_loader import discover_canonical


# ── Phase mapping tests ────────────────────────────────────────────────────────

def test_all_categories_have_phase_mapping():
    expected = {"c2", "entropy", "identity", "evasion", "payload", "llm", "persistence", "meta"}
    assert set(CATEGORY_PHASE_MAP.keys()) == expected

def test_c2_maps_to_observe():
    assert get_phase("c2") == Phase.OBSERVE

def test_entropy_maps_to_observe():
    assert get_phase("entropy") == Phase.OBSERVE

def test_identity_maps_to_observe():
    assert get_phase("identity") == Phase.OBSERVE

def test_evasion_maps_to_simulate():
    assert get_phase("evasion") == Phase.SIMULATE

def test_payload_maps_to_simulate():
    assert get_phase("payload") == Phase.SIMULATE

def test_llm_maps_to_simulate():
    assert get_phase("llm") == Phase.SIMULATE

def test_persistence_maps_to_execute():
    assert get_phase("persistence") == Phase.EXECUTE

def test_meta_maps_to_adapt():
    assert get_phase("meta") == Phase.ADAPT

def test_unknown_category_defaults_to_simulate():
    assert get_phase("unknown_xyz") == Phase.SIMULATE

def test_case_insensitive_mapping():
    assert get_phase("C2") == Phase.OBSERVE
    assert get_phase("PERSISTENCE") == Phase.EXECUTE


# ── Taxonomy summary tests ─────────────────────────────────────────────────────

def test_phase_summary_has_all_phases():
    manifest = json.loads(Path("shenron_manifest.json").read_text())["layers"]
    summary = build_phase_summary(manifest)
    for phase in Phase:
        assert phase.value in summary

def test_phase_summary_layer_counts_sum_to_51():
    manifest = json.loads(Path("shenron_manifest.json").read_text())["layers"]
    summary = build_phase_summary(manifest)
    total = sum(v["layer_count"] for v in summary.values())
    assert total == 52

def test_execute_phase_has_persistence_layers():
    manifest = json.loads(Path("shenron_manifest.json").read_text())["layers"]
    summary = build_phase_summary(manifest)
    assert summary[Phase.EXECUTE.value]["layer_count"] > 0


# ── Cycle dataclass tests ──────────────────────────────────────────────────────

def test_cycle_has_run_id():
    cycle = BananaTreeCycle()
    assert len(cycle.run_id) == 36  # uuid4

def test_cycle_safety_contract_matches_global():
    cycle = BananaTreeCycle()
    assert cycle.safety_contract == SAFETY_CONTRACT

def test_cycle_safety_contract_all_safe():
    cycle = BananaTreeCycle()
    assert cycle.safety_contract["simulation_only"] is True
    assert cycle.safety_contract["executable"] is False
    assert cycle.safety_contract["no_payload_present"] is True
    assert cycle.safety_contract["network_calls_made"] is False
    assert cycle.safety_contract["processes_spawned"] is False

def test_cycle_to_dict_has_all_phases_after_complete():
    cycle = BananaTreeCycle(campaign_name="test")
    for phase in Phase:
        result = cycle.start_phase(phase)
        result.layers_run.append("test_layer")
        result.mitre_techniques.append("T1027")
    cycle.complete()
    d = cycle.to_dict()
    assert set(d["phases"].keys()) == {p.value for p in Phase}

def test_cycle_complete_aggregates_mitre():
    cycle = BananaTreeCycle()
    r1 = cycle.start_phase(Phase.OBSERVE)
    r1.mitre_techniques = ["T1071", "T1132"]
    r2 = cycle.start_phase(Phase.EXECUTE)
    r2.mitre_techniques = ["T1053", "T1071"]  # T1071 duplicate
    cycle.complete()
    assert cycle.all_mitre.count("T1071") == 1  # deduped
    assert "T1053" in cycle.all_mitre

def test_cycle_to_dict_has_observe_simulate_execute_adapt():
    cycle = BananaTreeCycle()
    for phase in Phase:
        cycle.start_phase(phase)
    cycle.complete()
    d = cycle.to_dict()
    assert "OBSERVE"  in d["phases"]
    assert "SIMULATE" in d["phases"]
    assert "EXECUTE"  in d["phases"]
    assert "ADAPT"    in d["phases"]


# ── Scenario loading tests ─────────────────────────────────────────────────────

EXAMPLE_DIR = Path("scenarios/examples")

def test_all_example_scenarios_load():
    for p in EXAMPLE_DIR.glob("*.json"):
        scenario = load_scenario(p)
        assert "name" in scenario
        assert "phases" in scenario

def test_scenario_rejects_missing_file():
    with pytest.raises(ScenarioValidationError, match="not found"):
        load_scenario("/tmp/does_not_exist_xyz.json")

def test_scenario_rejects_missing_name_key(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"phases": {}}))
    with pytest.raises(ScenarioValidationError, match="name"):
        load_scenario(bad)

def test_scenario_rejects_missing_phases_key(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"name": "test"}))
    with pytest.raises(ScenarioValidationError, match="phases"):
        load_scenario(bad)

def test_scenario_rejects_unknown_phase(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"name": "test", "phases": {"ATTACK": {"layers": []}}}))
    with pytest.raises(ScenarioValidationError, match="Unknown phase"):
        load_scenario(bad)

def test_scenario_rejects_unknown_layers(tmp_path):
    canonical = discover_canonical()
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "name": "test",
        "phases": {"OBSERVE": {"layers": ["definitely_not_a_real_layer_xyz"]}}
    }))
    scenario = load_scenario(bad)
    with pytest.raises(ScenarioValidationError, match="Unknown layers"):
        validate_layers(scenario, canonical)


# ── Scenario runner dry-run tests ──────────────────────────────────────────────

def test_runner_dry_run_persistence_scenario():
    cycle = run_scenario(
        EXAMPLE_DIR / "persistence_pressure_test.json",
        dry_run=True,
        verbose=False,
    )
    assert isinstance(cycle, BananaTreeCycle)
    assert cycle.dry_run is True
    assert cycle.total_layers > 0

def test_runner_produces_all_four_phases():
    cycle = run_scenario(
        EXAMPLE_DIR / "persistence_pressure_test.json",
        dry_run=True,
        verbose=False,
    )
    d = cycle.to_dict()
    assert "OBSERVE"  in d["phases"]
    assert "SIMULATE" in d["phases"]
    assert "EXECUTE"  in d["phases"]
    assert "ADAPT"    in d["phases"]

def test_runner_safety_contract_unchanged():
    cycle = run_scenario(
        EXAMPLE_DIR / "c2_shape_detection_test.json",
        dry_run=True,
        verbose=False,
    )
    assert cycle.safety_contract["simulation_only"] is True
    assert cycle.safety_contract["executable"] is False
    assert cycle.safety_contract["no_payload_present"] is True
    assert cycle.safety_contract["network_calls_made"] is False

def test_runner_collects_findings():
    cycle = run_scenario(
        EXAMPLE_DIR / "persistence_pressure_test.json",
        dry_run=True,
        verbose=False,
    )
    all_findings = []
    for result in cycle.phases.values():
        all_findings.extend(result.findings)
    assert len(all_findings) > 0

def test_runner_collects_mitre_techniques():
    cycle = run_scenario(
        EXAMPLE_DIR / "c2_shape_detection_test.json",
        dry_run=True,
        verbose=False,
    )
    assert len(cycle.all_mitre) > 0

def test_runner_full_stack_all_phases_have_layers():
    cycle = run_scenario(
        EXAMPLE_DIR / "full_stack_adversarial_shape_test.json",
        dry_run=True,
        verbose=False,
    )
    for phase, result in cycle.phases.items():
        assert len(result.layers_run) > 0, f"{phase.value} has no layers"

def test_runner_entropy_sweep_scenario():
    cycle = run_scenario(
        EXAMPLE_DIR / "entropy_obfuscation_sweep.json",
        dry_run=True,
        verbose=False,
    )
    assert cycle.total_layers > 0
    assert Phase.OBSERVE  in cycle.phases
    assert Phase.SIMULATE in cycle.phases
    assert Phase.EXECUTE  in cycle.phases
    assert Phase.ADAPT    in cycle.phases

def test_runner_campaign_name_from_scenario():
    cycle = run_scenario(
        EXAMPLE_DIR / "persistence_pressure_test.json",
        dry_run=True,
        verbose=False,
    )
    assert "persistence" in cycle.campaign_name

def test_runner_completed_at_set_after_run():
    cycle = run_scenario(
        EXAMPLE_DIR / "c2_shape_detection_test.json",
        dry_run=True,
        verbose=False,
    )
    assert cycle.completed_at is not None
