"""
tests/test_windows_event_log_sim.py

Tests for core/layers/windows_event_log_sim.py — Windows Event Log Simulator.
"""
import json
import tempfile
from pathlib import Path
import pytest
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.layers.windows_event_log_sim import (
    simulate_windows_events,
    write_windows_artifact,
    EVENT_GENERATORS,
    DEFAULT_SCENARIO,
    SIMULATED_TASK_NAMES,
    SIMULATED_PROCESSES,
    SIMULATED_COMPUTERS,
    _base_event,
    _gen_4688,
    _gen_4698,
    _gen_4697,
    _gen_4625,
    _gen_1102,
    _gen_7045,
    _safe_fields,
)
import random

WINDOWS_ARTIFACT = Path(__file__).parent.parent / "artifacts" / "windows_events" / "scenario_run.jsonl"
WINDOWS_SIGMA    = Path(__file__).parent.parent / "sigma" / "rules" / "persistence" / "windows_event_log.yml"


# -- Safety contract -----------------------------------------------------------

def test_safe_fields_simulation_only():
    assert _safe_fields()["simulation_only"] is True

def test_safe_fields_no_executable():
    assert _safe_fields()["executable"] is False

def test_safe_fields_no_payload():
    assert _safe_fields()["payload_present"] is False

def test_safe_fields_no_network():
    assert _safe_fields()["network_connection"] is False

def test_safe_fields_no_subprocess():
    assert _safe_fields()["subprocess_spawned"] is False


# -- Base event ----------------------------------------------------------------

def test_base_event_required_fields():
    ev = _base_event(4698, "Security", "Microsoft-Windows-Security-Auditing",
                     "DC01-SIM", "sess-001")
    assert ev["EventID"] == 4698
    assert ev["Channel"] == "Security"
    assert ev["Provider_Name"] == "Microsoft-Windows-Security-Auditing"
    assert ev["Computer"] == "DC01-SIM"
    assert ev["session_id"] == "sess-001"
    assert ev["layer"] == "windows_event_log_sim"
    assert ev["simulation_only"] is True

def test_base_event_duplicate_fields():
    ev = _base_event(4698, "Security", "Provider", "HOST", "sess")
    assert ev["EventID"] == ev["windows_event_id"] == ev["event_id_sim"]
    assert ev["Channel"] == ev["channel_sim"]
    assert ev["Provider_Name"] == ev["provider_sim"]
    assert ev["Computer"] == ev["computer_sim"]


# -- Individual generators -----------------------------------------------------

def test_gen_4688_event_id():
    rng = random.Random(42)
    ev = _gen_4688("sess", rng)
    assert ev["EventID"] == 4688

def test_gen_4688_has_commandline():
    rng = random.Random(42)
    ev = _gen_4688("sess", rng)
    assert "CommandLine" in ev
    assert "command_sim" in ev

def test_gen_4688_has_image():
    rng = random.Random(42)
    ev = _gen_4688("sess", rng)
    assert "Image" in ev

def test_gen_4688_mitre():
    rng = random.Random(42)
    ev = _gen_4688("sess", rng)
    assert "T1059" in ev["mitre_techniques"]

def test_gen_4698_event_id():
    rng = random.Random(42)
    ev = _gen_4698("sess", rng)
    assert ev["EventID"] == 4698

def test_gen_4698_has_taskname():
    rng = random.Random(42)
    ev = _gen_4698("sess", rng)
    assert "TaskName" in ev
    assert "task_name_sim" in ev

def test_gen_4698_mitre():
    rng = random.Random(42)
    ev = _gen_4698("sess", rng)
    assert "T1053" in ev["mitre_techniques"]
    assert "T1053.005" in ev["mitre_techniques"]

def test_gen_4697_event_id():
    rng = random.Random(42)
    ev = _gen_4697("sess", rng)
    assert ev["EventID"] == 4697

def test_gen_4697_has_service_fields():
    rng = random.Random(42)
    ev = _gen_4697("sess", rng)
    assert "ServiceName" in ev
    assert "ServiceFileName" in ev

def test_gen_4625_event_id():
    rng = random.Random(42)
    ev = _gen_4625("sess", rng)
    assert ev["EventID"] == 4625

def test_gen_4625_mitre():
    rng = random.Random(42)
    ev = _gen_4625("sess", rng)
    assert "T1110" in ev["mitre_techniques"]

def test_gen_1102_event_id():
    rng = random.Random(42)
    ev = _gen_1102("sess", rng)
    assert ev["EventID"] == 1102

def test_gen_1102_channel():
    rng = random.Random(42)
    ev = _gen_1102("sess", rng)
    assert ev["Channel"] == "Security"

def test_gen_1102_mitre():
    rng = random.Random(42)
    ev = _gen_1102("sess", rng)
    assert "T1070.001" in ev["mitre_techniques"]

def test_gen_7045_event_id():
    rng = random.Random(42)
    ev = _gen_7045("sess", rng)
    assert ev["EventID"] == 7045

def test_gen_7045_channel_system():
    rng = random.Random(42)
    ev = _gen_7045("sess", rng)
    assert ev["Channel"] == "System"


# -- Simulation ----------------------------------------------------------------

def test_simulate_returns_tuple():
    result = simulate_windows_events(seed=42, verbose=False)
    assert isinstance(result, tuple)
    assert len(result) == 2

def test_simulate_returns_events():
    _, events = simulate_windows_events(seed=42, verbose=False)
    assert len(events) > 0

def test_simulate_default_scenario_count():
    _, events = simulate_windows_events(seed=42, verbose=False)
    assert len(events) == len(DEFAULT_SCENARIO)

def test_simulate_all_simulation_only():
    _, events = simulate_windows_events(seed=42, verbose=False)
    assert all(ev["simulation_only"] is True for ev in events)

def test_simulate_no_executable():
    _, events = simulate_windows_events(seed=42, verbose=False)
    assert all(ev["executable"] is False for ev in events)

def test_simulate_no_payload():
    _, events = simulate_windows_events(seed=42, verbose=False)
    assert all(ev["payload_present"] is False for ev in events)

def test_simulate_all_have_eventid():
    _, events = simulate_windows_events(seed=42, verbose=False)
    assert all("EventID" in ev for ev in events)

def test_simulate_all_have_channel():
    _, events = simulate_windows_events(seed=42, verbose=False)
    assert all("Channel" in ev for ev in events)

def test_simulate_all_have_provider():
    _, events = simulate_windows_events(seed=42, verbose=False)
    assert all("Provider_Name" in ev for ev in events)

def test_simulate_all_have_mitre():
    _, events = simulate_windows_events(seed=42, verbose=False)
    assert all(len(ev.get("mitre_techniques", [])) > 0 for ev in events)

def test_simulate_all_have_detection_opps():
    _, events = simulate_windows_events(seed=42, verbose=False)
    assert all(len(ev.get("detection_opportunities", [])) > 0 for ev in events)

def test_simulate_all_have_safety_contract():
    _, events = simulate_windows_events(seed=42, verbose=False)
    for ev in events:
        safety = ev.get("safety", {})
        assert safety.get("simulation_only") is True
        assert safety.get("executable") is False

def test_simulate_unique_artifact_ids():
    _, events = simulate_windows_events(seed=42, verbose=False)
    ids = [ev["artifact_id"] for ev in events]
    assert len(ids) == len(set(ids))

def test_simulate_custom_scenario():
    _, events = simulate_windows_events(scenario=[4688, 4698], seed=42, verbose=False)
    assert len(events) == 2
    event_ids = [ev["EventID"] for ev in events]
    assert 4688 in event_ids
    assert 4698 in event_ids

def test_simulate_event_generators_coverage():
    assert 4688 in EVENT_GENERATORS
    assert 4698 in EVENT_GENERATORS
    assert 4697 in EVENT_GENERATORS
    assert 4625 in EVENT_GENERATORS
    assert 1102 in EVENT_GENERATORS
    assert 7045 in EVENT_GENERATORS

def test_simulate_tasknames_has_update():
    update_names = [t for t in SIMULATED_TASK_NAMES if "update" in t.lower()]
    assert len(update_names) > 0


# -- Write artifact ------------------------------------------------------------

def test_write_artifact_creates_file():
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/windows_test.jsonl"
        summary = write_windows_artifact(path, seed=42, verbose=False)
        assert Path(path).exists()

def test_write_artifact_valid_jsonl():
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/windows_test.jsonl"
        summary = write_windows_artifact(path, seed=42, verbose=False)
        with open(path) as f:
            lines = [json.loads(l) for l in f if l.strip()]
        assert len(lines) == summary["events_written"]

def test_write_artifact_returns_summary():
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/windows_test.jsonl"
        summary = write_windows_artifact(path, seed=42, verbose=False)
        assert "events_written" in summary
        assert "event_ids" in summary
        assert "session_id" in summary

def test_write_artifact_event_ids():
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/windows_test.jsonl"
        summary = write_windows_artifact(path, seed=42, verbose=False)
        assert 4698 in summary["event_ids"]


# -- pySigma bridge integration ------------------------------------------------

def test_windows_sigma_rule_triggers_on_artifact():
    if not WINDOWS_ARTIFACT.exists():
        pytest.skip("Windows artifact not present")
    from core.sigma.pysigma_bridge import evaluate_with_pysigma, BridgeVerdict
    result = evaluate_with_pysigma(str(WINDOWS_SIGMA), str(WINDOWS_ARTIFACT))
    assert result.verdict == BridgeVerdict.TRIGGERED

def test_windows_sigma_match_has_taskname_update():
    if not WINDOWS_ARTIFACT.exists():
        pytest.skip("Windows artifact not present")
    from core.sigma.pysigma_bridge import evaluate_with_pysigma, BridgeVerdict
    result = evaluate_with_pysigma(str(WINDOWS_SIGMA), str(WINDOWS_ARTIFACT))
    if result.verdict == BridgeVerdict.TRIGGERED:
        for ev in result.matched_events:
            task = ev.get("TaskName", "")
            assert "update" in task.lower() or "Update" in task
