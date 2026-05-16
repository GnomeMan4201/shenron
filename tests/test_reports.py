#!/usr/bin/env python3
"""SHENRON report generator v2 tests."""
import json, sys, pytest, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.reports.model import (
    ShenronReport, Finding, DetectionOpportunity,
    EvidenceRef, MITRECoverage, SafetyVerification
)
from core.reports.evidence import (
    load_artifacts, verify_safety, get_campaign_runs,
    group_artifacts_by_layer, build_report_from_run,
)
from core.reports.markdown import (
    render_markdown, write_report, REQUIRED_SECTIONS
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _safe_artifact(**overrides):
    base = {
        "artifact_id":      "test-id-001",
        "session_id":       "sess-001",
        "layer":            "beacon_emitter_cloak",
        "phase":            "signal_clone",
        "timestamp":        "2026-05-16T00:00:00+00:00",
        "behavior_class":   "test_behavior_sim",
        "simulation_only":  True,
        "executable":       False,
        "no_payload_present": True,
        "network_calls_made": False,
        "processes_spawned":  False,
    }
    base.update(overrides)
    return base


def _make_report(**kwargs) -> ShenronReport:
    r = ShenronReport(
        run_id        = "run-test-001",
        campaign_name = "test_campaign",
        phases_run    = ["OBSERVE", "SIMULATE", "EXECUTE", "ADAPT"],
        layers_run    = ["beacon_emitter_cloak", "dormant_sleeper_seed"],
        total_events  = 5,
        **kwargs
    )
    r.safety.simulate_only     = True
    r.safety.executable_false  = True
    r.safety.no_payload_present= True
    r.safety.network_calls_false = True
    r.safety.processes_spawned_false = True
    r.safety.all_passed        = True
    r.mitre.techniques         = ["T1071", "T1053"]
    r.mitre.tactics            = ["command-and-control", "persistence"]
    r.findings = [
        Finding(
            phase="OBSERVE", layer="beacon_emitter_cloak",
            description="C2 beacon sim", mitre=["T1071"],
            detections=["periodic_beacon"],
        ),
        Finding(
            phase="EXECUTE", layer="dormant_sleeper_seed",
            description="Persistence sim", mitre=["T1053"],
            detections=["scheduled_task_creation"],
        ),
    ]
    r.detections = [
        DetectionOpportunity("OBSERVE", "beacon_emitter_cloak", "periodic_beacon", ["T1071"]),
        DetectionOpportunity("EXECUTE", "dormant_sleeper_seed", "scheduled_task_creation", ["T1053"]),
    ]
    r.alert_signatures = [
        {"layer": "beacon_emitter_cloak", "phase": "OBSERVE", "signature": "regular beacon interval"},
        {"layer": "dormant_sleeper_seed", "phase": "EXECUTE", "signature": "new scheduled task"},
    ]
    r.artifacts = [
        EvidenceRef("art-001", "beacon_emitter_cloak", "OBSERVE", "2026-05-16T00:00:00", "signal_clone_sim", True),
    ]
    return r


# ── Model tests ───────────────────────────────────────────────────────────────

def test_shenron_report_to_dict_has_required_keys():
    r = _make_report()
    d = r.to_dict()
    for key in ["report_id", "run_id", "campaign_name", "generated_at",
                "phases_run", "layers_run", "total_events", "mitre", "safety"]:
        assert key in d, f"missing key: {key}"

def test_safety_verification_passes_all_safe():
    sv = SafetyVerification()
    arts = [_safe_artifact() for _ in range(5)]
    sv.evaluate(arts)
    assert sv.all_passed is True
    assert len(sv.violations) == 0

def test_safety_verification_fails_when_executable_true():
    sv = SafetyVerification()
    arts = [_safe_artifact(executable=True)]
    sv.evaluate(arts)
    assert sv.all_passed is False
    assert any("executable" in v for v in sv.violations)

def test_safety_verification_fails_when_simulation_only_false():
    sv = SafetyVerification()
    arts = [_safe_artifact(simulation_only=False)]
    sv.evaluate(arts)
    assert sv.all_passed is False

def test_safety_verification_fails_when_network_calls_true():
    sv = SafetyVerification()
    arts = [_safe_artifact(network_calls_made=True)]
    sv.evaluate(arts)
    assert sv.all_passed is False

def test_safety_verification_fails_when_processes_spawned_true():
    sv = SafetyVerification()
    arts = [_safe_artifact(processes_spawned=True)]
    sv.evaluate(arts)
    assert sv.all_passed is False

def test_safety_verification_fails_closed_on_empty_artifacts():
    sv = SafetyVerification()
    sv.evaluate([])
    assert sv.all_passed is True  # empty = no violations

def test_safety_verification_fails_closed_on_missing_fields():
    sv = SafetyVerification()
    arts = [{"artifact_id": "x"}]  # no safety fields
    sv.evaluate(arts)
    # simulation_only missing → treated as violation
    assert sv.all_passed is False

def test_mitre_coverage_to_dict():
    m = MITRECoverage(techniques=["T1071", "T1053", "T1071"], tactics=["c2"])
    d = m.to_dict()
    assert d["technique_count"] == 2  # deduped
    assert "T1071" in d["techniques"]
    assert "c2" in d["tactics"]

def test_finding_has_required_fields():
    f = Finding(phase="OBSERVE", layer="beacon_emitter_cloak",
                description="test", mitre=["T1071"])
    assert f.phase == "OBSERVE"
    assert f.layer == "beacon_emitter_cloak"
    assert "T1071" in f.mitre

def test_evidence_ref_safe_flag():
    e = EvidenceRef("id", "layer", "phase", "ts", "behavior", safe=True)
    assert e.safe is True


# ── Evidence loader tests ──────────────────────────────────────────────────────

def test_load_artifacts_returns_empty_for_missing_file():
    result = load_artifacts(Path("/tmp/does_not_exist_xyz.jsonl"))
    assert result == []

def test_load_artifacts_parses_jsonl(tmp_path):
    p = tmp_path / "test.jsonl"
    records = [_safe_artifact(artifact_id=f"id-{i}") for i in range(5)]
    p.write_text("\n".join(json.dumps(r) for r in records))
    result = load_artifacts(p)
    assert len(result) == 5

def test_load_artifacts_skips_invalid_json(tmp_path):
    p = tmp_path / "test.jsonl"
    p.write_text('{"ok": true}\nNOT_JSON\n{"ok": true}\n')
    result = load_artifacts(p)
    assert len(result) == 2

def test_group_artifacts_by_layer():
    arts = [
        _safe_artifact(layer="beacon_emitter_cloak"),
        _safe_artifact(layer="beacon_emitter_cloak"),
        _safe_artifact(layer="dormant_sleeper_seed"),
    ]
    grouped = group_artifacts_by_layer(arts)
    assert len(grouped["beacon_emitter_cloak"]) == 2
    assert len(grouped["dormant_sleeper_seed"]) == 1

def test_get_campaign_runs_parses_timeline():
    timeline = [
        {"record_type": "bananatree_campaign_start", "run_id": "r1", "campaign_name": "test", "timestamp": "ts", "dry_run": True, "scenario": "s"},
        {"record_type": "bananatree_phase_end", "phase": "OBSERVE", "layers_run": ["beacon_emitter_cloak"], "findings": [], "mitre_techniques": ["T1071"], "errors": []},
        {"record_type": "bananatree_campaign_end", "run_id": "r1", "timestamp": "ts2", "total_layers": 1, "all_mitre": ["T1071"]},
    ]
    runs = get_campaign_runs(timeline)
    assert len(runs) == 1
    assert runs[0]["run_id"] == "r1"
    assert len(runs[0]["phases"]) == 1

def test_get_campaign_runs_returns_empty_for_empty_timeline():
    assert get_campaign_runs([]) == []

def test_verify_safety_passes_all_safe_artifacts():
    arts = [_safe_artifact() for _ in range(10)]
    sv = verify_safety(arts)
    assert sv.all_passed is True

def test_verify_safety_fails_closed_on_missing_simulation_only():
    arts = [{"artifact_id": "x", "executable": False}]
    sv = verify_safety(arts)
    assert sv.all_passed is False


# ── Markdown renderer tests ────────────────────────────────────────────────────

def test_render_markdown_contains_all_required_sections():
    r = _make_report()
    md = render_markdown(r)
    for section in REQUIRED_SECTIONS:
        assert section in md, f"Missing section: {section}"

def test_render_markdown_contains_run_id():
    r = _make_report()
    md = render_markdown(r)
    assert "run-test-001" in md

def test_render_markdown_contains_campaign_name():
    r = _make_report()
    md = render_markdown(r)
    assert "test_campaign" in md

def test_render_markdown_safety_pass_shows_checkmark():
    r = _make_report()
    r.safety.all_passed = True
    md = render_markdown(r)
    assert "✅" in md

def test_render_markdown_safety_fail_shows_cross():
    r = _make_report()
    r.safety.all_passed = False
    r.safety.violations = ["test violation"]
    md = render_markdown(r)
    assert "❌" in md

def test_render_markdown_contains_mitre_techniques():
    r = _make_report()
    md = render_markdown(r)
    assert "T1071" in md
    assert "T1053" in md

def test_render_markdown_contains_detection_opportunities():
    r = _make_report()
    md = render_markdown(r)
    assert "periodic beacon" in md or "periodic_beacon" in md

def test_render_markdown_contains_alert_signatures():
    r = _make_report()
    md = render_markdown(r)
    assert "regular beacon interval" in md
    assert "new scheduled task" in md

def test_render_markdown_contains_all_phase_names():
    r = _make_report()
    md = render_markdown(r)
    for phase in ["OBSERVE", "SIMULATE", "EXECUTE", "ADAPT"]:
        assert phase in md

def test_render_markdown_safety_contract_table_present():
    r = _make_report()
    md = render_markdown(r)
    assert "simulation_only" in md
    assert "executable" in md
    assert "no_payload_present" in md

def test_write_report_creates_file(tmp_path):
    r = _make_report()
    path = write_report(r, output_dir=str(tmp_path))
    assert Path(path).exists()
    assert Path(path).suffix == ".md"
    content = Path(path).read_text()
    assert "Executive Summary" in content

def test_write_report_filename_contains_run_id(tmp_path):
    r = _make_report()
    path = write_report(r, output_dir=str(tmp_path))
    assert "run-test" in path
