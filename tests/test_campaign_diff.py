"""
tests/test_campaign_diff.py

Tests for core/campaign/diff.py — SHENRON Campaign Diff Tool.
"""
import json
import tempfile
from pathlib import Path
import pytest
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.campaign.diff import (
    diff_campaigns,
    diff_scenario_seeds,
    CampaignDiffReport,
    PhaseDensity,
    _load_events,
    _extract_techniques,
    _extract_signals,
    _extract_phases,
    _extract_layers,
    _phase_density,
    _jaccard,
)

DEMO_ARTIFACT = Path(__file__).parent.parent / "artifacts" / "demo" / "shenron_demo_run.jsonl"
LLM_ARTIFACT  = Path(__file__).parent.parent / "artifacts" / "llm_manipulation" / "scenario_run.jsonl"

SAMPLE_EVENTS_A = [
    {"layer": "beacon_emitter_cloak", "phase": "OBSERVE",
     "mitre_techniques": ["T1071", "T1132"],
     "detection_opportunities": ["periodic_beacon"],
     "signal": "beacon_signal", "behavior_class": "c2_beacon",
     "simulation_only": True},
    {"layer": "dormant_persistence_sim", "phase": "EXECUTE",
     "mitre_techniques": ["T1053"],
     "detection_opportunities": ["scheduled_task_creation"],
     "signal": "persistence_signal", "behavior_class": "persistence",
     "simulation_only": True},
]

SAMPLE_EVENTS_B = [
    {"layer": "beacon_emitter_cloak", "phase": "OBSERVE",
     "mitre_techniques": ["T1071"],
     "detection_opportunities": ["periodic_beacon", "dns_burst"],
     "signal": "beacon_signal", "behavior_class": "c2_beacon",
     "simulation_only": True},
    {"layer": "lateral_webcrawler", "phase": "EXECUTE",
     "mitre_techniques": ["T1021", "T1046"],
     "detection_opportunities": ["subnet_sweep"],
     "signal": "lateral_signal", "behavior_class": "lateral",
     "simulation_only": True},
]


# -- Jaccard similarity --------------------------------------------------------

def test_jaccard_identical():
    assert _jaccard({"a", "b"}, {"a", "b"}) == 1.0

def test_jaccard_disjoint():
    assert _jaccard({"a", "b"}, {"c", "d"}) == 0.0

def test_jaccard_partial():
    result = _jaccard({"a", "b", "c"}, {"a", "b", "d"})
    assert 0.0 < result < 1.0

def test_jaccard_empty_both():
    assert _jaccard(set(), set()) == 1.0

def test_jaccard_one_empty():
    assert _jaccard({"a"}, set()) == 0.0


# -- Event extraction ----------------------------------------------------------

def test_extract_techniques_basic():
    techs = _extract_techniques(SAMPLE_EVENTS_A)
    assert "T1071" in techs
    assert "T1053" in techs

def test_extract_techniques_empty():
    assert _extract_techniques([]) == set()

def test_extract_techniques_single_field():
    events = [{"mitre_technique": "T1059", "mitre_techniques": []}]
    techs = _extract_techniques(events)
    assert "T1059" in techs

def test_extract_signals_basic():
    sigs = _extract_signals(SAMPLE_EVENTS_A)
    assert "periodic_beacon" in sigs
    assert "beacon_signal" in sigs

def test_extract_signals_includes_behavior_class():
    sigs = _extract_signals(SAMPLE_EVENTS_A)
    assert "c2_beacon" in sigs

def test_extract_phases_basic():
    phases = _extract_phases(SAMPLE_EVENTS_A)
    assert "OBSERVE" in phases
    assert "EXECUTE" in phases

def test_extract_layers_basic():
    layers = _extract_layers(SAMPLE_EVENTS_A)
    assert "beacon_emitter_cloak" in layers
    assert "dormant_persistence_sim" in layers

def test_phase_density_basic():
    density = _phase_density(SAMPLE_EVENTS_A)
    assert density["OBSERVE"] == 1
    assert density["EXECUTE"] == 1

def test_phase_density_empty():
    assert _phase_density([]) == {}


# -- Artifact loading ----------------------------------------------------------

def test_load_events_returns_list():
    events = _load_events(str(DEMO_ARTIFACT))
    assert isinstance(events, list)
    assert len(events) > 0

def test_load_events_all_dicts():
    events = _load_events(str(DEMO_ARTIFACT))
    assert all(isinstance(e, dict) for e in events)

def test_load_events_nonexistent():
    with pytest.raises(FileNotFoundError):
        _load_events("/nonexistent/path.jsonl")


# -- Diff report structure -----------------------------------------------------

def test_diff_returns_report():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as fa:
        for ev in SAMPLE_EVENTS_A:
            fa.write(json.dumps(ev) + "\n")
        path_a = fa.name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as fb:
        for ev in SAMPLE_EVENTS_B:
            fb.write(json.dumps(ev) + "\n")
        path_b = fb.name
    try:
        report = diff_campaigns(path_a, path_b, verbose=False)
        assert isinstance(report, CampaignDiffReport)
    finally:
        import os
        os.unlink(path_a)
        os.unlink(path_b)

def test_diff_has_required_fields():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as fa:
        for ev in SAMPLE_EVENTS_A:
            fa.write(json.dumps(ev) + "\n")
        path_a = fa.name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as fb:
        for ev in SAMPLE_EVENTS_B:
            fb.write(json.dumps(ev) + "\n")
        path_b = fb.name
    try:
        report = diff_campaigns(path_a, path_b, verbose=False)
        assert hasattr(report, "technique_stability")
        assert hasattr(report, "signal_stability")
        assert hasattr(report, "overall_stability")
        assert hasattr(report, "seed_dependent")
        assert hasattr(report, "coverage_delta")
        assert hasattr(report, "phase_density")
    finally:
        import os
        os.unlink(path_a)
        os.unlink(path_b)


# -- Self-diff (stability = 1.0) -----------------------------------------------

def test_self_diff_perfect_stability():
    report = diff_campaigns(str(DEMO_ARTIFACT), str(DEMO_ARTIFACT), verbose=False)
    assert report.overall_stability == 1.0

def test_self_diff_no_technique_diff():
    report = diff_campaigns(str(DEMO_ARTIFACT), str(DEMO_ARTIFACT), verbose=False)
    assert report.techniques_only_a == []
    assert report.techniques_only_b == []

def test_self_diff_no_signal_diff():
    report = diff_campaigns(str(DEMO_ARTIFACT), str(DEMO_ARTIFACT), verbose=False)
    assert report.signals_only_a == []
    assert report.signals_only_b == []

def test_self_diff_not_seed_dependent():
    report = diff_campaigns(str(DEMO_ARTIFACT), str(DEMO_ARTIFACT), verbose=False)
    assert report.seed_dependent is False

def test_self_diff_zero_coverage_delta():
    report = diff_campaigns(str(DEMO_ARTIFACT), str(DEMO_ARTIFACT), verbose=False)
    assert report.coverage_delta == 0


# -- Cross-scenario diff -------------------------------------------------------

def test_cross_diff_low_stability():
    if not LLM_ARTIFACT.exists():
        pytest.skip("LLM artifact not present")
    report = diff_campaigns(str(DEMO_ARTIFACT), str(LLM_ARTIFACT), verbose=False)
    assert report.overall_stability < 0.5

def test_cross_diff_has_technique_diff():
    if not LLM_ARTIFACT.exists():
        pytest.skip("LLM artifact not present")
    report = diff_campaigns(str(DEMO_ARTIFACT), str(LLM_ARTIFACT), verbose=False)
    assert len(report.techniques_only_a) > 0 or len(report.techniques_only_b) > 0

def test_cross_diff_event_counts():
    if not LLM_ARTIFACT.exists():
        pytest.skip("LLM artifact not present")
    report = diff_campaigns(str(DEMO_ARTIFACT), str(LLM_ARTIFACT), verbose=False)
    assert report.event_count_a == 50
    assert report.event_count_b == 12


# -- Stability scoring ---------------------------------------------------------

def test_stability_range():
    report = diff_campaigns(str(DEMO_ARTIFACT), str(DEMO_ARTIFACT), verbose=False)
    assert 0.0 <= report.technique_stability <= 1.0
    assert 0.0 <= report.signal_stability <= 1.0
    assert 0.0 <= report.overall_stability <= 1.0

def test_technique_stability_weight():
    # Overall = tech * 0.6 + signal * 0.4
    report = diff_campaigns(str(DEMO_ARTIFACT), str(DEMO_ARTIFACT), verbose=False)
    expected = round(report.technique_stability * 0.6 + report.signal_stability * 0.4, 3)
    assert abs(report.overall_stability - expected) < 0.001


# -- Phase density -------------------------------------------------------------

def test_phase_density_list_nonempty():
    report = diff_campaigns(str(DEMO_ARTIFACT), str(DEMO_ARTIFACT), verbose=False)
    assert len(report.phase_density) > 0

def test_phase_density_items_type():
    report = diff_campaigns(str(DEMO_ARTIFACT), str(DEMO_ARTIFACT), verbose=False)
    for pd in report.phase_density:
        assert isinstance(pd, PhaseDensity)

def test_phase_density_self_diff_zero_delta():
    report = diff_campaigns(str(DEMO_ARTIFACT), str(DEMO_ARTIFACT), verbose=False)
    for pd in report.phase_density:
        assert pd.delta == 0


# -- Report serialization ------------------------------------------------------

def test_to_dict():
    report = diff_campaigns(str(DEMO_ARTIFACT), str(DEMO_ARTIFACT), verbose=False)
    d = report.to_dict()
    assert "technique_stability" in d
    assert "signal_stability" in d
    assert "overall_stability" in d
    assert "phase_density" in d
    assert isinstance(d["phase_density"], list)

def test_to_markdown():
    report = diff_campaigns(str(DEMO_ARTIFACT), str(DEMO_ARTIFACT), verbose=False)
    md = report.to_markdown()
    assert "SHENRON Campaign Diff Report" in md
    assert "Stability Summary" in md
    assert "Technique Diff" in md
    assert "Phase Density" in md

def test_to_markdown_seed_stable_message():
    report = diff_campaigns(str(DEMO_ARTIFACT), str(DEMO_ARTIFACT), verbose=False)
    md = report.to_markdown()
    assert "seed-stable" in md.lower()

def test_to_dict_roundtrip():
    report = diff_campaigns(str(DEMO_ARTIFACT), str(DEMO_ARTIFACT), verbose=False)
    d = report.to_dict()
    assert d["technique_stability"] == report.technique_stability
    assert d["overall_stability"] == report.overall_stability
    assert d["seed_dependent"] == report.seed_dependent


# -- Scenario seed diff --------------------------------------------------------

def test_diff_scenario_seeds_returns_report():
    report = diff_scenario_seeds("apt29-style", seed_a=42, seed_b=99,
                                  output_dir="/tmp/shenron_diff_test", verbose=False)
    assert isinstance(report, CampaignDiffReport)

def test_diff_scenario_seeds_same_scenario_stable():
    report = diff_scenario_seeds("apt29-style", seed_a=42, seed_b=99,
                                  output_dir="/tmp/shenron_diff_test", verbose=False)
    # apt29-style with different seeds should have identical technique coverage
    assert report.technique_stability == 1.0

def test_diff_scenario_seeds_artifacts_created():
    import os
    out_dir = "/tmp/shenron_diff_test2"
    diff_scenario_seeds("apt29-style", seed_a=1, seed_b=2,
                        output_dir=out_dir, verbose=False)
    assert Path(out_dir).exists()
    jsonl_files = list(Path(out_dir).glob("*.jsonl"))
    assert len(jsonl_files) >= 2
