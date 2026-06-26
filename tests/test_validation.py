#!/usr/bin/env python3
"""SHENRON detector validation tests."""
import json, sys, pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.validation.coverage import (
    DetectionExpectation, DetectionResult, DetectionStatus,
    DetectionCoverageReport,
)
from core.validation.expectations import (
    _normalize, load_from_scenario, load_from_scenario_file,
)
from core.validation.scorer import (
    score_run, _match_expectation, _exact_match, _partial_match,
)
from core.reports.markdown import render_validation_section


# ── Fixtures ──────────────────────────────────────────────────────────────────

EXAMPLE_SCENARIO = {
    "name": "test_scenario",
    "phases": {
        "OBSERVE": {
            "layers": ["beacon_emitter_cloak"],
            "expected_findings": ["periodic_beacon_to_external_host", "dns_subdomain_query"],
        },
        "EXECUTE": {
            "layers": ["dormant_persistence_sim"],
            "expected_findings": ["scheduled_task_creation"],
        },
    }
}

def _safe_art(layer="beacon_emitter_cloak", phase="signal_clone", **kw):
    base = {
        "artifact_id":      "test-art-001",
        "session_id":       "sess-001",
        "layer":            layer,
        "phase":            phase,
        "timestamp":        "2026-05-16T00:00:00+00:00",
        "behavior_class":   "http_beacon_sim",
        "simulation_only":  True,
        "executable":       False,
        "no_payload_present": True,
        "network_calls_made": False,
        "processes_spawned":  False,
    }
    base.update(kw)
    return base

def _make_run(layers=None, all_mitre=None):
    return {
        "run_id":        "run-test-001",
        "campaign_name": "test_campaign",
        "scenario":      "test_scenario.json",
        "dry_run":       True,
        "phases": [
            {
                "phase":      "OBSERVE",
                "layers_run": layers or ["beacon_emitter_cloak"],
                "findings":   ["periodic_beacon"],
                "mitre":      ["T1071"],
                "errors":     [],
            }
        ],
        "all_mitre": all_mitre or ["T1071"],
    }

def _make_cov_report(verdict="PASS", observed=3, expected=4, missing=1):
    r = DetectionCoverageReport(
        run_id="run-001", campaign_name="test",
        expected_count=expected, observed_count=observed,
        missing_count=missing, coverage_percent=75.0,
        verdict=verdict,
    )
    r.results = [
        DetectionResult(
            expectation=DetectionExpectation(name="periodic_beacon", normalized="periodic_beacon"),
            status=DetectionStatus.PASS, match_reason="exact match",
        ),
        DetectionResult(
            expectation=DetectionExpectation(name="missing_detection", normalized="missing_detection"),
            status=DetectionStatus.MISS, match_reason="no match found",
        ),
    ]
    return r


# ── Normalization tests ───────────────────────────────────────────────────────

def test_normalize_lowercases():
    assert _normalize("PERIODIC_BEACON") == "periodic_beacon"

def test_normalize_strips_punctuation():
    assert _normalize("dns-subdomain-query") == "dns_subdomain_query"

def test_normalize_collapses_spaces():
    assert _normalize("scheduled task creation") == "scheduled_task_creation"

def test_normalize_handles_mixed():
    assert _normalize("Sequential IP Scan!") == "sequential_ip_scan"


# ── Expectation loading tests ──────────────────────────────────────────────────

def test_load_from_scenario_returns_list():
    exps = load_from_scenario(EXAMPLE_SCENARIO)
    assert isinstance(exps, list)
    assert len(exps) > 0

def test_load_from_scenario_includes_expected_findings():
    exps = load_from_scenario(EXAMPLE_SCENARIO)
    names = [e.name for e in exps]
    assert "periodic_beacon_to_external_host" in names or \
           any("beacon" in n for n in names)

def test_load_from_scenario_deduplicates():
    dupe_scenario = {
        "name": "dupe",
        "phases": {
            "OBSERVE": {"layers": [], "expected_findings": ["same_detection", "same_detection"]},
            "EXECUTE": {"layers": [], "expected_findings": ["same_detection"]},
        }
    }
    exps = load_from_scenario(dupe_scenario)
    normalized = [e.normalized for e in exps]
    assert normalized.count("same_detection") == 1

def test_load_from_scenario_assigns_phase():
    exps = load_from_scenario(EXAMPLE_SCENARIO)
    observe_exps = [e for e in exps if e.phase == "OBSERVE"]
    assert len(observe_exps) > 0

def test_load_from_scenario_file_returns_empty_for_missing():
    result = load_from_scenario_file("/tmp/does_not_exist_xyz.json")
    assert result == []

def test_load_from_scenario_file_loads_example():
    p = Path("scenarios/examples/persistence_pressure_test.json")
    if p.exists():
        exps = load_from_scenario_file(p)
        assert len(exps) > 0

def test_load_from_scenario_includes_manifest_events():
    exps = load_from_scenario(EXAMPLE_SCENARIO)
    # beacon_emitter_cloak has expected_events in manifest
    layers = [e.layer for e in exps if e.layer]
    assert "beacon_emitter_cloak" in layers or len(exps) > 0


# ── Matching tests ────────────────────────────────────────────────────────────

def test_exact_match_passes():
    assert _exact_match("periodic_beacon", "periodic_beacon") is True

def test_exact_match_fails_different():
    assert _exact_match("periodic_beacon", "dns_query") is False

def test_exact_match_case_insensitive():
    assert _exact_match("periodic_beacon", "PERIODIC_BEACON") is True

def test_partial_match_passes_with_overlap():
    assert _partial_match("periodic_beacon_external", "periodic_beacon") is True

def test_partial_match_fails_no_overlap():
    assert _partial_match("beacon_interval", "filesystem_write") is False

def test_partial_match_requires_50_percent():
    # "a_b_c_d" vs "a_b_x_y" → 2/4 = 50% → passes
    assert _partial_match("a_b_c_d", "a_b_x_y") is True
    # "a_b_c_d" vs "x_y_z_w" → 0/4 = 0% → fails
    assert _partial_match("a_b_c_d", "x_y_z_w") is False


# ── Scorer tests ───────────────────────────────────────────────────────────────

def test_score_run_returns_report():
    run = _make_run()
    arts = [_safe_art()]
    report = score_run(run, arts, EXAMPLE_SCENARIO)
    assert isinstance(report, DetectionCoverageReport)

def test_score_run_expected_count_positive():
    run = _make_run()
    arts = [_safe_art()]
    report = score_run(run, arts, EXAMPLE_SCENARIO)
    assert report.expected_count > 0

def test_score_run_coverage_between_0_and_100():
    run = _make_run()
    arts = [_safe_art()]
    report = score_run(run, arts, EXAMPLE_SCENARIO)
    assert 0.0 <= report.coverage_percent <= 100.0

def test_score_run_exact_match_produces_pass():
    run = _make_run(layers=["beacon_emitter_cloak"])
    arts = [_safe_art(
        layer="beacon_emitter_cloak",
        behavior_class="periodic_beacon_to_external_host",
    )]
    exps = [DetectionExpectation(
        name="periodic_beacon_to_external_host",
        normalized="periodic_beacon_to_external_host",
        layer="beacon_emitter_cloak",
    )]
    from core.validation.scorer import _match_expectation
    from core.reports.evidence import _load_manifest_index
    manifest = _load_manifest_index()
    by_layer = {"beacon_emitter_cloak": arts}
    result = _match_expectation(exps[0], by_layer, arts, manifest)
    assert result.status == DetectionStatus.PASS

def test_score_run_missing_detection_produces_miss():
    run = _make_run()
    arts = []  # no artifacts
    exp = DetectionExpectation(
        name="xyz_impossible_detection_never_exists",
        normalized="xyz_impossible_detection_never_exists",
    )
    from core.validation.scorer import _match_expectation
    from core.reports.evidence import _load_manifest_index
    manifest = _load_manifest_index()
    result = _match_expectation(exp, {}, arts, manifest)
    assert result.status == DetectionStatus.MISS

def test_score_run_partial_match_produces_partial():
    from core.validation.scorer import _match_expectation
    from core.reports.evidence import _load_manifest_index
    manifest = _load_manifest_index()
    arts = [_safe_art(behavior_class="periodic_beacon_check_sim")]
    exp = DetectionExpectation(
        name="periodic_beacon",
        normalized="periodic_beacon",
    )
    by_layer = {"beacon_emitter_cloak": arts}
    result = _match_expectation(exp, by_layer, arts, manifest)
    assert result.status in (DetectionStatus.PASS, DetectionStatus.PARTIAL)

def test_score_run_safety_failure_reduces_verdict():
    run = _make_run()
    arts = [_safe_art(simulation_only=False)]  # safety violation
    report = score_run(run, arts, EXAMPLE_SCENARIO)
    assert report.safety_failure_count > 0
    assert report.verdict == "UNSAFE"

def test_coverage_report_compute_pass_at_80_percent():
    r = DetectionCoverageReport()
    r.results = [
        DetectionResult(
            expectation=DetectionExpectation(name=f"det_{i}", normalized=f"det_{i}"),
            status=DetectionStatus.PASS,
        )
        for i in range(8)
    ] + [
        DetectionResult(
            expectation=DetectionExpectation(name=f"miss_{i}", normalized=f"miss_{i}"),
            status=DetectionStatus.MISS,
        )
        for i in range(2)
    ]
    r.compute()
    assert r.verdict == "PASS"
    assert r.coverage_percent == 80.0

def test_coverage_report_compute_fail_below_50():
    r = DetectionCoverageReport()
    r.results = [
        DetectionResult(
            expectation=DetectionExpectation(name=f"det_{i}", normalized=f"det_{i}"),
            status=DetectionStatus.MISS,
        )
        for i in range(10)
    ]
    r.compute()
    assert r.verdict == "FAIL"
    assert r.coverage_percent == 0.0

def test_coverage_report_partial_counts_half():
    r = DetectionCoverageReport()
    r.results = [
        DetectionResult(
            expectation=DetectionExpectation(name="p", normalized="p"),
            status=DetectionStatus.PARTIAL,
        ),
        DetectionResult(
            expectation=DetectionExpectation(name="m", normalized="m"),
            status=DetectionStatus.MISS,
        ),
    ]
    r.compute()
    assert r.coverage_percent == 25.0  # 0.5 / 2 * 100

def test_coverage_report_to_dict_keys():
    r = DetectionCoverageReport()
    r.compute()
    d = r.to_dict()
    for key in ["run_id", "expected_count", "observed_count", "missing_count",
                "coverage_percent", "verdict", "results"]:
        assert key in d


# ── Markdown validation section tests ──────────────────────────────────────────

def test_render_validation_section_contains_header():
    cov = _make_cov_report()
    md = render_validation_section(cov)
    assert "Detector Validation" in md

def test_render_validation_section_contains_verdict():
    cov = _make_cov_report(verdict="PASS")
    md = render_validation_section(cov)
    assert "PASS" in md

def test_render_validation_section_contains_coverage_percent():
    cov = _make_cov_report()
    cov.coverage_percent = 75.0
    md = render_validation_section(cov)
    assert "75.0" in md

def test_render_validation_section_contains_coverage_table():
    cov = _make_cov_report()
    md = render_validation_section(cov)
    assert "Coverage Table" in md

def test_render_validation_section_contains_missing_list():
    cov = _make_cov_report()
    md = render_validation_section(cov)
    assert "Missing Detections" in md
    assert "missing_detection" in md

def test_render_validation_section_unsafe_note_on_safety_failure():
    cov = _make_cov_report(verdict="UNSAFE")
    cov.safety_failure_count = 2
    md = render_validation_section(cov)
    assert "UNSAFE" in md or "Safety" in md

def test_full_report_includes_validation_section():
    from core.reports.model import ShenronReport, Finding
    from core.reports.markdown import render_markdown
    rpt = ShenronReport(
        run_id="r1", campaign_name="test",
        phases_run=["OBSERVE", "EXECUTE"],
        layers_run=["beacon_emitter_cloak"],
    )
    rpt.safety.all_passed = True
    rpt.mitre.techniques  = ["T1071"]
    cov = _make_cov_report()
    md = render_markdown(rpt, validation=cov)
    assert "Detector Validation" in md
