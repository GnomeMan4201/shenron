"""
tests/test_adaptation.py

Tests for core/campaign/adaptation.py — SHENRON Adversary Adaptation Engine.
Uses the committed demo artifact and existing sigma rules.
"""
import json
import os
import tempfile
from pathlib import Path
import pytest
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.campaign.adaptation import (
    run_adaptation,
    _collect_rules,
    _write_temp_artifact,
    _safety_intact,
    _evaluate_rules,
    _firing_rule_ids,
    _apply_mutation,
    AdaptationReport,
    AdaptationIteration,
    RuleFireResult,
    ADAPTATION_STRATEGIES,
)

DEMO_ARTIFACT   = Path(__file__).parent.parent / "artifacts" / "demo" / "shenron_demo_run.jsonl"
SIGMA_RULES_DIR = Path(__file__).parent.parent / "sigma" / "rules"
GENERATED_DIR   = Path(__file__).parent.parent / "artifacts" / "sigma_generated"

SAMPLE_EVENTS = [
    {
        "artifact_id": "test-001",
        "session_id": "sess-abc",
        "layer": "beacon_emitter_cloak",
        "phase": "OBSERVE",
        "behavior_class": "periodic_beacon_to_external_host",
        "detection_opportunities": ["periodic_beacon_to_external_host"],
        "mitre_techniques": ["T1071"],
        "simulation_only": True,
        "executable": False,
        "timestamp": "2026-06-25T00:00:00+00:00",
    }
]


# ── Rule collection ────────────────────────────────────────────────────────────

def test_collect_rules_returns_list():
    rules = _collect_rules([str(SIGMA_RULES_DIR)])
    assert isinstance(rules, list)


def test_collect_rules_finds_yml_files():
    rules = _collect_rules([str(SIGMA_RULES_DIR)])
    assert len(rules) > 0
    assert all(str(r).endswith(".yml") for r in rules)


def test_collect_rules_deduplicates():
    rules = _collect_rules([str(SIGMA_RULES_DIR), str(SIGMA_RULES_DIR)])
    paths = [str(r) for r in rules]
    assert len(paths) == len(set(paths))


def test_collect_rules_nonexistent_dir():
    rules = _collect_rules(["/nonexistent/path"])
    assert rules == []


def test_collect_rules_multiple_dirs():
    rules = _collect_rules([str(SIGMA_RULES_DIR), str(GENERATED_DIR)])
    assert len(rules) >= len(_collect_rules([str(SIGMA_RULES_DIR)]))


# ── Artifact I/O ───────────────────────────────────────────────────────────────

def test_write_temp_artifact_creates_file():
    path = _write_temp_artifact(SAMPLE_EVENTS)
    try:
        assert os.path.exists(path)
    finally:
        os.unlink(path)


def test_write_temp_artifact_valid_jsonl():
    path = _write_temp_artifact(SAMPLE_EVENTS)
    try:
        with open(path) as f:
            lines = [json.loads(l) for l in f if l.strip()]
        assert len(lines) == len(SAMPLE_EVENTS)
    finally:
        os.unlink(path)


def test_write_temp_artifact_preserves_fields():
    path = _write_temp_artifact(SAMPLE_EVENTS)
    try:
        with open(path) as f:
            ev = json.loads(f.readline())
        assert ev["layer"] == "beacon_emitter_cloak"
        assert ev["simulation_only"] is True
    finally:
        os.unlink(path)


# ── Safety checks ──────────────────────────────────────────────────────────────

def test_safety_intact_clean_events():
    assert _safety_intact(SAMPLE_EVENTS) is True


def test_safety_intact_detects_executable():
    bad = [{"simulation_only": True, "executable": False,
            "safety": {"executable": True, "payload_present": False}}]
    assert _safety_intact(bad) is False


def test_safety_intact_detects_payload():
    bad = [{"simulation_only": True, "safety": {"executable": False, "payload_present": True}}]
    assert _safety_intact(bad) is False


def test_safety_intact_empty_list():
    assert _safety_intact([]) is True


# ── Rule evaluation ────────────────────────────────────────────────────────────

def test_evaluate_rules_returns_list():
    rules = _collect_rules([str(SIGMA_RULES_DIR)])[:3]
    path = _write_temp_artifact(SAMPLE_EVENTS)
    try:
        results = _evaluate_rules(rules, path)
    finally:
        os.unlink(path)
    assert isinstance(results, list)


def test_evaluate_rules_result_structure():
    rules = _collect_rules([str(SIGMA_RULES_DIR)])[:3]
    path = _write_temp_artifact(SAMPLE_EVENTS)
    try:
        results = _evaluate_rules(rules, path)
    finally:
        os.unlink(path)
    for r in results:
        assert hasattr(r, "rule_id")
        assert hasattr(r, "triggered")
        assert isinstance(r.triggered, bool)


def test_firing_rule_ids_returns_set():
    results = [
        RuleFireResult("r1", "Rule 1", "/path/r1.yml", "TRIGGERED", True),
        RuleFireResult("r2", "Rule 2", "/path/r2.yml", "NOT_TRIGGERED", False),
    ]
    firing = _firing_rule_ids(results)
    assert firing == {"r1"}


def test_firing_rule_ids_empty():
    assert _firing_rule_ids([]) == set()


# ── Mutation application ───────────────────────────────────────────────────────

def test_apply_mutation_label_ambiguity():
    result = _apply_mutation(SAMPLE_EVENTS, "label_ambiguity", "run-001", 42, None)
    assert isinstance(result, list)
    assert len(result) > 0


def test_apply_mutation_field_drop():
    result = _apply_mutation(SAMPLE_EVENTS, "field_drop", "run-001", 42, None)
    assert isinstance(result, list)


def test_apply_mutation_timing_jitter():
    result = _apply_mutation(SAMPLE_EVENTS, "timing_jitter", "run-001", 42, None)
    assert isinstance(result, list)


def test_apply_mutation_technique_noise():
    result = _apply_mutation(SAMPLE_EVENTS, "technique_noise", "run-001", 42, None)
    assert isinstance(result, list)


def test_apply_mutation_combined():
    result = _apply_mutation(SAMPLE_EVENTS, "combined", "run-001", 42, None)
    assert isinstance(result, list)
    assert len(result) > 0


def test_apply_mutation_unknown_strategy_returns_original():
    result = _apply_mutation(SAMPLE_EVENTS, "nonexistent_strategy", "run-001", 42, None)
    assert result == SAMPLE_EVENTS


def test_apply_mutation_preserves_safety():
    for strategy in ["label_ambiguity", "field_drop", "timing_jitter", "technique_noise"]:
        result = _apply_mutation(SAMPLE_EVENTS, strategy, "run-001", 42, None)
        assert _safety_intact(result), f"Safety broken by {strategy}"


# ── Adaptation strategies list ─────────────────────────────────────────────────

def test_adaptation_strategies_nonempty():
    assert len(ADAPTATION_STRATEGIES) > 0


def test_adaptation_strategies_are_strings():
    assert all(isinstance(s, str) for s in ADAPTATION_STRATEGIES)


def test_adaptation_strategies_has_combined():
    assert "combined" in ADAPTATION_STRATEGIES


# ── Full adaptation run ────────────────────────────────────────────────────────

def test_run_adaptation_returns_report():
    report = run_adaptation(
        artifact_path=str(DEMO_ARTIFACT),
        rules_dirs=[str(SIGMA_RULES_DIR)],
        max_iterations=3,
        verbose=False,
        seed=42,
    )
    assert isinstance(report, AdaptationReport)


def test_run_adaptation_report_has_required_fields():
    report = run_adaptation(
        artifact_path=str(DEMO_ARTIFACT),
        rules_dirs=[str(SIGMA_RULES_DIR)],
        max_iterations=2,
        verbose=False,
        seed=42,
    )
    assert hasattr(report, "campaign_id")
    assert hasattr(report, "evasion_achieved")
    assert hasattr(report, "iterations_run")
    assert hasattr(report, "surviving_rules")
    assert hasattr(report, "evaded_rules")
    assert hasattr(report, "adaptation_path")
    assert hasattr(report, "iterations")


def test_run_adaptation_iterations_bounded():
    max_iter = 3
    report = run_adaptation(
        artifact_path=str(DEMO_ARTIFACT),
        rules_dirs=[str(SIGMA_RULES_DIR)],
        max_iterations=max_iter,
        verbose=False,
        seed=42,
    )
    assert report.iterations_run <= max_iter


def test_run_adaptation_adaptation_path_length():
    max_iter = 3
    report = run_adaptation(
        artifact_path=str(DEMO_ARTIFACT),
        rules_dirs=[str(SIGMA_RULES_DIR)],
        max_iterations=max_iter,
        verbose=False,
        seed=42,
    )
    assert len(report.adaptation_path) == report.iterations_run


def test_run_adaptation_evasion_rate_valid():
    report = run_adaptation(
        artifact_path=str(DEMO_ARTIFACT),
        rules_dirs=[str(SIGMA_RULES_DIR)],
        max_iterations=3,
        verbose=False,
        seed=42,
    )
    for it in report.iterations:
        assert 0.0 <= it.evasion_rate <= 1.0


def test_run_adaptation_safety_intact_all_iterations():
    report = run_adaptation(
        artifact_path=str(DEMO_ARTIFACT),
        rules_dirs=[str(SIGMA_RULES_DIR)],
        max_iterations=3,
        verbose=False,
        seed=42,
    )
    assert all(it.safety_intact for it in report.iterations)


def test_run_adaptation_no_rules_dir():
    report = run_adaptation(
        artifact_path=str(DEMO_ARTIFACT),
        rules_dirs=["/nonexistent/path"],
        max_iterations=3,
        verbose=False,
        seed=42,
    )
    assert report.total_rules_evaluated == 0
    assert report.evasion_achieved is False


def test_run_adaptation_both_rule_dirs():
    report = run_adaptation(
        artifact_path=str(DEMO_ARTIFACT),
        rules_dirs=[str(SIGMA_RULES_DIR), str(GENERATED_DIR)],
        max_iterations=3,
        verbose=False,
        seed=42,
    )
    assert report.total_rules_evaluated >= len(_collect_rules([str(SIGMA_RULES_DIR)]))


def test_run_adaptation_to_dict():
    report = run_adaptation(
        artifact_path=str(DEMO_ARTIFACT),
        rules_dirs=[str(SIGMA_RULES_DIR)],
        max_iterations=2,
        verbose=False,
        seed=42,
    )
    d = report.to_dict()
    assert "campaign_id" in d
    assert "iterations" in d
    assert "evasion_achieved" in d
    assert isinstance(d["iterations"], list)


def test_run_adaptation_to_markdown():
    report = run_adaptation(
        artifact_path=str(DEMO_ARTIFACT),
        rules_dirs=[str(SIGMA_RULES_DIR)],
        max_iterations=2,
        verbose=False,
        seed=42,
    )
    md = report.to_markdown()
    assert "SHENRON Adversary Adaptation Report" in md
    assert "Adaptation Path" in md
    assert "Per-Iteration Results" in md


def test_run_adaptation_surviving_and_evaded_consistent():
    report = run_adaptation(
        artifact_path=str(DEMO_ARTIFACT),
        rules_dirs=[str(SIGMA_RULES_DIR)],
        max_iterations=3,
        verbose=False,
        seed=42,
    )
    total = len(report.surviving_rules) + len(report.evaded_rules)
    assert total <= report.rules_firing_on_original


def test_run_adaptation_full_evasion_with_enough_iterations():
    report = run_adaptation(
        artifact_path=str(DEMO_ARTIFACT),
        rules_dirs=[str(SIGMA_RULES_DIR), str(GENERATED_DIR)],
        max_iterations=12,
        verbose=False,
        seed=42,
    )
    if report.evasion_achieved:
        assert report.iterations_to_evasion is not None
        assert report.iterations_to_evasion <= 12
        assert len(report.surviving_rules) == 0
