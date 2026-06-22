#!/usr/bin/env python3
"""Tests for core/campaign/comparator.py"""
import sys
import os
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.campaign.comparator import ScenarioComparator, ComparisonReport, ScenarioResult
from core.campaign.builder import SCENARIOS


@pytest.fixture
def rules_dir():
    rdir = "sigma/rules"
    if not os.path.exists(rdir):
        pytest.skip("sigma/rules directory not found")
    return rdir


def test_comparator_initializes(rules_dir):
    comp = ScenarioComparator(rules_dir)
    assert len(comp.scorer.rule_paths) > 0


def test_run_all_returns_report_with_all_scenarios(rules_dir):
    comp = ScenarioComparator(rules_dir)
    report = comp.run_all()
    assert isinstance(report, ComparisonReport)
    assert len(report.scenarios) == len(SCENARIOS)


def test_per_scenario_results_have_correct_field_types(rules_dir):
    comp = ScenarioComparator(rules_dir)
    report = comp.run_all()
    for res in report.scenarios:
        assert isinstance(res, ScenarioResult)
        assert isinstance(res.scenario_name, str)
        assert isinstance(res.overall_brittleness, float)
        assert isinstance(res.per_stage, dict)
        assert isinstance(res.most_brittle_stage, str)
        assert isinstance(res.triggered_count, int)
        assert isinstance(res.total_stages, int)


def test_universal_stages_are_subsets(rules_dir):
    comp = ScenarioComparator(rules_dir)
    report = comp.run_all()
    stage_sets = [set(r.per_stage.keys()) for r in report.scenarios]
    common_stages = set.intersection(*stage_sets) if stage_sets else set()
    for stage in report.universally_brittle_stages:
        assert stage in common_stages
    for stage in report.universally_detected_stages:
        assert stage in common_stages


def test_report_to_dict_has_expected_keys(rules_dir):
    comp = ScenarioComparator(rules_dir)
    report = comp.run_all()
    d = report.report_to_dict()
    assert "scenarios" in d
    assert "generated_at" in d
    assert "rules_evaluated" in d
    assert "universally_brittle_stages" in d
    assert "strategy_effectiveness" in d


def test_report_to_markdown_contains_headers_and_names(rules_dir):
    comp = ScenarioComparator(rules_dir)
    report = comp.run_all()
    md = report.report_to_markdown()
    assert "# Cross-Scenario Brittleness Comparison" in md
    assert "| Scenario | Brittleness |" in md
    for name in SCENARIOS.keys():
        assert name in md


def test_run_selected_with_one_scenario(rules_dir):
    comp = ScenarioComparator(rules_dir)
    report = comp.run_selected(["apt29-style"])
    assert len(report.scenarios) == 1
    assert report.scenarios[0].scenario_name == "apt29-style"


def test_run_selected_ignores_invalid_scenarios(rules_dir):
    comp = ScenarioComparator(rules_dir)
    report = comp.run_selected(["apt29-style", "nonexistent-scenario"])
    assert len(report.scenarios) == 1
