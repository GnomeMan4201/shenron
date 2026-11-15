#!/usr/bin/env python3
"""Regression tests for review findings on PR #71 (brittleness measurement).

1. A scenario with no baseline detections must complete and report n/a,
   not crash in the correlation scorer.
2. Mutation seeds must not depend on the random IDs the campaign builder
   assigns, so two fresh campaigns of one scenario mutate identically.
3. A strategy that evaded nothing must never be reported as "most
   effective".
"""
import argparse
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.brittleness.scorer import BrittlenessScorer
from core.campaign.builder import CampaignBuilder, SCENARIOS
from core.campaign.comparator import ComparisonReport, ScenarioComparator
from core.campaign.correlation import CorrelationBrittlenessScorer

SCENARIO = sorted(SCENARIOS)[0]

NEVER_MATCHES = """\
title: Never matches
id: test-never-matches
status: test
logsource:
    product: shenron
    category: simulation
detection:
    selection:
        layer: no_such_layer_value_anywhere
    condition: selection
level: low
"""


@pytest.fixture
def silent_rules_dir(tmp_path):
    (tmp_path / "never.yml").write_text(NEVER_MATCHES)
    return str(tmp_path)


def test_no_baseline_detection_scenario_reports_na(silent_rules_dir):
    result = ScenarioComparator(silent_rules_dir)._evaluate_scenario(SCENARIO)
    assert result.overall_brittleness is None
    assert result.triggered_count == 0


def test_correlation_scorer_accepts_unscored_artifact_brittleness():
    campaign = CampaignBuilder(SCENARIO).build()
    report = CorrelationBrittlenessScorer(artifact_brittleness=None).score_campaign(campaign)
    assert report.gap_vs_artifact_brittleness is None


def _seed_inputs_for_fresh_campaign(scorer, monkeypatch):
    """Record what each stage's mutation seed is derived from.

    The builder randomizes how many artifacts a stage emits, so the number
    of mutate calls varies between fresh campaigns; the per-stage seed must
    not.
    """
    import core.brittleness.scorer as scorer_module

    inputs = []
    original = scorer_module.stable_seed

    def record(*parts):
        inputs.append(parts)
        return original(*parts)

    monkeypatch.setattr(scorer_module, "stable_seed", record)
    scorer.score_campaign(CampaignBuilder(SCENARIO).build())
    monkeypatch.setattr(scorer_module, "stable_seed", original)
    return inputs


def test_mutation_seeds_identical_across_fresh_campaigns(monkeypatch):
    scorer = BrittlenessScorer("sigma/rules")
    first = _seed_inputs_for_fresh_campaign(scorer, monkeypatch)
    second = _seed_inputs_for_fresh_campaign(scorer, monkeypatch)
    assert first and first == second
    assert all(not any(len(p) == 36 and p.count("-") == 4 for p in parts) for parts in first), \
        "seed derived from a UUID"


def _run_cli_with(report, monkeypatch, tmp_path, capsys):
    from core.cli.commands import compare_scenarios

    monkeypatch.setattr(ScenarioComparator, "run_all", lambda self, persist=None: report)
    compare_scenarios.handle(argparse.Namespace(scenarios=None, out=str(tmp_path)))
    return capsys.readouterr().out


def test_cli_does_not_call_zero_rate_strategy_most_effective(monkeypatch, tmp_path, capsys):
    report = ComparisonReport(generated_at="t", rules_evaluated=1, scenarios=[])
    report.strategy_effectiveness = {"value_swap": 0.0, "field_omit": 0.0}
    out = _run_cli_with(report, monkeypatch, tmp_path, capsys)
    assert "Most effective" not in out
    assert "No strategy evaded" in out


def test_cli_still_names_a_real_winner(monkeypatch, tmp_path, capsys):
    report = ComparisonReport(generated_at="t", rules_evaluated=1, scenarios=[])
    report.strategy_effectiveness = {"value_swap": 0.5, "field_omit": 0.0}
    out = _run_cli_with(report, monkeypatch, tmp_path, capsys)
    assert "Most effective evasion: value_swap" in out
