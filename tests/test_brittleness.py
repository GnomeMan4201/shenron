#!/usr/bin/env python3
"""Tests for core/brittleness/scorer.py"""
import sys
import json
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.campaign.builder import CampaignBuilder
from core.brittleness.scorer import BrittlenessScorer, BrittlenessReport

SIGMA_RULE_FIXTURE = """
title: Test Exfil Rule
id: test-exfil-1
logsource:
    product: windows
detection:
    selection:
        layer: transient_exfil_shell
    condition: selection
"""


@pytest.fixture
def rules_dir(tmp_path):
    p = tmp_path / "rules"
    p.mkdir()
    (p / "exfil.yml").write_text(SIGMA_RULE_FIXTURE)
    return str(p)


def test_brittleness_scorer_initializes(rules_dir):
    scorer = BrittlenessScorer(rules_dir)
    assert len(scorer.rule_paths) == 1


def test_score_campaign_returns_report(rules_dir):
    builder = CampaignBuilder.from_scenario("insider-threat", 24)
    campaign = builder.build()
    scorer = BrittlenessScorer(rules_dir)
    report = scorer.score_campaign(campaign)
    assert isinstance(report, BrittlenessReport)
    assert report.artifact_count == len(campaign.events)
    assert 0.0 <= report.overall_brittleness_score <= 1.0
    assert isinstance(report.most_brittle_stage, str)
    assert isinstance(report.most_effective_strategy, str)


def test_report_to_dict_and_jsonl(rules_dir):
    builder = CampaignBuilder.from_scenario("ransomware-precursor", 24)
    campaign = builder.build()
    scorer = BrittlenessScorer(rules_dir)
    report = scorer.score_campaign(campaign)
    d = report.report_to_dict()
    assert "per_artifact" in d
    assert len(d["per_artifact"]) == len(campaign.events)
    jsonl = report.report_to_jsonl()
    lines = jsonl.strip().split("\n")
    assert len(lines) == len(campaign.events)
    for line in lines:
        assert "event_id" in json.loads(line)


def test_correlation_break_count(rules_dir):
    builder = CampaignBuilder.from_scenario("apt29-style", 24)
    campaign = builder.build()
    scorer = BrittlenessScorer(rules_dir)
    report = scorer.score_campaign(campaign)
    assert isinstance(report.correlation_break_count, int)
    assert report.correlation_break_count >= 0


def test_brittleness_scorer_resolves_correct_sigma_dir():
    import os
    sigma_dir = "sigma/rules"
    if not os.path.exists(sigma_dir):
        import pytest
        pytest.skip("sigma/rules directory not found")
    scorer = BrittlenessScorer(sigma_dir)
    assert len(scorer.rule_paths) > 3, f"Expected >3 rules, got {len(scorer.rule_paths)}"


def test_apt29_scenario_not_fully_evaded(tmp_path):
    import os
    sigma_dir = "sigma/rules"
    if not os.path.exists(sigma_dir):
        import pytest
        pytest.skip("sigma/rules directory not found")
    builder = CampaignBuilder.from_scenario("apt29-style", 24)
    campaign = builder.build()
    scorer = BrittlenessScorer(sigma_dir)
    report = scorer.score_campaign(campaign)
    assert report.overall_brittleness_score < 1.0, "Expected at least one stage to be caught"
    assert any(ab.original_triggered for ab in report.per_artifact), "Expected at least one original artifact to trigger"
