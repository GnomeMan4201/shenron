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
        layer: transient_exfil_sim
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


def test_unicode_substitute_neutralized_by_evaluator():
    """Homoglyph map in evaluator should transliterate Cyrillic to Latin."""
    from core.sigma.evaluator import _normalize
    # 'а' is Cyrillic U+0430, 'е' is Cyrillic U+0435
    assert _normalize("lsаss.exe") == "lsass.exe"
    assert _normalize("pоwеrshеll") == "powershell"


def test_custom_scenario_composition():
    """Dynamic scenario composition via from_custom_sequence."""
    from core.campaign.builder import CampaignBuilder, CampaignStage
    custom_stages = [
        (CampaignStage.INITIAL_ACCESS, "passive_recon_harvester"),
        (CampaignStage.EXFIL, "transient_exfil_sim"),
    ]
    builder = CampaignBuilder.from_custom_sequence(custom_stages, 24)
    campaign = builder.build()
    assert len(campaign.events) == 2
    assert campaign.events[0].layer_name == "passive_recon_harvester"
    assert campaign.events[1].layer_name == "transient_exfil_sim"
    assert campaign.events[0].parent_event_id is None
    assert campaign.events[1].parent_event_id == campaign.events[0].event_id


def test_markdown_report_generation():
    """Brittleness report renders valid Markdown."""
    import os
    sigma_dir = "sigma/rules"
    if not os.path.exists(sigma_dir):
        import pytest
        pytest.skip("sigma/rules directory not found")
    builder = CampaignBuilder.from_scenario("insider-threat", 24)
    campaign = builder.build()
    scorer = BrittlenessScorer(sigma_dir)
    report = scorer.score_campaign(campaign)
    md = report.report_to_markdown()
    assert "# Brittleness Report" in md
    assert "Per-Stage Breakdown" in md
    assert "| Stage | Layer |" in md
    assert "Remediation Guidance" in md


def test_unicode_substitute_neutralized_by_evaluator():
    from core.sigma.evaluator import _normalize
    assert _normalize("lsаss.exe") == "lsass.exe"
    assert _normalize("pоwеrshеll") == "powershell"


def test_custom_scenario_composition():
    from core.campaign.builder import CampaignBuilder, CampaignStage
    custom_stages = [
        (CampaignStage.INITIAL_ACCESS, "passive_recon_harvester"),
        (CampaignStage.EXFIL, "transient_exfil_sim"),
    ]
    builder = CampaignBuilder.from_custom_sequence(custom_stages, 24)
    campaign = builder.build()
    assert len(campaign.events) == 2
    assert campaign.events[0].layer_name == "passive_recon_harvester"
    assert campaign.events[1].layer_name == "transient_exfil_sim"
    assert campaign.events[0].parent_event_id is None
    assert campaign.events[1].parent_event_id == campaign.events[0].event_id


def test_markdown_report_generation():
    import os
    sigma_dir = "sigma/rules"
    if not os.path.exists(sigma_dir):
        import pytest
        pytest.skip("sigma/rules directory not found")
    builder = CampaignBuilder.from_scenario("insider-threat", 24)
    campaign = builder.build()
    scorer = BrittlenessScorer(sigma_dir)
    report = scorer.score_campaign(campaign)
    md = report.report_to_markdown()
    assert "# Brittleness Report" in md
    assert "Per-Stage Breakdown" in md
    assert "| Stage | Layer |" in md
    assert "Remediation Guidance" in md
