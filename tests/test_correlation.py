#!/usr/bin/env python3
"""Tests for core/campaign/correlation.py"""
import sys
import os
import pytest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.campaign.builder import CampaignBuilder
from core.campaign.correlation import (
    CampaignMutator,
    CampaignMutationStrategy,
    CorrelationBrittlenessScorer,
    CorrelationBrittlenessReport,
)


@pytest.fixture
def short_campaign():
    builder = CampaignBuilder.from_scenario("ransomware-precursor", 5)
    return builder.build()


def test_mutator_preserves_simulation_only(short_campaign):
    mutator = CampaignMutator()
    for strategy in CampaignMutationStrategy:
        mutated = mutator.mutate(short_campaign, strategy, seed=42)
        for event in mutated.events:
            assert event.artifact.get("simulation_only") is True
            for art in getattr(event, "artifacts", []):
                assert art.get("simulation_only") is True


def test_session_id_rotation_changes_subset(short_campaign):
    mutator = CampaignMutator()
    mutated = mutator.mutate(short_campaign, CampaignMutationStrategy.SESSION_ID_ROTATION, seed=42)
    mut_sids = {e.session_id for e in mutated.events}
    assert len(mut_sids) > 1


def test_session_id_rotation_does_not_change_all(short_campaign):
    mutator = CampaignMutator()
    mutated = mutator.mutate(short_campaign, CampaignMutationStrategy.SESSION_ID_ROTATION, seed=42)
    orig_sid = short_campaign.events[0].session_id
    assert any(e.session_id == orig_sid for e in mutated.events)


def test_timestamp_stretch_increases_gap(short_campaign):
    def max_gap_seconds(camp):
        mx = 0
        for i in range(1, len(camp.events)):
            t1 = datetime.fromisoformat(camp.events[i - 1].timestamp)
            t2 = datetime.fromisoformat(camp.events[i].timestamp)
            g = (t2 - t1).total_seconds()
            if g > mx:
                mx = g
        return mx
    mutator = CampaignMutator()
    mutated = mutator.mutate(short_campaign, CampaignMutationStrategy.TIMESTAMP_STRETCH, seed=42)
    assert max_gap_seconds(mutated) > max_gap_seconds(short_campaign)


def test_stage_dropout_sets_unknown(short_campaign):
    mutator = CampaignMutator()
    mutated = mutator.mutate(short_campaign, CampaignMutationStrategy.STAGE_DROPOUT, seed=42)
    stages = {e.stage for e in mutated.events}
    assert "UNKNOWN" in stages


def test_actor_drift_changes_after_midpoint(short_campaign):
    mutator = CampaignMutator()
    mutated = mutator.mutate(short_campaign, CampaignMutationStrategy.ACTOR_DRIFT, seed=42)
    orig_actor = short_campaign.events[0].actor_id
    mid = len(short_campaign.events) // 2
    for i in range(mid):
        assert mutated.events[i].actor_id == orig_actor
    for i in range(mid, len(mutated.events)):
        assert mutated.events[i].actor_id != orig_actor


def test_score_detects_broken_session_id(short_campaign):
    mutator = CampaignMutator()
    mutated = mutator.mutate(short_campaign, CampaignMutationStrategy.SESSION_ID_ROTATION, seed=42)
    scorer = CorrelationBrittlenessScorer()
    score = scorer._score_correlation(short_campaign, mutated)
    assert not score.session_id_intact


def test_score_detects_temporal_incoherence(short_campaign):
    mutator = CampaignMutator()
    mutated = mutator.mutate(short_campaign, CampaignMutationStrategy.TIMESTAMP_STRETCH, seed=42)
    scorer = CorrelationBrittlenessScorer()
    score = scorer._score_correlation(short_campaign, mutated)
    assert not score.temporal_coherent


def test_score_detects_stage_dropout(short_campaign):
    mutator = CampaignMutator()
    mutated = mutator.mutate(short_campaign, CampaignMutationStrategy.STAGE_DROPOUT, seed=42)
    scorer = CorrelationBrittlenessScorer()
    score = scorer._score_correlation(short_campaign, mutated)
    assert not score.stage_coverage_intact


def test_score_detects_actor_drift(short_campaign):
    mutator = CampaignMutator()
    mutated = mutator.mutate(short_campaign, CampaignMutationStrategy.ACTOR_DRIFT, seed=42)
    scorer = CorrelationBrittlenessScorer()
    score = scorer._score_correlation(short_campaign, mutated)
    assert not score.actor_consistent


def test_report_dict_has_expected_keys(short_campaign):
    scorer = CorrelationBrittlenessScorer(artifact_brittleness=0.5)
    report = scorer.score_campaign(short_campaign)
    d = report.report_to_dict()
    assert "overall_correlation_brittleness" in d
    assert "gap_vs_artifact_brittleness" in d
    assert "per_strategy" in d
    assert "most_fragile_strategy" in d


def test_report_markdown_contains_strategies(short_campaign):
    scorer = CorrelationBrittlenessScorer(artifact_brittleness=0.5)
    report = scorer.score_campaign(short_campaign)
    md = report.report_to_markdown()
    assert "SESSION_ID_ROTATION" in md
    assert "TIMESTAMP_STRETCH" in md
    assert "STAGE_DROPOUT" in md
    assert "ACTOR_DRIFT" in md


def test_gap_computed_correctly(short_campaign):
    scorer = CorrelationBrittlenessScorer(artifact_brittleness=0.8)
    report = scorer.score_campaign(short_campaign)
    expected = report.overall_correlation_brittleness - 0.8
    assert abs(report.gap_vs_artifact_brittleness - expected) < 0.001


def test_score_campaign_returns_all_strategies(short_campaign):
    scorer = CorrelationBrittlenessScorer()
    report = scorer.score_campaign(short_campaign)
    assert len(report.per_strategy) == len(list(CampaignMutationStrategy))
    strategies = {ps.strategy for ps in report.per_strategy}
    for s in CampaignMutationStrategy:
        assert s.value in strategies
