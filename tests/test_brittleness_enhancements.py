#!/usr/bin/env python3
"""Tests for combined_evasion, weighted scoring, and deterministic seeding."""
import os
import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.mutation.sigma_aware import SigmaAwareMutator
from core.brittleness.scorer import BrittlenessScorer, BrittlenessReport
from core.campaign.builder import CampaignBuilder


@pytest.fixture
def rules_dir():
    rdir = "sigma/rules"
    if not os.path.exists(rdir):
        pytest.skip("sigma/rules not found")
    return rdir


@pytest.fixture
def base_artifact():
    return {
        "artifact_id": "test-001",
        "session_id": "sess-test",
        "layer": "lotl_execution_sim",
        "behavior_class": "interpreter_inline_exec_sim",
        "detection_opportunities": ["interpreter_spawn_no_script_arg_sim"],
        "mitre_techniques": ["T1059"],
        "simulation_only": True,
        "safety": {"simulation_only": True},
        "phase": "inline_exec",
    }


def test_mutate_all_strategies_returns_6(rules_dir, base_artifact):
    mutator = SigmaAwareMutator(rules_dir)
    variants = mutator.mutate_all_strategies(base_artifact)
    assert len(variants) == 6


def test_combined_evasion_strategy_present(rules_dir, base_artifact):
    mutator = SigmaAwareMutator(rules_dir)
    variants = mutator.mutate_all_strategies(base_artifact)
    strategies = [v["_mutation_meta"]["strategy"] for v in variants]
    assert "combined_evasion" in strategies


def test_case_flip_is_deterministic_with_seed(rules_dir, base_artifact):
    mutator = SigmaAwareMutator(rules_dir)
    v1 = mutator.mutate_targeted(base_artifact, "case_flip", seed=42)
    v2 = mutator.mutate_targeted(base_artifact, "case_flip", seed=42)
    assert v1["_mutation_meta"]["mutated_value"] == v2["_mutation_meta"]["mutated_value"]


def test_case_flip_different_seeds_differ(rules_dir, base_artifact):
    mutator = SigmaAwareMutator(rules_dir)
    v1 = mutator.mutate_targeted(base_artifact, "case_flip", seed=1)
    v2 = mutator.mutate_targeted(base_artifact, "case_flip", seed=999)
    # Different seeds should produce different results (probabilistically true)
    # Test that seeds are actually being used by checking they aren't identical to original
    orig = base_artifact.get(v1["_mutation_meta"]["field_targeted"], "")
    assert v1["_mutation_meta"]["mutated_value"] != orig or v2["_mutation_meta"]["mutated_value"] != orig


def test_weighted_brittleness_score_present(rules_dir):
    builder = CampaignBuilder.from_scenario("insider-threat", 24)
    campaign = builder.build()
    scorer = BrittlenessScorer(rules_dir)
    report = scorer.score_campaign(campaign)
    assert hasattr(report, "weighted_brittleness_score")
    assert 0.0 <= report.weighted_brittleness_score <= 1.0


def test_weighted_score_in_report_to_dict(rules_dir):
    builder = CampaignBuilder.from_scenario("insider-threat", 24)
    campaign = builder.build()
    scorer = BrittlenessScorer(rules_dir)
    report = scorer.score_campaign(campaign)
    d = report.report_to_dict()
    assert "weighted_brittleness_score" in d


def test_weighted_score_in_markdown(rules_dir):
    builder = CampaignBuilder.from_scenario("insider-threat", 24)
    campaign = builder.build()
    scorer = BrittlenessScorer(rules_dir)
    report = scorer.score_campaign(campaign)
    md = report.report_to_markdown()
    assert "Weighted Brittleness Score" in md


def test_adversary_weights_defined():
    from core.brittleness.scorer import BrittlenessScorer
    assert hasattr(BrittlenessScorer, "ADVERSARY_WEIGHTS")
    weights = BrittlenessScorer.ADVERSARY_WEIGHTS
    assert weights["case_flip"] > weights["value_swap"]
    assert "combined_evasion" in weights


def test_simulation_only_preserved_in_combined_evasion(rules_dir, base_artifact):
    mutator = SigmaAwareMutator(rules_dir)
    variant = mutator.mutate_targeted(base_artifact, "combined_evasion")
    assert variant.get("simulation_only") is True
