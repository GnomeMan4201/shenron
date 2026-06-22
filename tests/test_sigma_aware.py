#!/usr/bin/env python3
"""Tests for core/mutation/sigma_aware.py"""
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.mutation.sigma_aware import SigmaTargetExtractor, SigmaAwareMutator

SIGMA_RULE_FIXTURE = """
title: Test Rule
id: test-1
logsource:
    product: windows
detection:
    selection:
        Image: powershell.exe
        CommandLine: '*-enc*'
    condition: selection
"""


@pytest.fixture
def rules_dir(tmp_path):
    p = tmp_path / "rules"
    p.mkdir()
    (p / "test.yml").write_text(SIGMA_RULE_FIXTURE)
    return str(p)


@pytest.fixture
def base_artifact():
    return {
        "artifact_id": "12345",
        "session_id": "sess-1",
        "layer": "lotl_execution_phantom",
        "behavior_class": "execution_sim",
        "detection_opportunities": ["cmdline_sim"],
        "mitre_techniques": ["T1059"],
        "simulation_only": True,
        "safety": {"simulation_only": True},
        "command_sim": "powershell.exe -enc abc",
        "target_process_sim": "powershell.exe",
    }


def test_target_extractor_loads_rules(rules_dir):
    ext = SigmaTargetExtractor()
    rules = ext.load_rules(rules_dir)
    assert len(rules) == 1
    assert rules[0]["title"] == "Test Rule"


def test_mutator_produces_5_variants(rules_dir, base_artifact):
    mutator = SigmaAwareMutator(rules_dir)
    variants = mutator.mutate_all_strategies(base_artifact)
    assert len(variants) == 6


def test_variants_have_mutation_meta(rules_dir, base_artifact):
    mutator = SigmaAwareMutator(rules_dir)
    variants = mutator.mutate_all_strategies(base_artifact)
    for v in variants:
        assert "_mutation_meta" in v
        meta = v["_mutation_meta"]
        assert "strategy" in meta
        assert "field_targeted" in meta
        assert "original_value" in meta
        assert "mutated_value" in meta


def test_protected_fields_not_omitted(rules_dir, base_artifact):
    mutator = SigmaAwareMutator(rules_dir)
    variant = mutator.mutate_targeted(base_artifact, "field_omit")
    assert "simulation_only" in variant
    assert "artifact_id" in variant
    assert "safety" in variant
    assert variant["_mutation_meta"]["strategy"] == "field_omit"


def test_unicode_substitution(rules_dir, base_artifact):
    mutator = SigmaAwareMutator(rules_dir)
    variant = mutator.mutate_targeted(base_artifact, "unicode_substitute")
    target = variant["_mutation_meta"]["field_targeted"]
    assert base_artifact[target] != variant[target]
