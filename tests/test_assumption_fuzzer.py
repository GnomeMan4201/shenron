"""
tests/test_assumption_fuzzer.py

Tests for core/assumptions/fuzzer.py — SHENRON Assumption Fuzzer.
"""
import json
import os
import tempfile
from pathlib import Path
import pytest
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.assumptions.fuzzer import (
    fuzz_assumption,
    _load_assumption_yaml,
    _write_temp_assumption,
    _mutate_claim_drop,
    _mutate_technique_swap,
    _mutate_technique_add,
    _mutate_signal_corrupt,
    _mutate_signal_add,
    _mutate_oos_inject,
    _run_mutated,
    _verdict_changed,
    FuzzReport,
    ClaimFuzzResult,
    _TECHNIQUE_SWAPS,
    _NOISE_TECHNIQUES,
    _NOISE_SIGNALS,
)

DEMO_ARTIFACT    = Path(__file__).parent.parent / "artifacts" / "demo" / "shenron_demo_run.jsonl"
C2_ASSUMPTION    = Path(__file__).parent.parent / "assumptions" / "examples" / "c2_coverage.yaml"
KILLCHAIN_ASSUMPTION = Path(__file__).parent.parent / "assumptions" / "examples" / "full_kill_chain_coverage.yaml"

MINIMAL_ASSUMPTION = {
    "id": "test_assumption",
    "schema_version": "1.0",
    "description": "Test assumption",
    "claims": [
        {
            "id": "claim_a",
            "type": "positive_evidence",
            "severity": "high",
            "description": "Test claim A",
            "requires_techniques": ["T1071"],
            "requires_signals": [],
        },
        {
            "id": "claim_b",
            "type": "positive_evidence",
            "severity": "medium",
            "description": "Test claim B",
            "requires_techniques": ["T1053"],
            "requires_signals": [],
        },
    ],
}


# -- YAML I/O ------------------------------------------------------------------

def test_load_assumption_yaml_returns_dict():
    data = _load_assumption_yaml(str(C2_ASSUMPTION))
    assert isinstance(data, dict)

def test_load_assumption_yaml_has_id():
    data = _load_assumption_yaml(str(C2_ASSUMPTION))
    assert "id" in data

def test_load_assumption_yaml_has_claims():
    data = _load_assumption_yaml(str(C2_ASSUMPTION))
    assert "claims" in data
    assert isinstance(data["claims"], list)

def test_write_temp_assumption_creates_file():
    path = _write_temp_assumption(MINIMAL_ASSUMPTION)
    try:
        assert os.path.exists(path)
    finally:
        os.unlink(path)

def test_write_temp_assumption_valid_yaml():
    import yaml
    path = _write_temp_assumption(MINIMAL_ASSUMPTION)
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        assert data["id"] == "test_assumption"
    finally:
        os.unlink(path)

def test_write_temp_assumption_roundtrip():
    import yaml
    path = _write_temp_assumption(MINIMAL_ASSUMPTION)
    try:
        with open(path) as f:
            loaded = yaml.safe_load(f)
        assert len(loaded["claims"]) == len(MINIMAL_ASSUMPTION["claims"])
    finally:
        os.unlink(path)


# -- Mutation strategies -------------------------------------------------------

def test_mutate_claim_drop_removes_claim():
    mutated, note = _mutate_claim_drop(MINIMAL_ASSUMPTION, 0)
    assert len(mutated["claims"]) == len(MINIMAL_ASSUMPTION["claims"]) - 1

def test_mutate_claim_drop_correct_claim():
    mutated, note = _mutate_claim_drop(MINIMAL_ASSUMPTION, 0)
    remaining_ids = [c["id"] for c in mutated["claims"]]
    assert "claim_a" not in remaining_ids
    assert "claim_b" in remaining_ids

def test_mutate_claim_drop_out_of_bounds():
    mutated, note = _mutate_claim_drop(MINIMAL_ASSUMPTION, 99)
    assert note == "no-op"

def test_mutate_claim_drop_preserves_original():
    original_len = len(MINIMAL_ASSUMPTION["claims"])
    _mutate_claim_drop(MINIMAL_ASSUMPTION, 0)
    assert len(MINIMAL_ASSUMPTION["claims"]) == original_len

def test_mutate_technique_swap_changes_techniques():
    mutated, note = _mutate_technique_swap(MINIMAL_ASSUMPTION, 0)
    original_techs = MINIMAL_ASSUMPTION["claims"][0]["requires_techniques"]
    mutated_techs = mutated["claims"][0]["requires_techniques"]
    assert mutated_techs != original_techs or note.startswith("no-op")

def test_mutate_technique_swap_no_techniques():
    assumption = {"claims": [{"id": "c", "requires_techniques": [], "requires_signals": []}]}
    mutated, note = _mutate_technique_swap(assumption, 0)
    assert "no-op" in note

def test_mutate_technique_add_adds_technique():
    mutated, note = _mutate_technique_add(MINIMAL_ASSUMPTION, 0, 0)
    original_count = len(MINIMAL_ASSUMPTION["claims"][0]["requires_techniques"])
    mutated_count = len(mutated["claims"][0]["requires_techniques"])
    assert mutated_count > original_count

def test_mutate_technique_add_uses_noise():
    mutated, note = _mutate_technique_add(MINIMAL_ASSUMPTION, 0, 0)
    noise = _NOISE_TECHNIQUES[0]
    assert noise in mutated["claims"][0]["requires_techniques"]

def test_mutate_signal_corrupt_corrupts():
    assumption = {
        "claims": [{
            "id": "c",
            "requires_techniques": [],
            "requires_signals": ["some_signal"],
        }]
    }
    mutated, note = _mutate_signal_corrupt(assumption, 0)
    assert "CORRUPTED" in mutated["claims"][0]["requires_signals"][0]

def test_mutate_signal_corrupt_no_signals():
    mutated, note = _mutate_signal_corrupt(MINIMAL_ASSUMPTION, 0)
    assert "no-op" in note

def test_mutate_signal_add_adds_phantom():
    mutated, note = _mutate_signal_add(MINIMAL_ASSUMPTION, 0, 0)
    signals = mutated["claims"][0].get("requires_signals", [])
    assert any("nonexistent" in s or "phantom" in s or "ghost" in s or "synthetic" in s
               for s in signals)

def test_mutate_oos_inject_adds_claim():
    mutated, note = _mutate_oos_inject(MINIMAL_ASSUMPTION, 0)
    assert len(mutated["claims"]) > len(MINIMAL_ASSUMPTION["claims"])

def test_mutate_oos_inject_is_oos_type():
    mutated, note = _mutate_oos_inject(MINIMAL_ASSUMPTION, 0)
    oos_claims = [c for c in mutated["claims"] if c.get("type") == "out_of_scope_claim"]
    assert len(oos_claims) > 0

def test_mutate_oos_inject_preserves_original_claims():
    mutated, note = _mutate_oos_inject(MINIMAL_ASSUMPTION, 0)
    original_ids = {c["id"] for c in MINIMAL_ASSUMPTION["claims"]}
    mutated_ids = {c["id"] for c in mutated["claims"]}
    assert original_ids.issubset(mutated_ids)


# -- Verdict change detection --------------------------------------------------

def test_verdict_changed_same():
    assert _verdict_changed("SUPPORTED", "SUPPORTED") is False

def test_verdict_changed_different():
    assert _verdict_changed("SUPPORTED", "PARTIALLY_SUPPORTED") is True

def test_verdict_changed_error():
    assert _verdict_changed("SUPPORTED", "ERROR: something") is False

def test_verdict_changed_oos():
    assert _verdict_changed("SUPPORTED", "OUT_OF_SCOPE_VIOLATION") is True


# -- Run mutated ---------------------------------------------------------------

def test_run_mutated_returns_string():
    result = _run_mutated(MINIMAL_ASSUMPTION, str(DEMO_ARTIFACT))
    assert isinstance(result, str)

def test_run_mutated_valid_status():
    result = _run_mutated(MINIMAL_ASSUMPTION, str(DEMO_ARTIFACT))
    valid = {"SUPPORTED", "PARTIALLY_SUPPORTED", "UNSUPPORTED", "OUT_OF_SCOPE_VIOLATION"}
    assert result in valid or result.startswith("ERROR")

def test_run_mutated_cleans_up_tempfile():
    import glob
    before = set(glob.glob("/tmp/*.yaml"))
    _run_mutated(MINIMAL_ASSUMPTION, str(DEMO_ARTIFACT))
    after = set(glob.glob("/tmp/*.yaml"))
    assert after == before


# -- Full fuzz run -------------------------------------------------------------

def test_fuzz_assumption_returns_report():
    report = fuzz_assumption(
        assumption_path=str(C2_ASSUMPTION),
        artifact_path=str(DEMO_ARTIFACT),
        verbose=False,
    )
    assert isinstance(report, FuzzReport)

def test_fuzz_assumption_has_required_fields():
    report = fuzz_assumption(
        assumption_path=str(C2_ASSUMPTION),
        artifact_path=str(DEMO_ARTIFACT),
        verbose=False,
    )
    assert hasattr(report, "assumption_id")
    assert hasattr(report, "original_status")
    assert hasattr(report, "claim_sensitivity")
    assert hasattr(report, "load_bearing_claims")
    assert hasattr(report, "redundant_claims")
    assert hasattr(report, "results")

def test_fuzz_assumption_claim_sensitivity_keys():
    report = fuzz_assumption(
        assumption_path=str(C2_ASSUMPTION),
        artifact_path=str(DEMO_ARTIFACT),
        verbose=False,
    )
    data = _load_assumption_yaml(str(C2_ASSUMPTION))
    positive_claim_ids = {
        c["id"] for c in data["claims"]
        if c.get("type") != "out_of_scope_claim"
    }
    for cid in positive_claim_ids:
        assert cid in report.claim_sensitivity

def test_fuzz_assumption_sensitivity_range():
    report = fuzz_assumption(
        assumption_path=str(C2_ASSUMPTION),
        artifact_path=str(DEMO_ARTIFACT),
        verbose=False,
    )
    for score in report.claim_sensitivity.values():
        assert 0.0 <= score <= 1.0

def test_fuzz_assumption_load_bearing_subset_of_claims():
    report = fuzz_assumption(
        assumption_path=str(C2_ASSUMPTION),
        artifact_path=str(DEMO_ARTIFACT),
        verbose=False,
    )
    all_claims = set(report.claim_sensitivity.keys())
    assert set(report.load_bearing_claims).issubset(all_claims)

def test_fuzz_assumption_redundant_subset_of_claims():
    report = fuzz_assumption(
        assumption_path=str(C2_ASSUMPTION),
        artifact_path=str(DEMO_ARTIFACT),
        verbose=False,
    )
    all_claims = set(report.claim_sensitivity.keys())
    assert set(report.redundant_claims).issubset(all_claims)

def test_fuzz_assumption_total_mutations_positive():
    report = fuzz_assumption(
        assumption_path=str(C2_ASSUMPTION),
        artifact_path=str(DEMO_ARTIFACT),
        verbose=False,
    )
    assert report.total_mutations > 0

def test_fuzz_assumption_killchain():
    report = fuzz_assumption(
        assumption_path=str(KILLCHAIN_ASSUMPTION),
        artifact_path=str(DEMO_ARTIFACT),
        verbose=False,
    )
    assert isinstance(report, FuzzReport)
    assert report.most_sensitive_claim == "persistence_present"

def test_fuzz_assumption_to_dict():
    report = fuzz_assumption(
        assumption_path=str(C2_ASSUMPTION),
        artifact_path=str(DEMO_ARTIFACT),
        verbose=False,
    )
    d = report.to_dict()
    assert "assumption_id" in d
    assert "results" in d
    assert "claim_sensitivity" in d
    assert isinstance(d["results"], list)

def test_fuzz_assumption_to_markdown():
    report = fuzz_assumption(
        assumption_path=str(C2_ASSUMPTION),
        artifact_path=str(DEMO_ARTIFACT),
        verbose=False,
    )
    md = report.to_markdown()
    assert "SHENRON Assumption Fuzz Report" in md
    assert "Claim Sensitivity" in md
    assert "Load-Bearing Claims" in md

def test_fuzz_assumption_single_strategy():
    report = fuzz_assumption(
        assumption_path=str(C2_ASSUMPTION),
        artifact_path=str(DEMO_ARTIFACT),
        strategies=["claim_drop"],
        verbose=False,
    )
    strategies_used = {r.strategy for r in report.results}
    assert strategies_used == {"claim_drop"}
