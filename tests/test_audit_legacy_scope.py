"""Audit input contract: explicitly scope frozen legacy examples, never accept unknown invalid YAML."""
import json
from pathlib import Path

import pytest

from core.audit.bundle import run_audit_bundle


EVENTS = "artifacts/demo/shenron_demo_run.jsonl"
RULES = "sigma/rules"
EXAMPLES = "assumptions/examples"
LEGACY = {"c2_lateral_coverage.yaml", "assumption_dependency_confusion.yaml"}


def test_builtin_legacy_exclusions_are_recorded_not_validated(tmp_path):
    result = run_audit_bundle(EVENTS, RULES, EXAMPLES, str(tmp_path), verbose=False)
    assert result["ok"] is True
    exclusions = json.loads((tmp_path / "assumption_exclusions.json").read_text())
    assert {row["filename"] for row in exclusions} == LEGACY
    assert all(row["reason"] == "legacy_format_not_validated" for row in exclusions)
    assert all(row["git_blob_sha1"] for row in exclusions)
    validated = json.loads((tmp_path / "assumption_results.json").read_text())
    assert len(validated) == 17
    assert all(row["assumption_id"] not in LEGACY for row in validated)
    repro = json.loads((tmp_path / "reproducibility.json").read_text())
    assert repro["inputs"]["assumptions_count"] == 17
    assert repro["inputs"]["assumptions_excluded_count"] == 2
    assert repro["summary"]["assumptions_excluded"] == 2
    md = (tmp_path / "reproducibility.md").read_text()
    assert "legacy" in md.lower()
    for name in LEGACY:
        assert name in md


def test_unknown_malformed_claims_are_not_excluded_by_filename(tmp_path):
    assumptions = tmp_path / "custom_assumptions"
    assumptions.mkdir()
    (assumptions / "c2_lateral_coverage.yaml").write_text(
        'schema_version: "1.0"\nid: custom\nclaims:\n  - "not a claim object"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="claim 1 must be"):
        run_audit_bundle(EVENTS, RULES, str(assumptions),
                         str(tmp_path / "audit"), verbose=False)


def test_empty_canonical_assumption_blocks_audit(tmp_path):
    assumptions = tmp_path / "empty_assumptions"
    assumptions.mkdir()
    (assumptions / "unexpected.yaml").write_text(
        'schema_version: "1.0"\nid: unexpected\nclaims: []\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="no canonical claims"):
        run_audit_bundle(EVENTS, RULES, str(assumptions),
                         str(tmp_path / "audit"), verbose=False)
