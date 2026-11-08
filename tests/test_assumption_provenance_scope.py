"""Provenance scope tests: independent records must not jointly satisfy an opt-in claim."""
import pytest
from core.assumptions.model import Claim, ClaimType, ClaimStatus
from core.assumptions.validator import _check_claim
from core.assumptions.loader import load_assumption


def test_disjoint_artifacts_do_not_satisfy_same_artifact_claim():
    claim = Claim(id="linked", type=ClaimType.POSITIVE_EVIDENCE,
                  requires_techniques=["T1059"],
                  requires_signals=["interpreter_inline_exec_sim"],
                  evidence_scope="same_artifact")
    records = [
        {"artifact_id": "one", "mitre_techniques": ["T1059"], "behavior_class": "other"},
        {"artifact_id": "two", "mitre_techniques": ["T1027"],
         "behavior_class": "interpreter_inline_exec_sim"},
    ]
    result = _check_claim(claim, records)
    assert result.status == ClaimStatus.PARTIALLY_SUPPORTED
    assert len(result.unsupported) == 1


def test_same_artifact_can_support_claim():
    claim = Claim(id="linked", requires_techniques=["T1059"],
                  requires_signals=["interpreter_inline_exec_sim"],
                  evidence_scope="same_artifact")
    records = [{"artifact_id": "one", "mitre_techniques": ["T1059"],
                "behavior_class": "interpreter_inline_exec_sim"}]
    assert _check_claim(claim, records).status == ClaimStatus.SUPPORTED


def test_legacy_category_aggregation_is_explicitly_distinct():
    claim = Claim(id="legacy", requires_techniques=["T1059"],
                  requires_signals=["interpreter_inline_exec_sim"])
    records = [
        {"mitre_techniques": ["T1059"]},
        {"behavior_class": "interpreter_inline_exec_sim"},
    ]
    assert _check_claim(claim, records).status == ClaimStatus.SUPPORTED


def test_out_of_scope_scans_all_records_even_with_scope_setting():
    claim = Claim(id="no_exfil", type=ClaimType.OUT_OF_SCOPE,
                  requires_techniques=["T1041"], evidence_scope="same_artifact")
    records = [{"mitre_techniques": ["T1041"]}, {"mitre_techniques": ["T1059"]}]
    assert _check_claim(claim, records).status == ClaimStatus.OUT_OF_SCOPE


def test_invalid_scope_is_rejected(tmp_path):
    p = tmp_path / "invalid.yaml"
    p.write_text('id: invalid\nschema_version: "1.0"\nclaims:\n  - id: bad\n    evidence_scope: arbitrary\n')
    with pytest.raises(ValueError, match="Invalid evidence_scope"):
        load_assumption(p)
