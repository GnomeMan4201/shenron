"""Red-first regression for reviewer C1/C2: fail closed on invalid evidence."""
import json
from pathlib import Path

import pytest
import yaml

from core.assumptions.loader import load_assumption
from core.assumptions.model import AssumptionStatus, Claim, ClaimType, ClaimStatus
from core.assumptions import validator


IDENTITY = Path(__file__).resolve().parents[1] / "assumptions/examples/identity_spoofing_coverage.yaml"
GOOD = {
    "mitre_techniques": ["T1542", "T1078"],
    "detection_opportunities": [
        "bios_log_forge_sim", "bios_tamper_log_write_sim",
        "multi_identity_emit_sim", "trusted_name_rename_sim",
    ],
}


def _jsonl(tmp_path, *records):
    path = tmp_path / "evidence.jsonl"
    path.write_text("\n".join(records) + "\n", encoding="utf-8")
    return path


def test_valid_evidence_still_supported(tmp_path):
    result = validator.validate_assumption(IDENTITY, _jsonl(tmp_path, json.dumps(GOOD)))
    assert result.status == AssumptionStatus.SUPPORTED


def test_valid_prohibited_technique_still_detected(tmp_path):
    result = validator.validate_assumption(
        IDENTITY, _jsonl(tmp_path, json.dumps(GOOD), '{"mitre_techniques":["T1041"]}')
    )
    assert result.status == AssumptionStatus.OUT_OF_SCOPE_VIOLATION


@pytest.mark.parametrize("bad_record,diagnostic", [
    ('{"mitre_techniques":["T1041"],}', "line 2"),
    ('null', "line 2"),
    (json.dumps({"mitre_techniques": {"T1041": True}}), "mitre_techniques"),
    (json.dumps({"detection_opportunities": ["ok", 123]}), "detection_opportunities"),
    (json.dumps({"phase": None}), "phase"),
])
def test_invalid_evidence_is_not_ignored(tmp_path, bad_record, diagnostic):
    with pytest.raises(ValueError, match=diagnostic):
        validator.validate_assumption(
            IDENTITY, _jsonl(tmp_path, json.dumps(GOOD), bad_record)
        )


def test_blank_lines_are_allowed(tmp_path):
    result = validator.validate_assumption(
        IDENTITY, _jsonl(tmp_path, "", json.dumps(GOOD), "")
    )
    assert result.status == AssumptionStatus.SUPPORTED


def test_empty_positive_requirements_rejected(tmp_path):
    doc = yaml.safe_load(IDENTITY.read_text(encoding="utf-8"))
    doc["claims"].append({"id": "unresolved_required_claim", "type": "positive_evidence",
                          "requires_signals": [], "evidence_scope": "same_artifact"})
    assumption = tmp_path / "altered.yaml"
    assumption.write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(ValueError, match="unresolved_required_claim"):
        load_assumption(assumption)


def test_unresolved_claim_cannot_pass_aggregate_even_if_loader_bypassed(tmp_path, monkeypatch):
    supported = Claim(id="known", type=ClaimType.POSITIVE_EVIDENCE,
                      requires_techniques=["T1542"])
    unresolved = Claim(id="unresolved", type=ClaimType.POSITIVE_EVIDENCE)
    monkeypatch.setattr(validator, "load_assumption",
                        lambda _: ("test", "", [supported, unresolved]))
    result = validator.validate_assumption(
        IDENTITY, _jsonl(tmp_path, json.dumps(GOOD))
    )
    assert [r.status for r in result.claim_results] == [ClaimStatus.SUPPORTED, ClaimStatus.UNRESOLVED]
    assert result.status != AssumptionStatus.SUPPORTED
    assert "partially supports" in result.safe_conclusion


def test_empty_metric_requirements_rejected(tmp_path):
    assumption = tmp_path / "empty_metric.yaml"
    assumption.write_text('schema_version: "1.0"\nid: metric\nclaims:\n  - id: empty_metric\n    type: metric_threshold\n    requires_metrics: []\n', encoding="utf-8")
    with pytest.raises(ValueError, match="empty_metric"):
        load_assumption(assumption)
