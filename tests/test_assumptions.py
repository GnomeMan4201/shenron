#!/usr/bin/env python3
"""SHENRON assumption validation tests — evidence discipline."""
import sys, json, pytest, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.assumptions.model import (
    Claim, ClaimType, ClaimSeverity, ClaimStatus,
    AssumptionStatus, AssumptionResult,
)
from core.assumptions.loader import load_assumption
from core.assumptions.validator import validate_assumption, _check_claim


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _art(layer="dormant_sleeper_seed", techniques=None, signals=None, **kw):
    base = {
        "artifact_id":     "test-001",
        "layer":           layer,
        "phase":           "persistence_install",
        "behavior_class":  signals[0] if signals else "test_sim",
        "mitre_techniques":techniques or ["T1053"],
        "simulation_only": True,
        "executable":      False,
        "no_payload_present": True,
        "detection_opportunities": signals or [],
    }
    base.update(kw)
    return base


def _persistence_artifacts():
    return [
        _art(techniques=["T1053"], signals=["scheduled_task_creation"]),
        _art(techniques=["T1547"], signals=["autostart_registry_modification_sim"]),
        _art(techniques=["T1055"], signals=["process_injection_attempt_sim"]),
    ]


def _c2_artifacts():
    return [
        _art(layer="beacon_emitter_cloak",
             techniques=["T1071"],
             signals=["periodic_beacon_to_external_host", "http_beacon_sim"]),
        _art(layer="autonomous_signal_cloner",
             techniques=["T1102"],
             signals=["signal_clone_across_interfaces"]),
    ]


def _persistence_claim():
    return Claim(
        id="scheduled_task_evidence",
        type=ClaimType.POSITIVE_EVIDENCE,
        severity=ClaimSeverity.MEDIUM,
        requires_techniques=["T1053"],
        requires_signals=["scheduled_task_creation"],
    )


def _c2_oos_claim():
    return Claim(
        id="no_c2_overclaim",
        type=ClaimType.OUT_OF_SCOPE,
        severity=ClaimSeverity.HIGH,
        requires_techniques=["T1071"],
        requires_signals=["periodic_beacon_to_external_host"],
    )


# ── Model tests ───────────────────────────────────────────────────────────────

def test_assumption_result_to_dict_has_required_keys():
    r = AssumptionResult(assumption_id="test", assumption_file="f", artifact_file="a")
    d = r.to_dict()
    for key in ["assumption_id", "status", "supported_count", "unsupported_count",
                "safe_conclusion", "claims"]:
        assert key in d


# ── Claim check tests ─────────────────────────────────────────────────────────

def test_persistence_assumption_supported_by_persistence_artifact():
    claim = _persistence_claim()
    result = _check_claim(claim, _persistence_artifacts())
    assert result.status == ClaimStatus.SUPPORTED

def test_c2_assumption_not_supported_by_persistence_artifact():
    claim = Claim(
        id="beacon_evidence",
        type=ClaimType.POSITIVE_EVIDENCE,
        severity=ClaimSeverity.HIGH,
        requires_techniques=["T1071"],
        requires_signals=["periodic_beacon_to_external_host"],
    )
    result = _check_claim(claim, _persistence_artifacts())
    assert result.status == ClaimStatus.UNSUPPORTED

def test_empty_artifact_cannot_support_positive_claim():
    claim = _persistence_claim()
    result = _check_claim(claim, [])
    assert result.status == ClaimStatus.UNSUPPORTED
    assert result.matched_artifacts == 0

def test_out_of_scope_claim_not_triggered_when_absent():
    claim = _c2_oos_claim()
    result = _check_claim(claim, _persistence_artifacts())
    # C2 signals absent from persistence artifacts — correctly absent
    assert result.status == ClaimStatus.SUPPORTED

def test_out_of_scope_claim_triggered_when_present():
    claim = _c2_oos_claim()
    result = _check_claim(claim, _c2_artifacts())
    assert result.status == ClaimStatus.OUT_OF_SCOPE

def test_out_of_scope_claim_is_marked_high_risk():
    claim = _c2_oos_claim()
    assert claim.severity == ClaimSeverity.HIGH
    assert claim.type == ClaimType.OUT_OF_SCOPE

def test_unknown_technique_is_reported_as_unsupported():
    claim = Claim(
        id="unknown",
        type=ClaimType.POSITIVE_EVIDENCE,
        severity=ClaimSeverity.LOW,
        requires_techniques=["T9999"],
        requires_signals=["definitely_not_in_any_artifact"],
    )
    result = _check_claim(claim, _persistence_artifacts())
    assert result.status == ClaimStatus.UNSUPPORTED
    assert "T9999" in result.unsupported

def test_partial_match_produces_partially_supported():
    claim = Claim(
        id="partial_test",
        type=ClaimType.POSITIVE_EVIDENCE,
        severity=ClaimSeverity.MEDIUM,
        requires_techniques=["T1053"],                 # present
        requires_signals=["definitely_not_present"],   # absent
    )
    result = _check_claim(claim, _persistence_artifacts())
    assert result.status == ClaimStatus.PARTIALLY_SUPPORTED


# ── Full validation tests ─────────────────────────────────────────────────────

def test_persistence_assumption_file_loads(tmp_path):
    yaml = tmp_path / "test.yaml"
    yaml.write_text("""
id: test_assumption
description: Test

claims:
  - id: sched_task
    type: positive_evidence
    severity: medium
    requires_techniques:
      - T1053
""")
    assumption_id, description, claims = load_assumption(yaml)
    assert assumption_id == "test_assumption"
    assert len(claims) == 1
    assert claims[0].id == "sched_task"
    assert "T1053" in claims[0].requires_techniques

def test_validate_assumption_persistence_supported(tmp_path):
    yaml = tmp_path / "persist.yaml"
    yaml.write_text("""
id: persistence_test
description: Test

claims:
  - id: sched_task
    type: positive_evidence
    severity: medium
    requires_techniques:
      - T1053
    requires_signals:
      - scheduled_task_creation
""")
    jsonl = tmp_path / "artifacts.jsonl"
    arts = _persistence_artifacts()
    jsonl.write_text("\n".join(json.dumps(a) for a in arts))

    result = validate_assumption(yaml, jsonl)
    assert result.status == AssumptionStatus.SUPPORTED
    assert result.supported_count >= 1
    assert result.unsupported_count == 0

def test_validate_assumption_c2_unsupported_by_persistence(tmp_path):
    yaml = tmp_path / "c2.yaml"
    yaml.write_text("""
id: c2_test
description: Test

claims:
  - id: beacon
    type: positive_evidence
    severity: high
    requires_techniques:
      - T1071
    requires_signals:
      - periodic_beacon_to_external_host
""")
    jsonl = tmp_path / "artifacts.jsonl"
    jsonl.write_text("\n".join(json.dumps(a) for a in _persistence_artifacts()))

    result = validate_assumption(yaml, jsonl)
    assert result.status == AssumptionStatus.UNSUPPORTED
    assert result.supported_count == 0

def test_validate_assumption_oos_violation_detected(tmp_path):
    yaml = tmp_path / "oos.yaml"
    yaml.write_text("""
id: oos_test
description: Test

claims:
  - id: no_beacon
    type: out_of_scope_claim
    severity: high
    requires_techniques:
      - T1071
    requires_signals:
      - periodic_beacon_to_external_host
""")
    jsonl = tmp_path / "artifacts.jsonl"
    jsonl.write_text("\n".join(json.dumps(a) for a in _c2_artifacts()))

    result = validate_assumption(yaml, jsonl)
    assert result.status == AssumptionStatus.OUT_OF_SCOPE_VIOLATION
    assert "no_beacon" in result.out_of_scope_violations

def test_validate_assumption_safe_conclusion_present(tmp_path):
    yaml = tmp_path / "test.yaml"
    yaml.write_text("""
id: test
description: Test

claims:
  - id: t1
    type: positive_evidence
    severity: low
    requires_techniques:
      - T1053
""")
    jsonl = tmp_path / "artifacts.jsonl"
    jsonl.write_text("\n".join(json.dumps(a) for a in _persistence_artifacts()))

    result = validate_assumption(yaml, jsonl)
    assert result.safe_conclusion
    assert len(result.safe_conclusion) > 20

def test_assumption_report_includes_safe_conclusion(tmp_path):
    yaml = tmp_path / "test.yaml"
    yaml.write_text("""
id: test
description: Test

claims:
  - id: t1
    type: positive_evidence
    severity: medium
    requires_techniques:
      - T1053
    requires_signals:
      - scheduled_task_creation
""")
    jsonl = tmp_path / "artifacts.jsonl"
    jsonl.write_text("\n".join(json.dumps(a) for a in _persistence_artifacts()))

    result = validate_assumption(yaml, jsonl)
    d = result.to_dict()
    assert d["safe_conclusion"]
    assert d["status"] in [s.value for s in AssumptionStatus]
    assert "claims" in d
    assert len(d["claims"]) >= 1
