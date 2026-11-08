"""Regression tests for exact signal matching and negated evidence."""

import pytest

from core.assumptions.model import Claim, ClaimType, ClaimSeverity, ClaimStatus
from core.assumptions.validator import _check_claim


@pytest.mark.parametrize(
    ("signal", "expected"),
    [
        ("credential_access", ClaimStatus.SUPPORTED),
        ("unrelated_signal", ClaimStatus.PARTIALLY_SUPPORTED),
        ("credential_access_not_observed", ClaimStatus.PARTIALLY_SUPPORTED),
    ],
)
def test_signal_evidence_matching(signal, expected):
    claim = Claim(
        id="credential_access_evidence",
        type=ClaimType.POSITIVE_EVIDENCE,
        severity=ClaimSeverity.HIGH,
        requires_techniques=["T1003"],
        requires_signals=["credential_access"],
    )
    artifact = {
        "artifact_id": "negation-regression-001",
        "layer": "synthetic_test",
        "mitre_techniques": ["T1003"],
        "detection_opportunities": [signal],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
    }
    result = _check_claim(claim, [artifact])
    assert result.status == expected
    assert "T1003" in result.supported
    if signal == "credential_access":
        assert "credential_access" in result.supported
        assert "credential_access" not in result.unsupported
    else:
        assert "credential_access" not in result.supported
        assert "credential_access" in result.unsupported
