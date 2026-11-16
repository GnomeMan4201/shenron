import pytest
from core.assumptions.model import Claim, ClaimType, ClaimSeverity, ClaimStatus
from core.assumptions.validator import _check_claim

@pytest.mark.parametrize("name,kind,artifact,expected", [
    ("expected_event_only", ClaimType.POSITIVE_EVIDENCE, {"expected_events": ["credential_access"], "simulation_only": True}, ClaimStatus.SUPPORTED),
    ("out_of_scope_missing", ClaimType.OUT_OF_SCOPE, {"simulation_only": True}, ClaimStatus.SUPPORTED),
])
def test_current_evidence_semantics(name, kind, artifact, expected):
    claim = Claim(id=name, type=kind, severity=ClaimSeverity.HIGH, requires_signals=["credential_access"])
    result = _check_claim(claim, [artifact])
    assert result.status == expected


def test_expected_only_conclusion_current_behavior():
    from core.assumptions.validator import _safe_conclusion
    claim = Claim(id="expected_only", type=ClaimType.POSITIVE_EVIDENCE, severity=ClaimSeverity.HIGH, requires_signals=["credential_access"])
    result = _check_claim(claim, [{"expected_events": ["credential_access"], "simulation_only": True}])
    conclusion = _safe_conclusion("credential_access", [result])
    assert result.status == ClaimStatus.SUPPORTED
    assert "supports validation claims" in conclusion
    assert "declared simulation expectations" in conclusion.lower()
    assert "does not independently verify observed telemetry" in conclusion.lower()
