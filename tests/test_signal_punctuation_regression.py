"""Red-first: punctuation must not turn negative evidence into exact positive signals."""

import pytest

from core.assumptions.model import Claim, ClaimStatus, ClaimType
from core.assumptions.validator import _check_claim, _normalize


CANONICAL = "credential_access"


@pytest.mark.parametrize(
    "observed",
    [
        "!credential_access",
        "~credential_access",
        "credential_access!",
        "credential_access~",
        "credential!access",
        "credential/access",
        "credential.access",
        "credential_access.",
    ],
)
@pytest.mark.parametrize("scope", ["category", "same_artifact"])
def test_punctuation_does_not_create_positive_evidence(observed, scope):
    claim = Claim(
        id="credential_access_evidence",
        type=ClaimType.POSITIVE_EVIDENCE,
        requires_techniques=["T1003"],
        requires_signals=[CANONICAL],
        evidence_scope=scope,
    )
    artifact = {
        "mitre_techniques": ["T1003"],
        "detection_opportunities": [observed],
    }
    result = _check_claim(claim, [artifact])
    assert result.status == ClaimStatus.PARTIALLY_SUPPORTED
    assert CANONICAL in result.unsupported
    assert CANONICAL not in result.supported


@pytest.mark.parametrize(
    "observed",
    ["!credential_access", "~credential_access", "credential_access!"],
)
def test_punctuation_cannot_trigger_out_of_scope_false_violation(observed):
    claim = Claim(
        id="no_credential_access",
        type=ClaimType.OUT_OF_SCOPE,
        requires_signals=[CANONICAL],
    )
    result = _check_claim(claim, [{"detection_opportunities": [observed]}])
    assert result.status == ClaimStatus.SUPPORTED


@pytest.mark.parametrize(
    "observed",
    [
        "credential_access",
        "CREDENTIAL_ACCESS",
        "credential-access",
        "credential access",
        "credential__access",
    ],
)
def test_intentional_equivalent_spellings_still_match(observed):
    claim = Claim(
        id="credential_access_evidence",
        type=ClaimType.POSITIVE_EVIDENCE,
        requires_signals=[CANONICAL],
    )
    result = _check_claim(claim, [{"detection_opportunities": [observed]}])
    assert result.status == ClaimStatus.SUPPORTED


@pytest.mark.parametrize("observed", ["!credential_access", "~credential_access", "credential_access!"])
def test_normalization_does_not_erase_punctuation(observed):
    assert _normalize(observed) != _normalize(CANONICAL)
