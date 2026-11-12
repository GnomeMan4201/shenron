"""Red-first: device identity emission is not evidence of valid-account abuse."""

import json
import random
from pathlib import Path

from core.assumptions.loader import load_assumption
from core.assumptions.model import ClaimStatus
from core.assumptions.validator import _check_claim
from core.layers import device_fingerprint_spoof


REPO_ROOT = Path(__file__).resolve().parents[1]
CLAIMS = REPO_ROOT / "assumptions/examples/identity_spoofing_coverage.yaml"


def _identity_claim():
    _, _, claims = load_assumption(CLAIMS)
    return next(c for c in claims if c.id == "device_identity_pollution_evidence")


def test_declared_device_fingerprint_techniques_do_not_include_valid_accounts():
    assert "T1078" not in device_fingerprint_spoof.MITRE_TECHNIQUES


def test_generated_device_identity_records_do_not_claim_valid_accounts(tmp_path, monkeypatch):
    artifact = tmp_path / "scoped_identity.jsonl"
    monkeypatch.setattr(device_fingerprint_spoof, "_get_artifact_log", lambda: artifact)
    rng_state = random.getstate()
    try:
        _, events = device_fingerprint_spoof.simulate_device_fingerprint_spoof(seed=23)
    finally:
        random.setstate(rng_state)
    assert len(events) == 4
    recorded = [json.loads(row) for row in artifact.read_text().splitlines()]
    assert len(recorded) == len(events)
    allowed = set(device_fingerprint_spoof.MITRE_TECHNIQUES)
    for record in recorded:
        assert record["simulation_only"] is True
        assert record["executable"] is False
        assert "T1078" not in record["mitre_techniques"]
        assert set(record["mitre_techniques"]) <= allowed


def test_device_identity_assumption_does_not_require_valid_accounts():
    claim = _identity_claim()
    assert claim.evidence_scope == "same_artifact"
    assert claim.requires_signals == ["multi_identity_emit_sim"]
    assert "T1078" not in claim.requires_techniques


def test_device_identity_signal_does_not_need_valid_account_label():
    claim = _identity_claim()
    record = {
        "mitre_techniques": ["T1036"],
        "behavior_class": "multi_identity_emit_sim",
    }
    result = _check_claim(claim, [record])
    assert result.status == ClaimStatus.SUPPORTED


def test_valid_account_label_alone_does_not_prove_device_identity_emission():
    claim = _identity_claim()
    record = {
        "mitre_techniques": ["T1078"],
        "behavior_class": "unrelated",
    }
    result = _check_claim(claim, [record])
    assert result.status == ClaimStatus.PARTIALLY_SUPPORTED or result.status == ClaimStatus.UNSUPPORTED


def test_existing_taxonomy_and_manifest_do_not_require_t1078_for_this_layer():
    taxonomy = json.loads((REPO_ROOT / "taxonomy/mitre_mappings.json").read_text())
    manifest = json.loads((REPO_ROOT / "shenron_manifest.json").read_text())
    tax = taxonomy["layers"]["device_fingerprint_spoof"]["techniques"]
    man = next(x for x in manifest["layers"] if x["name"] == "device_fingerprint_spoof")
    assert "T1078" not in tax
    assert "T1078" not in man["mitre"]["techniques"]
