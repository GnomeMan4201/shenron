"""
tests/test_demo_artifact_lock.py
SHENRON — demo artifact integrity gate

Asserts the committed demo artifact hasn't drifted.
If you intentionally regenerate the demo artifact, update EXPECTED_SHA256.

To update:
    python3 shenron.py --demo
    sha256sum artifacts/demo/shenron_demo_run.jsonl
    # paste the new hash below
"""
import hashlib
from pathlib import Path

DEMO_PATH     = Path("artifacts/demo/shenron_demo_run.jsonl")
EXPECTED_SHA256 = "d2eb0b62912b6aeff5c0ebe442e72803b8074b8be736ab4283a352ceae41cd9f"


def test_demo_artifact_exists():
    assert DEMO_PATH.exists(), (
        f"Demo artifact not found: {DEMO_PATH}. "
        "Run: python3 shenron.py --demo"
    )


def test_demo_artifact_schema():
    """Every record must have the required schema fields."""
    import json
    required = {"artifact_id", "session_id", "layer", "mitre_techniques",
                 "simulation_only", "behavior_class", "detection_opportunities"}
    records = [json.loads(l) for l in DEMO_PATH.read_text().splitlines() if l.strip()]
    assert len(records) == 40, f"Expected 40 demo records, got {len(records)}"
    for i, r in enumerate(records):
        missing = required - set(r.keys())
        assert not missing, f"Record {i+1} missing fields: {missing}"


def test_demo_artifact_safety_contract():
    """Every record must have simulation_only=True."""
    import json
    records = [json.loads(l) for l in DEMO_PATH.read_text().splitlines() if l.strip()]
    for i, r in enumerate(records):
        assert r.get("simulation_only") is True, (
            f"Record {i+1} has simulation_only != True"
        )
        assert r.get("executable") is False, (
            f"Record {i+1} has executable != False"
        )


def test_demo_artifact_checksum():
    """Demo artifact checksum must match the committed baseline.

    If you intentionally regenerated the demo artifact, update EXPECTED_SHA256
    in this file with the output of:
        sha256sum artifacts/demo/shenron_demo_run.jsonl
    """
    actual = hashlib.sha256(DEMO_PATH.read_bytes()).hexdigest()
    assert actual == EXPECTED_SHA256, (
        f"Demo artifact has changed (checksum mismatch).\n"
        f"  Expected: {EXPECTED_SHA256}\n"
        f"  Actual:   {actual}\n"
        f"If this is intentional, update EXPECTED_SHA256 in {__file__}"
    )
