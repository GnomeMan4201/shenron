"""Regression coverage for read-only, exact-match assumption diagnostics."""
import json

from scripts.diagnose_assumption_signals import diagnose


def test_payload_diagnostic_requires_exact_inline_interpreter_evidence(tmp_path):
    path = tmp_path / "payload.jsonl"
    path.write_text(json.dumps({
        "mitre_techniques": ["T1059"],
        "behavior_class": "script_execution_sim",
        "detection_opportunities": ["interpreter_spawn_no_script_arg_sim"],
    }) + "\n")
    report = diagnose("payload", path)
    claim = next(c for c in report["claims"] if c["claim_id"] == "scripting_evidence")
    matches = {s["signal"]: s["exact_match"] for s in claim["required_signals"]}
    assert matches["script_execution_sim"] is True
    assert matches["interpreter_inline_exec_sim"] is False
    assert claim["status"] == "PARTIALLY_SUPPORTED"
    assert "interpreter_inline_exec_sim" in claim["unsupported"]


def test_identity_diagnostic_does_not_conflate_uuid_with_multi_identity(tmp_path):
    path = tmp_path / "identity.jsonl"
    path.write_text(json.dumps({
        "mitre_techniques": ["T1078"],
        "behavior_class": "uuid_anomaly_sim",
        "detection_opportunities": ["synthetic_device_uuid_rapid_generation_sim"],
    }) + "\n")
    report = diagnose("identity", path)
    claim = next(c for c in report["claims"] if c["claim_id"] == "device_identity_pollution_evidence")
    matches = {s["signal"]: s["exact_match"] for s in claim["required_signals"]}
    assert matches["multi_identity_emit_sim"] is False
    assert claim["status"] == "PARTIALLY_SUPPORTED"
    assert "multi_identity_emit_sim" in claim["unsupported"]


def test_identity_assumption_does_not_claim_token_impersonation(tmp_path):
    path = tmp_path / "identity.jsonl"
    path.write_text(json.dumps({}) + "\n")
    report = diagnose("identity", path)
    assert "token_impersonation_evidence" not in {c["claim_id"] for c in report["claims"]}
    assert "process_injection_identity_evidence" not in {c["claim_id"] for c in report["claims"]}
