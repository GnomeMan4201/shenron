# tests/test_audit_bundle.py
import json
import tempfile
from pathlib import Path
import pytest
from core.audit.bundle import run_audit_bundle

DEMO     = "artifacts/demo/shenron_demo_run.jsonl"
RULES    = "sigma/rules"
ASSUMPTIONS = "assumptions/examples"


def _run(tmp):
    return run_audit_bundle(
        events_path     = DEMO,
        rules_dir       = RULES,
        assumptions_dir = ASSUMPTIONS,
        out_dir         = tmp,
        verbose         = False,
    )


def test_bundle_returns_ok():
    with tempfile.TemporaryDirectory() as tmp:
        result = _run(tmp)
        assert result.get("ok") is True


def test_bundle_output_files_exist():
    with tempfile.TemporaryDirectory() as tmp:
        _run(tmp)
        out = Path(tmp)
        expected = [
            "safety_verification.json",
            "sigma_results.json",
            "assumption_results.json",
            "attack_navigator_layer.json",
            "overclaim_risk.md",
            "reproducibility.json",
            "reproducibility.md",
            "index.html",
        ]
        for fname in expected:
            assert (out / fname).exists(), f"Missing: {fname}"
            assert (out / fname).stat().st_size > 0, f"Empty: {fname}"


def test_bundle_schema_gate_passes():
    with tempfile.TemporaryDirectory() as tmp:
        result = _run(tmp)
        repro = json.loads((Path(tmp) / "reproducibility.json").read_text())
        assert repro["summary"]["schema_valid"] is True


def test_bundle_safety_verdict_pass():
    with tempfile.TemporaryDirectory() as tmp:
        _run(tmp)
        safety = json.loads((Path(tmp) / "safety_verification.json").read_text())
        assert safety["verdict"] == "PASS"
        assert safety["violations"] == []


def test_bundle_sigma_has_triggered():
    with tempfile.TemporaryDirectory() as tmp:
        _run(tmp)
        sigma = json.loads((Path(tmp) / "sigma_results.json").read_text())
        verdicts = [r.get("verdict") for r in sigma]
        assert "TRIGGERED" in verdicts


def test_bundle_assumptions_has_supported():
    with tempfile.TemporaryDirectory() as tmp:
        _run(tmp)
        assumptions = json.loads((Path(tmp) / "assumption_results.json").read_text())
        statuses = [r.get("status") for r in assumptions]
        assert "SUPPORTED" in statuses


def test_bundle_navigator_has_techniques():
    with tempfile.TemporaryDirectory() as tmp:
        _run(tmp)
        nav = json.loads((Path(tmp) / "attack_navigator_layer.json").read_text())
        assert len(nav.get("techniques", [])) > 0


def test_bundle_overclaim_risk_exists_and_nonempty():
    with tempfile.TemporaryDirectory() as tmp:
        _run(tmp)
        content = (Path(tmp) / "overclaim_risk.md").read_text()
        assert "# Overclaim Risk Report" in content


def test_bundle_reproducibility_has_sha256():
    with tempfile.TemporaryDirectory() as tmp:
        _run(tmp)
        repro = json.loads((Path(tmp) / "reproducibility.json").read_text())
        sha = repro["inputs"]["events_sha256"]
        assert len(sha) == 64  # SHA-256 hex


def test_bundle_reproducibility_counts_match():
    with tempfile.TemporaryDirectory() as tmp:
        _run(tmp)
        repro = json.loads((Path(tmp) / "reproducibility.json").read_text())
        assert repro["inputs"]["events_count"] == 102
        assert repro["inputs"]["rules_count"] == 8
        assert repro["summary"]["mitre_techniques"] == 23


def test_bundle_index_html_contains_html_tag():
    with tempfile.TemporaryDirectory() as tmp:
        _run(tmp)
        content = (Path(tmp) / "index.html").read_text()
        assert "<html" in content


def test_bundle_fails_on_missing_events():
    with tempfile.TemporaryDirectory() as tmp:
        result = run_audit_bundle(
            events_path     = "nonexistent.jsonl",
            rules_dir       = RULES,
            assumptions_dir = ASSUMPTIONS,
            out_dir         = tmp,
            verbose         = False,
        )
        assert result.get("ok") is not True
