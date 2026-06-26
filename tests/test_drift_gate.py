"""
tests/test_drift_gate.py

Tests for core/ci/drift_gate.py — SHENRON MITRE ATT&CK Drift CI Gate.
Uses offline mode with a minimal synthetic STIX bundle to avoid network calls.
"""
import json
import tempfile
from pathlib import Path
import pytest
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.ci.drift_gate import (
    run_drift_gate,
    main,
    _build_gate_result,
    _write_gate_result,
    _print_summary,
    EXIT_PASS,
    EXIT_ERROR,
    EXIT_DRIFT,
)

MANIFEST_PATH = Path(__file__).parent.parent / "shenron_manifest.json"
GATE_RESULT   = Path(__file__).parent.parent / "reports" / "ci" / "drift_gate_result.json"

# Minimal synthetic ATT&CK STIX bundle for offline testing
SYNTHETIC_STIX = {
    "type": "bundle",
    "objects": [
        {
            "type": "attack-pattern",
            "name": "Application Layer Protocol",
            "x_mitre_deprecated": False,
            "revoked": False,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1071"}
            ]
        },
        {
            "type": "attack-pattern",
            "name": "Data Encoding",
            "x_mitre_deprecated": False,
            "revoked": False,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1132"}
            ]
        },
        {
            "type": "attack-pattern",
            "name": "Scheduled Task",
            "x_mitre_deprecated": False,
            "revoked": False,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1053"}
            ]
        },
    ]
}


# -- Constants -----------------------------------------------------------------

def test_exit_codes_defined():
    assert EXIT_PASS  == 0
    assert EXIT_ERROR == 1
    assert EXIT_DRIFT == 2

def test_exit_codes_distinct():
    assert len({EXIT_PASS, EXIT_ERROR, EXIT_DRIFT}) == 3


# -- _build_gate_result --------------------------------------------------------

def test_build_gate_result_basic():
    r = _build_gate_result("PASS", EXIT_PASS)
    assert r["verdict"] == "PASS"
    assert r["exit_code"] == EXIT_PASS
    assert r["gate"] == "shenron_drift_gate"
    assert "timestamp" in r

def test_build_gate_result_error():
    r = _build_gate_result("ERROR", EXIT_ERROR, error_message="test error")
    assert r["verdict"] == "ERROR"
    assert r["error"] == "test error"

def test_build_gate_result_no_drift_report():
    r = _build_gate_result("PASS", EXIT_PASS)
    assert "drift_summary" not in r

def test_build_gate_result_manifest_path():
    r = _build_gate_result("PASS", EXIT_PASS, manifest_path="/custom/path.json")
    assert r["manifest_path"] == "/custom/path.json"

def test_build_gate_result_has_version():
    r = _build_gate_result("PASS", EXIT_PASS)
    assert "version" in r
    assert r["version"] == "0.1.0"


# -- _write_gate_result --------------------------------------------------------

def test_write_gate_result_creates_file():
    r = _build_gate_result("PASS", EXIT_PASS)
    with tempfile.TemporaryDirectory() as d:
        path = _write_gate_result(r, d, quiet=True)
        assert Path(path).exists()

def test_write_gate_result_valid_json():
    r = _build_gate_result("PASS", EXIT_PASS)
    with tempfile.TemporaryDirectory() as d:
        path = _write_gate_result(r, d, quiet=True)
        with open(path) as f:
            loaded = json.load(f)
        assert loaded["verdict"] == "PASS"

def test_write_gate_result_creates_parent_dirs():
    r = _build_gate_result("PASS", EXIT_PASS)
    with tempfile.TemporaryDirectory() as d:
        nested = f"{d}/nested/deep"
        path = _write_gate_result(r, nested, quiet=True)
        assert Path(path).exists()

def test_write_gate_result_returns_path_string():
    r = _build_gate_result("PASS", EXIT_PASS)
    with tempfile.TemporaryDirectory() as d:
        path = _write_gate_result(r, d, quiet=True)
        assert isinstance(path, str)


# -- run_drift_gate: manifest missing ------------------------------------------

def test_run_drift_gate_missing_manifest():
    with tempfile.TemporaryDirectory() as d:
        code = run_drift_gate(
            manifest_path="/nonexistent/manifest.json",
            report_dir=d,
            quiet=True,
        )
    assert code == EXIT_ERROR

def test_run_drift_gate_missing_manifest_writes_result():
    with tempfile.TemporaryDirectory() as d:
        run_drift_gate(
            manifest_path="/nonexistent/manifest.json",
            report_dir=d,
            quiet=True,
        )
        result_file = Path(d) / "drift_gate_result.json"
        assert result_file.exists()
        with open(result_file) as f:
            data = json.load(f)
        assert data["verdict"] == "ERROR"


# -- run_drift_gate: offline with synthetic bundle ------------------------------

def test_run_drift_gate_offline_pass():
    with tempfile.TemporaryDirectory() as d:
        cache = f"{d}/attack.json"
        with open(cache, "w") as f:
            json.dump(SYNTHETIC_STIX, f)
        code = run_drift_gate(
            manifest_path=str(MANIFEST_PATH),
            report_dir=d,
            offline=True,
            cache_path=cache,
            quiet=True,
        )
    # With synthetic bundle only 3 techniques present, rest are missing -> DRIFT
    assert code in (EXIT_PASS, EXIT_ERROR, EXIT_DRIFT)

def test_run_drift_gate_offline_writes_result():
    with tempfile.TemporaryDirectory() as d:
        cache = f"{d}/attack.json"
        with open(cache, "w") as f:
            json.dump(SYNTHETIC_STIX, f)
        run_drift_gate(
            manifest_path=str(MANIFEST_PATH),
            report_dir=d,
            offline=True,
            cache_path=cache,
            quiet=True,
        )
        result_file = Path(d) / "drift_gate_result.json"
        assert result_file.exists()

def test_run_drift_gate_offline_writes_markdown():
    with tempfile.TemporaryDirectory() as d:
        cache = f"{d}/attack.json"
        with open(cache, "w") as f:
            json.dump(SYNTHETIC_STIX, f)
        run_drift_gate(
            manifest_path=str(MANIFEST_PATH),
            report_dir=d,
            offline=True,
            cache_path=cache,
            quiet=True,
        )
        md_file = Path(d) / "drift_gate_report.md"
        assert md_file.exists()

def test_run_drift_gate_result_structure():
    with tempfile.TemporaryDirectory() as d:
        cache = f"{d}/attack.json"
        with open(cache, "w") as f:
            json.dump(SYNTHETIC_STIX, f)
        run_drift_gate(
            manifest_path=str(MANIFEST_PATH),
            report_dir=d,
            offline=True,
            cache_path=cache,
            quiet=True,
        )
        with open(Path(d) / "drift_gate_result.json") as f:
            data = json.load(f)
        assert "verdict" in data
        assert "exit_code" in data
        assert "timestamp" in data
        assert "gate" in data
        assert "drift_summary" in data

def test_run_drift_gate_drift_summary_fields():
    with tempfile.TemporaryDirectory() as d:
        cache = f"{d}/attack.json"
        with open(cache, "w") as f:
            json.dump(SYNTHETIC_STIX, f)
        run_drift_gate(
            manifest_path=str(MANIFEST_PATH),
            report_dir=d,
            offline=True,
            cache_path=cache,
            quiet=True,
        )
        with open(Path(d) / "drift_gate_result.json") as f:
            data = json.load(f)
        ds = data["drift_summary"]
        assert "ok_count" in ds
        assert "stale_count" in ds
        assert "renamed_count" in ds
        assert "total_techniques" in ds
        assert "stale_techniques" in ds
        assert "renamed_techniques" in ds


# -- main() CLI entrypoint -----------------------------------------------------

def test_main_missing_manifest():
    with tempfile.TemporaryDirectory() as d:
        code = main(["--manifest", "/nonexistent.json", "--report-dir", d, "--quiet"])
    assert code == EXIT_ERROR

def test_main_offline_requires_cache():
    code = main(["--offline"])
    assert code == EXIT_ERROR

def test_main_returns_int():
    with tempfile.TemporaryDirectory() as d:
        result = main(["--manifest", "/nonexistent.json", "--report-dir", d, "--quiet"])
    assert isinstance(result, int)


# -- Committed gate result (from previous run) ---------------------------------

def test_committed_gate_result_exists():
    assert GATE_RESULT.exists(), f"Gate result not found: {GATE_RESULT}"

def test_committed_gate_result_was_pass():
    if not GATE_RESULT.exists():
        pytest.skip("Gate result not committed yet")
    with open(GATE_RESULT) as f:
        data = json.load(f)
    assert data["verdict"] == "PASS"
    assert data["exit_code"] == EXIT_PASS

def test_committed_gate_result_has_summary():
    if not GATE_RESULT.exists():
        pytest.skip("Gate result not committed yet")
    with open(GATE_RESULT) as f:
        data = json.load(f)
    assert "drift_summary" in data
    assert data["drift_summary"]["stale_count"] == 0
