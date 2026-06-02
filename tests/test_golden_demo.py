import json
import tempfile
from pathlib import Path
import pytest
from core.quickstart import run_quickstart

def test_golden_demo_outputs_exist_and_nonempty():
    with tempfile.TemporaryDirectory() as tmp:
        results = run_quickstart(out_dir=tmp, verbose=False)
        out = Path(tmp)

        expected = [
            "sigma_validation.txt",
            "assumption_validation.txt",
            "attack_navigator_layer.json",
            "shenron_report.html",
        ]
        for fname in expected:
            p = out / fname
            assert p.exists(), f"Missing output file: {fname}"
            assert p.stat().st_size > 0, f"Empty output file: {fname}"

def test_golden_demo_sigma_has_triggered():
    with tempfile.TemporaryDirectory() as tmp:
        results = run_quickstart(out_dir=tmp, verbose=False)
        sigma = results.get("sigma", [])
        verdicts = [r.get("verdict") for r in sigma]
        assert "TRIGGERED" in verdicts, (
            f"Expected at least 1 TRIGGERED sigma result, got: {verdicts}"
        )

def test_golden_demo_pinned_assumptions_supported():
    pinned = {
        "full_kill_chain_coverage",
    }
    with tempfile.TemporaryDirectory() as tmp:
        results = run_quickstart(out_dir=tmp, verbose=False)
        assumptions = results.get("assumptions", [])
        status_map = {r["assumption_id"]: r["status"] for r in assumptions}
        for aid in pinned:
            assert aid in status_map, f"Assumption not found in results: {aid}"
            assert status_map[aid] == "SUPPORTED", (
                f"Expected {aid} to be SUPPORTED, got: {status_map[aid]}"
            )

def test_golden_demo_navigator_has_techniques():
    with tempfile.TemporaryDirectory() as tmp:
        results = run_quickstart(out_dir=tmp, verbose=False)
        nav_path = Path(results.get("navigator", ""))
        assert nav_path.exists(), "Navigator layer file not found"
        layer = json.loads(nav_path.read_text())
        techniques = layer.get("techniques", [])
        assert len(techniques) > 0, "Navigator layer has 0 techniques"

def test_golden_demo_html_contains_html_tag():
    with tempfile.TemporaryDirectory() as tmp:
        results = run_quickstart(out_dir=tmp, verbose=False)
        html_path = Path(results.get("html", ""))
        assert html_path.exists(), "HTML report file not found"
        content = html_path.read_text(encoding="utf-8", errors="replace")
        assert "<html" in content, "HTML report does not contain <html tag"
