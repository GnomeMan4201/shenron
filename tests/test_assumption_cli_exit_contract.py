# CLI regression tests; Python 3.10–3.12; pytest + SHENRON dependencies; [needs Linux runner].
"""Issue #59: strict single-assumption CLI exit and schema qualification contract."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]


def _run_cli(tmp_path, assumption, events, *, scope=False):
    home = tmp_path / "home"
    reports = tmp_path / "reports"
    env = os.environ.copy()
    env["SHENRON_HOME"] = str(home)
    env["SHENRON_REPORT_DIR"] = str(reports)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    argv = [
        sys.executable, str(ROOT / "shenron.py"), "assumption", "validate",
        str(assumption), "--events", str(events),
    ]
    if scope:
        argv.append("--scope-report")
    result = subprocess.run(
        argv, cwd=ROOT, env=env, text=True, capture_output=True,
        timeout=30, check=False,
    )
    return result, home, reports


def _inputs(tmp_path, *, status="SUPPORTED", schema_version="1.0"):
    records = [{"behavior_class": "signal_one"}]
    claims = [{
        "id": "required_signal",
        "type": "positive_evidence",
        "requires_signals": ["signal_one"],
    }]
    if status == "UNSUPPORTED":
        records = [{"behavior_class": "not_observed"}]
    elif status == "PARTIALLY_SUPPORTED":
        # Aggregate partial requires one fully supported positive claim.
        # An incomplete claim by itself aggregates to UNSUPPORTED.
        claims[0]["requires_signals"].append("signal_two")
        claims.append({
            "id": "supported_control",
            "type": "positive_evidence",
            "requires_signals": ["signal_one"],
        })
    elif status == "OUT_OF_SCOPE_VIOLATION":
        claims.append({
            "id": "forbidden_signal", "type": "out_of_scope_claim",
            "requires_signals": ["signal_one"],
        })
    doc = {"id": "cli_boundary", "description": "Synthetic fixture", "claims": claims}
    if schema_version is not None:
        doc["schema_version"] = schema_version
    assumption = tmp_path / "assumption.yaml"
    assumption.write_text(yaml.safe_dump(doc), encoding="utf-8")
    events = tmp_path / "evidence.jsonl"
    events.write_text("".join(json.dumps(x) + "\n" for x in records), encoding="utf-8")
    return assumption, events


@pytest.mark.parametrize("verdict,code,printed", [
    ("SUPPORTED", 0, "STATUS:     SUPPORTED"),
    ("PARTIALLY_SUPPORTED", 1, "STATUS:     PARTIALLY SUPPORTED"),
    ("UNSUPPORTED", 1, "STATUS:     UNSUPPORTED"),
    ("OUT_OF_SCOPE_VIOLATION", 1, "STATUS:     OUT-OF-SCOPE VIOLATION"),
])
def test_valid_verdict_exit_contract_and_provenance(tmp_path, verdict, code, printed):
    assumption, events = _inputs(tmp_path, status=verdict)
    outcome, home, reports = _run_cli(
        tmp_path, assumption, events, scope=verdict == "SUPPORTED"
    )
    assert outcome.returncode == code, outcome.stdout + outcome.stderr
    assert printed in outcome.stdout
    assert "Traceback" not in outcome.stderr
    history = home / "validation_history.jsonl"
    assert history.is_file(), "Valid negative verdicts are still recorded as evidence"
    records = [json.loads(line) for line in history.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["data"]["status"] == verdict
    index = reports / "assumptions/index.md"
    assert index.is_file() and verdict in index.read_text()
    if verdict == "SUPPORTED":
        assert list((reports / "assumptions").glob("scope_*.md"))


@pytest.mark.parametrize("kind", ["missing_events", "malformed_jsonl", "non_object_jsonl",
                                    "missing_yaml", "invalid_yaml"])
def test_invalid_inputs_exit_three_without_success_or_history(tmp_path, kind):
    assumption, events = _inputs(tmp_path)
    if kind == "missing_events":
        events.unlink()
    elif kind == "malformed_jsonl":
        events.write_text('{"behavior_class":"signal_one"}\n{not-json}\n', encoding="utf-8")
    elif kind == "non_object_jsonl":
        events.write_text('{"behavior_class":"signal_one"}\nnull\n', encoding="utf-8")
    elif kind == "missing_yaml":
        assumption.unlink()
    elif kind == "invalid_yaml":
        assumption.write_text("claims: [\n", encoding="utf-8")
    outcome, home, reports = _run_cli(tmp_path, assumption, events)
    assert outcome.returncode == 3, outcome.stdout + outcome.stderr
    assert "Traceback" not in outcome.stderr
    assert "SUPPORTED" not in outcome.stdout
    assert not (home / "validation_history.jsonl").exists()
    assert not (reports / "assumptions/index.md").exists()


@pytest.mark.parametrize("schema", [None, "0.9", "2.0", ""])
def test_unqualified_schema_never_returns_supported(tmp_path, schema):
    assumption, events = _inputs(tmp_path, schema_version=schema)
    outcome, home, reports = _run_cli(tmp_path, assumption, events)
    assert outcome.returncode == 3, outcome.stdout + outcome.stderr
    assert "Traceback" not in outcome.stderr
    assert "schema_version" in outcome.stderr
    assert "STATUS:     SUPPORTED" not in outcome.stdout
    assert not (home / "validation_history.jsonl").exists()
    assert not (reports / "assumptions/index.md").exists()


def test_non_cli_loader_keeps_explicit_version_warnings(tmp_path):
    # Direct library callers retain the historical warning-only route; the
    # individual CLI opts into a stricter 1.0 qualification contract.
    from core.assumptions.loader import load_assumption

    assumption, _ = _inputs(tmp_path, schema_version=None)
    with pytest.warns(UserWarning, match="missing 'schema_version'"):
        _, _, claims = load_assumption(assumption)
    assert len(claims) == 1
    with pytest.raises(ValueError, match="schema_version"):
        load_assumption(assumption, require_current_schema=True)
