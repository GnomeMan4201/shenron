"""Release-blocker regressions: corrupt evidence must never qualify a rule."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from core.sigma import evaluator, loader, pysigma_bridge as bridge
from scripts.generate_demo_artifacts import generate_events

ROOT = Path(__file__).resolve().parents[1]
RULE = """title: Sigma ingestion release control
id: 2e604a73-f824-467f-99ac-a32419db54ed
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    layer: beacon_emitter_cloak
  condition: selection
level: low
"""


@pytest.fixture
def inputs(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    rule = rules / "first.yml"
    rule.write_text(RULE, encoding="utf-8")
    (rules / "second.yml").write_text(
        RULE.replace("2e604a73-f824-467f-99ac-a32419db54ed",
                     "af4df31c-deac-450f-bbd7-00de4dff9896"), encoding="utf-8"
    )
    artifact = tmp_path / "events.jsonl"
    rows = generate_events("sigma-ingestion-regression")
    artifact.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return rule, artifact


@pytest.fixture(params=["fallback", "native"])
def backend(request):
    if request.param == "native":
        pytest.importorskip("sigma.collection")
        assert bridge.pysigma_available()
    return request.param


def corrupt(artifact, case):
    lines = artifact.read_text(encoding="utf-8").splitlines()
    if case == "first":
        lines.insert(0, "{not-json}")
        line = 1
    elif case == "middle":
        lines.insert(20, "{not-json}")
        line = 21
    elif case == "final":
        lines.append("{not-json}")
        line = 41
    else:
        lines.insert(20, case)
        line = 21
    artifact.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return line


def cli(args, backend, tmp_path):
    # Native runs the installed backend unmodified. Fallback selection only
    # disables availability; it does not mock parsing, matching, or CLI handling.
    if backend == "native":
        command = [sys.executable, str(ROOT / "shenron.py"), *args]
    else:
        command = [sys.executable, "-c", (
            "import runpy,sys;"
            "from core.sigma import pysigma_bridge as b;"
            "b.pysigma_available=lambda:False;"
            "sys.argv=['shenron.py']+sys.argv[1:];"
            "runpy.run_path('shenron.py',run_name='__main__')"
        ), *args]
    env = os.environ.copy()
    env["SHENRON_HOME"] = str(tmp_path / "home")
    return subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)


def json_results(completed):
    start = completed.stdout.index("\n[\n") + 1
    return json.loads(completed.stdout[start:])


@pytest.mark.parametrize("mode", ["strict", "tolerant", "explain"])
def test_clean_backend_and_nontriggered_behavior(inputs, backend, mode):
    rule, artifact = inputs
    result = evaluator.evaluate_sigma_rule(rule, artifact, match_mode=mode,
                                           prefer_pysigma=backend == "native")
    assert result.verdict.value == "TRIGGERED"
    assert result.triggered_count == 1
    if backend == "native":
        assert result.coverage_note.startswith("[pySigma]")
    rule.write_text(RULE.replace("layer: beacon_emitter_cloak", "layer: absent_layer"))
    result = evaluator.evaluate_sigma_rule(rule, artifact, match_mode=mode,
                                           prefer_pysigma=backend == "native")
    assert result.verdict.value == "NOT_TRIGGERED"


@pytest.mark.parametrize("case", ["first", "middle", "final", "[]", "null", "42", '"string"', "true"])
def test_all_corrupt_locations_and_event_types_rejected(inputs, backend, case):
    rule, artifact = inputs
    line = corrupt(artifact, case)
    with pytest.raises(ValueError) as caught:
        evaluator.evaluate_sigma_rule(rule, artifact, prefer_pysigma=backend == "native")
    assert str(artifact) in str(caught.value)
    assert f"line {line}" in str(caught.value)
    with pytest.raises(ValueError):
        loader.load_artifacts(artifact)
    if backend == "native":
        result = bridge.evaluate_with_pysigma(str(rule), str(artifact))
        assert result.verdict == bridge.BridgeVerdict.ERROR
        assert result.triggered_count == 0
        assert str(artifact) in " ".join(result.errors)
        assert f"line {line}" in " ".join(result.errors)


def test_blank_lines_remain_ignored(inputs, backend):
    rule, artifact = inputs
    artifact.write_text(" \t\n\n" + artifact.read_text() + " \t\n")
    result = evaluator.evaluate_sigma_rule(rule, artifact, prefer_pysigma=backend == "native")
    assert result.verdict.value == "TRIGGERED"
    assert result.triggered_count == 1


@pytest.mark.parametrize("route", ["validate", "validate-mutations", "validate-dir", "sigma", "sigma-dir"])
@pytest.mark.parametrize("case", ["final", "null"])
def test_cli_corrupt_evidence_is_unqualified(inputs, backend, route, case, tmp_path):
    rule, artifact = inputs
    line = corrupt(artifact, case)
    if route.startswith("validate"):
        target = rule.parent if route == "validate-dir" else rule
        args = ["validate", "--rules", str(target), "--artifact", str(artifact), "--format", "json"]
        if route != "validate-mutations":
            args.append("--no-mutations")
    else:
        args = ["sigma", "validate-dir" if route == "sigma-dir" else "validate",
                str(rule.parent if route == "sigma-dir" else rule), "--events", str(artifact)]
    completed = cli(args, backend, tmp_path)
    assert completed.returncode == 3, completed.stdout + completed.stderr
    assert str(artifact) in completed.stderr
    assert f"line {line}" in completed.stderr
    if route.startswith("validate"):
        results = json_results(completed)
        assert len(results) == (2 if route == "validate-dir" else 1)
        assert all(r["verdict"] == "ERROR" and not r["triggered"] for r in results)
        assert all(r["triggered_count"] == 0 and r["error"] for r in results)
        assert all(f"line {line}" in r["error"] for r in results)
    else:
        assert "TRIGGERED" not in completed.stdout


@pytest.mark.parametrize("route", ["validate", "sigma", "sigma-dir"])
def test_cli_clean_input_still_succeeds(inputs, backend, route, tmp_path):
    rule, artifact = inputs
    if route == "validate":
        args = ["validate", "--rules", str(rule), "--artifact", str(artifact), "--no-mutations", "--format", "json"]
    else:
        args = ["sigma", "validate-dir" if route == "sigma-dir" else "validate",
                str(rule.parent if route == "sigma-dir" else rule), "--events", str(artifact)]
    completed = cli(args, backend, tmp_path)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert not completed.stderr
    assert "TRIGGERED" in completed.stdout
    if route == "validate":
        assert json_results(completed)[0]["error"] is None


def test_native_ingestion_failure_never_falls_back(inputs, monkeypatch):
    pytest.importorskip("sigma.collection")
    rule, artifact = inputs
    calls = []
    def unreadable(path):
        calls.append(str(path))
        raise OSError(f"injected ingestion failure: {path}")
    monkeypatch.setattr(bridge, "load_artifacts", unreadable)
    # Preflight has a valid artifact. The real native bridge must report its
    # subsequent ingestion failure, and the evaluator must not match via fallback.
    with pytest.raises(ValueError, match="injected ingestion failure"):
        evaluator.evaluate_sigma_rule(rule, artifact)
    assert calls == [str(artifact)]


def test_native_rule_parse_fallback_still_rejects_bad_evidence(inputs):
    pytest.importorskip("sigma.collection")
    rule, artifact = inputs
    # pySigma requires logsource; the legacy evaluator accepts this rule.
    rule.write_text("title: Legacy rule\ndetection:\n  selection:\n    layer: beacon_emitter_cloak\n  condition: selection\n")
    assert evaluator.evaluate_sigma_rule(rule, artifact).verdict.value == "TRIGGERED"
    corrupt(artifact, "final")
    with pytest.raises(ValueError, match="line 41"):
        evaluator.evaluate_sigma_rule(rule, artifact)
