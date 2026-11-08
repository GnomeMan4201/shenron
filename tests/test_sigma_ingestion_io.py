"""F1/F2: mandatory Sigma evidence and per-line UTF-8 errors fail closed."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.assumptions import loader as assumption_loader
from core.cli.commands import validate as validate_cli
from core.ingest.jsonl import ArtifactInputError
from core.sigma import evaluator, loader, pysigma_bridge as bridge
from tests.test_sigma_ingestion import RULE, backend, cli, inputs, json_results


@pytest.fixture(params=["canonical", "legacy"])
def rule_kind(request, inputs):
    rule, artifact = inputs
    if request.param == "legacy":
        text = RULE.replace("logsource:\n  category: process_creation\n  product: windows\n", "")
        for path in rule.parent.glob("*.yml"):
            path.write_text(text, encoding="utf-8")
    return request.param


def invalid_input(artifact, case):
    if case == "missing":
        artifact.unlink()
        return None
    lines = artifact.read_bytes().splitlines(keepends=True)
    position = {"utf8-first": 0, "utf8-middle": 20, "utf8-final": 40}[case]
    lines.insert(position, b"\xff\n")
    artifact.write_bytes(b"".join(lines))
    return position + 1


@pytest.mark.parametrize("case", ["missing", "utf8-first", "utf8-middle", "utf8-final"])
def test_evaluator_io_errors(inputs, backend, rule_kind, case):
    rule, artifact = inputs
    line = invalid_input(artifact, case)
    expected = FileNotFoundError if case == "missing" else ArtifactInputError
    with pytest.raises(expected) as caught:
        evaluator.evaluate_sigma_rule(rule, artifact, prefer_pysigma=backend == "native")
    assert str(artifact) in str(caught.value)
    if line is not None:
        assert f"line {line}:" in str(caught.value)
    with pytest.raises(expected):
        loader.load_artifacts(artifact)


@pytest.mark.parametrize("case", ["missing", "utf8-first", "utf8-middle", "utf8-final"])
@pytest.mark.parametrize("route", ["validate", "validate-mutations", "validate-dir", "sigma", "sigma-dir"])
def test_cli_io_errors(inputs, backend, rule_kind, case, route, tmp_path):
    rule, artifact = inputs
    line = invalid_input(artifact, case)
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
    assert "Traceback" not in completed.stderr
    assert str(artifact) in completed.stderr
    if line is not None:
        assert f"line {line}:" in completed.stderr
    if route.startswith("validate"):
        rows = json_results(completed)
        assert len(rows) == (2 if route == "validate-dir" else 1)
        for row in rows:
            assert row["verdict"] == "ERROR"
            assert row["triggered"] is False and row["triggered_count"] == 0
            assert str(artifact) in row["error"]
            if line is not None:
                assert f"line {line}:" in row["error"]
    else:
        assert "NOT_TRIGGERED" not in completed.stdout
        assert "TRIGGERED" not in completed.stdout


@pytest.mark.parametrize("case", ["missing", "utf8-first", "utf8-middle", "utf8-final"])
def test_direct_native_io_errors(inputs, case):
    pytest.importorskip("sigma.collection")
    rule, artifact = inputs
    line = invalid_input(artifact, case)
    result = bridge.evaluate_with_pysigma(str(rule), str(artifact))
    assert result.verdict == bridge.BridgeVerdict.ERROR
    assert result.artifact_error and not result.matched_events
    assert result.triggered_count == 0
    assert str(artifact) in " ".join(result.errors)
    if line is not None:
        assert f"line {line}:" in " ".join(result.errors)


@pytest.mark.parametrize("separator", [b"\n", b"\r\n", b"\r"])
def test_clean_utf8_and_universal_newlines(inputs, backend, separator):
    rule, artifact = inputs
    rows = [json.loads(line) for line in artifact.read_text().splitlines()]
    rows[0]["unicode_control"] = "caf\u00e9 \U0001f409"
    artifact.write_bytes(separator.join(json.dumps(row, ensure_ascii=False).encode("utf-8") for row in rows) + separator)
    result = evaluator.evaluate_sigma_rule(rule, artifact, prefer_pysigma=backend == "native")
    assert result.verdict.value == "TRIGGERED" and result.triggered_count == 1
    artifact.write_bytes(artifact.read_bytes() + b"\xff" + separator)
    with pytest.raises(ArtifactInputError, match="line 41:"):
        evaluator.evaluate_sigma_rule(rule, artifact, prefer_pysigma=backend == "native")


@pytest.mark.parametrize("mutations", [False, True])
def test_missing_default_artifact_is_structured_error(inputs, tmp_path, monkeypatch, capsys, mutations):
    rule, _ = inputs
    fake_module = tmp_path / "isolated" / "core" / "cli" / "commands" / "validate.py"
    monkeypatch.setattr(validate_cli, "__file__", str(fake_module))
    missing = tmp_path / "isolated" / "artifacts" / "demo" / "shenron_demo_run.jsonl"
    args = SimpleNamespace(rules=str(rule), artifact=None, scenario="unused",
                           mutations=mutations, threshold=0.5, format="json", out=None)
    with pytest.raises(SystemExit) as caught:
        validate_cli.run(args)
    assert caught.value.code == 3
    captured = capsys.readouterr()
    assert str(missing) in captured.err
    rows = json.loads(captured.out[captured.out.index("\n[\n") + 1:])
    assert rows[0]["verdict"] == "ERROR" and str(missing) in rows[0]["error"]


def test_assumption_missing_file_behavior_is_preserved(tmp_path):
    assert assumption_loader.load_artifacts(tmp_path / "absent.jsonl") == []
