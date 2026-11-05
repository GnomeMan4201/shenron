# Reviewer evidence-gate negative controls; Python 3.10+; pytest and SHENRON dependencies.
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.assumptions.loader import load_artifacts
from core.audit.bundle import run_audit_bundle
from core.cli.commands import validate as validation_cli


def test_malformed_jsonl_is_not_silently_dropped(tmp_path):
    path = tmp_path / "partially_corrupt.jsonl"
    path.write_text('{"behavior_class": "required_signal"}\n{not-json}\n', encoding="utf-8")
    with pytest.raises((ValueError, json.JSONDecodeError), match=r"(?i)(line 2|json)"):
        load_artifacts(path)


def test_audit_bundle_rejects_missing_nested_safety_field(tmp_path):
    source = Path("artifacts/demo/shenron_demo_run.jsonl")
    rows = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert rows and "safety" in rows[0]
    rows[0]["safety"].pop("network_connection")
    modified = tmp_path / "missing_safety_field.jsonl"
    modified.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    outcome = run_audit_bundle(
        events_path=str(modified),
        rules_dir="sigma/rules",
        assumptions_dir="assumptions/examples",
        out_dir=str(tmp_path / "audit"),
        verbose=False,
    )
    assert outcome.get("ok") is False


def test_brittleness_evaluator_exception_cannot_mean_zero_brittleness(monkeypatch):
    def failure(*args, **kwargs):
        raise RuntimeError("injected evaluator failure")

    monkeypatch.setattr("core.sigma.evaluator.evaluate_sigma_rule", failure)
    with pytest.raises(RuntimeError, match="injected evaluator failure"):
        validation_cli._score_brittleness("rule.yml", "artifact.jsonl")


def test_mixed_rule_evaluation_error_exits_nonzero(tmp_path, monkeypatch):
    artifact = tmp_path / "events.jsonl"
    artifact.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(validation_cli, "_load_rule_paths", lambda _: [Path("good.yml"), Path("bad.yml")])
    monkeypatch.setattr(validation_cli, "_evaluate_rules", lambda *_: {
        "good.yml": {"rule_id": "good", "rule_title": "good", "verdict": "TRIGGERED", "triggered": True, "triggered_count": 1},
        "bad.yml": {"rule_id": "bad", "rule_title": "bad", "verdict": "ERROR", "triggered": False, "triggered_count": 0, "error": "injected parse failure"},
    })
    args = SimpleNamespace(
        rules=".", artifact=str(artifact), scenario="unused", mutations=False,
        threshold=0.5, format="json", out=None,
    )
    with pytest.raises(SystemExit) as caught:
        validation_cli.run(args)
    assert caught.value.code != 0
