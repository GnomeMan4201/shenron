"""Regression tests for adaptation evaluation and rule-ID integrity."""

from pathlib import Path
from types import SimpleNamespace

import pytest

import core.campaign.adaptation as adaptation


def _write_rule(path: Path, rule_id: str, field: str, value: str) -> Path:
    path.write_text(
        "\n".join(
            [
                f"title: Test {rule_id}",
                f"id: {rule_id}",
                "status: experimental",
                "logsource:",
                "  category: process_creation",
                "  product: windows",
                "detection:",
                "  selection:",
                f"    {field}: '{value}'",
                "  condition: selection",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


def test_evaluate_rules_fails_closed_on_metadata_error():
    missing_rule = Path("definitely-missing-rule.yml")

    with pytest.raises(RuntimeError, match="Unable to load Sigma rule metadata"):
        adaptation._evaluate_rules([missing_rule], "artifact.jsonl")


def test_evaluate_rules_fails_closed_on_evaluator_error(monkeypatch, tmp_path):
    rule_path = _write_rule(
        tmp_path / "broken.yml",
        "stable-rule-id",
        "CommandLine",
        "powershell",
    )

    def explode(*args, **kwargs):
        raise ValueError("synthetic evaluator failure")

    monkeypatch.setattr(adaptation, "evaluate_sigma_rule", explode)

    with pytest.raises(RuntimeError, match=r"Sigma evaluation failed.*broken\.yml"):
        adaptation._evaluate_rules([rule_path], "artifact.jsonl")


def test_evaluate_rules_preserves_source_id_over_parser_id(monkeypatch, tmp_path):
    rule_path = _write_rule(
        tmp_path / "source.yml",
        "stable-source-id",
        "CommandLine",
        "powershell",
    )
    parser_result = SimpleNamespace(
        rule_id="9f58586e-740d-4f9e-b59f-3ee170d4e302",
        rule_title="Parser title",
        verdict=adaptation.RuleVerdict.TRIGGERED,
    )
    monkeypatch.setattr(
        adaptation,
        "evaluate_sigma_rule",
        lambda *args, **kwargs: parser_result,
    )

    results = adaptation._evaluate_rules([rule_path], "artifact.jsonl")

    assert len(results) == 1
    assert results[0].rule_id == "stable-source-id"
    assert results[0].rule_title == "Test stable-source-id"
    assert results[0].triggered is True


def test_strategy_scoring_resolves_rule_id_from_metadata_not_filename(tmp_path):
    command_rule = _write_rule(
        tmp_path / "first.yml",
        "rule-alpha",
        "CommandLine",
        "powershell",
    )
    task_rule = _write_rule(
        tmp_path / "second.yml",
        "rule-beta",
        "TaskName",
        "Updater",
    )

    rule_paths = [command_rule, task_rule]
    still_firing = {"rule-alpha"}

    assert adaptation._score_strategy_for_firing_rules(
        "sigma_aware_unicode", still_firing, rule_paths
    ) == 1
    assert adaptation._score_strategy_for_firing_rules(
        "sigma_aware_whitespace", still_firing, rule_paths
    ) == 0


def test_unknown_firing_rule_id_fails_closed(tmp_path):
    rule_path = _write_rule(
        tmp_path / "rule.yml",
        "known-rule",
        "CommandLine",
        "powershell",
    )

    with pytest.raises(ValueError, match="Unable to resolve firing Sigma rule IDs: missing-rule"):
        adaptation._score_strategy_for_firing_rules(
            "sigma_aware_unicode", {"missing-rule"}, [rule_path]
        )


def test_duplicate_firing_rule_id_is_rejected_as_ambiguous(tmp_path):
    first = _write_rule(
        tmp_path / "first.yml",
        "duplicate-rule",
        "CommandLine",
        "powershell",
    )
    second = _write_rule(
        tmp_path / "second.yml",
        "duplicate-rule",
        "TaskName",
        "Updater",
    )

    with pytest.raises(ValueError, match="Ambiguous firing Sigma rule IDs"):
        adaptation._score_strategy_for_firing_rules(
            "sigma_aware_unicode", {"duplicate-rule"}, [first, second]
        )
