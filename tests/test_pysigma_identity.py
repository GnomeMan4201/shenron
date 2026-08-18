"""Regression coverage for source-stable Sigma identity across the pySigma bridge."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from core.sigma.pysigma_bridge import _ensure_uuid_id, evaluate_with_pysigma


def _rule_text(rule_id: str | None) -> str:
    id_line = f"id: {rule_id}\n" if rule_id is not None else ""
    return (
        "title: Stable identity test\n"
        f"{id_line}"
        "status: experimental\n"
        "logsource:\n"
        "  category: process_creation\n"
        "  product: windows\n"
        "detection:\n"
        "  selection:\n"
        "    CommandLine|contains: powershell\n"
        "  condition: selection\n"
    )


def _write_artifact(path: Path) -> None:
    path.write_text(
        json.dumps({"command_sim": "powershell -NoProfile"}) + "\n",
        encoding="utf-8",
    )


def _parser_id(transformed_yaml: str) -> str:
    line = next(line for line in transformed_yaml.splitlines() if line.startswith("id:"))
    return line.split(":", 1)[1].strip()


def test_non_uuid_parser_id_is_deterministic():
    source = _rule_text("stable-human-id")

    first = _ensure_uuid_id(source)
    second = _ensure_uuid_id(source)

    assert first == second
    assert str(uuid.UUID(_parser_id(first))) == _parser_id(first)


def test_valid_uuid_parser_id_is_preserved():
    source_id = "5cf82876-4427-4b6f-901e-e7388e3d0944"
    transformed = _ensure_uuid_id(_rule_text(source_id))

    assert _parser_id(transformed) == source_id


def test_missing_id_gets_deterministic_parser_only_uuid():
    source = _rule_text(None)

    first = _ensure_uuid_id(source)
    second = _ensure_uuid_id(source)

    assert first == second
    uuid.UUID(_parser_id(first))


def test_bridge_returns_committed_non_uuid_source_id(tmp_path):
    rule = tmp_path / "source-rule.yml"
    artifact = tmp_path / "events.jsonl"
    rule.write_text(_rule_text("stable-human-id"), encoding="utf-8")
    _write_artifact(artifact)

    first = evaluate_with_pysigma(str(rule), str(artifact))
    second = evaluate_with_pysigma(str(rule), str(artifact))

    assert first.rule_id == "stable-human-id"
    assert second.rule_id == "stable-human-id"


def test_bridge_uses_deterministic_filename_fallback_when_source_id_missing(tmp_path):
    rule = tmp_path / "no-source-id.yml"
    artifact = tmp_path / "events.jsonl"
    rule.write_text(_rule_text(None), encoding="utf-8")
    _write_artifact(artifact)

    first = evaluate_with_pysigma(str(rule), str(artifact))
    second = evaluate_with_pysigma(str(rule), str(artifact))

    assert first.rule_id == "no-source-id"
    assert second.rule_id == "no-source-id"
