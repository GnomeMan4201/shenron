"""Red-first Issue #63: canonical YAML keys and required evidence provenance.

Runtime: Python 3.10–3.12; dependencies: pytest, PyYAML, project package.
[needs Linux runner] Passive local synthetic fixtures only.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from core.assumptions.legacy import documented_builtin_legacy_exclusion
from core.assumptions.loader import load_artifacts, load_assumption
from core.assumptions.model import AssumptionStatus
from core.assumptions.validator import validate_assumption


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "assumptions" / "examples"
KNOWN_LEGACY = {"c2_lateral_coverage.yaml", "assumption_dependency_confusion.yaml"}


def fixture(tmp_path):
    document = {
        "schema_version": "1.0",
        "id": "issue63",
        "description": "local synthetic test",
        "claims": [{
            "id": "signal_positive", "type": "positive_evidence",
            "requires_signals": ["expected_signal"],
        }],
    }
    yaml_path = tmp_path / "assumption.yaml"
    evidence = tmp_path / "evidence.jsonl"
    evidence.write_text(json.dumps({"behavior_class": "expected_signal"}) + "\n", encoding="utf-8")
    yaml_path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return document, yaml_path, evidence


@pytest.mark.parametrize("bad_field", [
    "claim", "claimes", "descriptionn", "schema_versoin", "surprise_field",
])
@pytest.mark.parametrize("strict", [False, True], ids=["legacy-loader", "qualified-loader"])
def test_unknown_document_key_rejected_on_both_loader_routes(tmp_path, bad_field, strict):
    document, path, _ = fixture(tmp_path)
    if bad_field == "claim":
        document["claim"] = document.pop("claims")
    elif bad_field == "schema_versoin":
        document["schema_versoin"] = document.pop("schema_version")
    else:
        document[bad_field] = "unexpected"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown (top-level|document) key"):
        load_assumption(path, require_current_schema=strict)


@pytest.mark.parametrize("bad_field", ["claimes", "descriptionn"])
def test_document_typo_is_not_validated_as_supported(tmp_path, bad_field):
    document, path, evidence = fixture(tmp_path)
    document[bad_field] = "ignored on baseline"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown (top-level|document) key"):
        validate_assumption(path, evidence)


def test_unknown_document_key_cli_is_input_error_without_history(tmp_path):
    document, path, evidence = fixture(tmp_path)
    document["descriptoin"] = "forgotten field"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    home, reports = tmp_path / "home", tmp_path / "reports"
    env = os.environ.copy()
    env.update(SHENRON_HOME=str(home), SHENRON_REPORT_DIR=str(reports),
               PYTHONDONTWRITEBYTECODE="1")
    cmd = [sys.executable, str(ROOT / "shenron.py"), "assumption",
           "validate", str(path), "--events", str(evidence)]
    result = subprocess.run(cmd, cwd=ROOT, env=env, text=True,
                            capture_output=True, timeout=30, check=False)
    assert result.returncode == 3, (result.returncode, result.stdout, result.stderr)
    assert "unknown" in result.stderr.lower()
    assert not (home / "validation_history.jsonl").exists()
    assert not (reports / "assumptions" / "index.md").exists()


@pytest.mark.parametrize("suffix", [".jsonl", ".json"], ids=["jsonl", "graph-json"])
def test_nonexistent_evidence_raises_not_unsupported(tmp_path, suffix):
    _, path, _ = fixture(tmp_path)
    missing = tmp_path / ("not_generated" + suffix)
    assert not missing.exists()
    with pytest.raises(FileNotFoundError, match="not_generated"):
        validate_assumption(path, missing)


@pytest.mark.parametrize("suffix", [".jsonl", ".json"], ids=["jsonl", "graph-json"])
def test_directory_is_not_a_qualified_evidence_file(tmp_path, suffix):
    _, path, _ = fixture(tmp_path)
    directory = tmp_path / ("evidence_directory" + suffix)
    directory.mkdir()
    with pytest.raises((FileNotFoundError, IsADirectoryError), match="evidence_directory"):
        validate_assumption(path, directory)


@pytest.mark.parametrize("suffix", [".jsonl", ".json"], ids=["jsonl", "graph-json"])
def test_existing_empty_evidence_remains_valid_negative(tmp_path, suffix):
    _, path, _ = fixture(tmp_path)
    evidence = tmp_path / ("existing_empty" + suffix)
    evidence.write_text("{}\n" if suffix == ".json" else "", encoding="utf-8")
    result = validate_assumption(path, evidence)
    assert result.status == AssumptionStatus.UNSUPPORTED


def test_existing_nonmatching_evidence_is_real_unsupported_result(tmp_path):
    _, path, evidence = fixture(tmp_path)
    evidence.write_text(json.dumps({"behavior_class": "other_signal"}) + "\n", encoding="utf-8")
    result = validate_assumption(path, evidence)
    assert result.status == AssumptionStatus.UNSUPPORTED


def test_general_purpose_optional_artifact_loading_retains_empty_default(tmp_path):
    # Issue #63 is about *qualified validation*; reporting's optional loader
    # still maps absent log streams to [] until a separate caller contract.
    assert load_artifacts(tmp_path / "optional_report_log.jsonl") == []


def test_seventeen_canonical_files_and_two_exact_legacy_exclusions():
    paths = sorted(EXAMPLES.glob("*.yaml"))
    assert len(paths) == 19
    assert {p.name for p in paths if documented_builtin_legacy_exclusion(p, EXAMPLES)} == KNOWN_LEGACY
    for path in paths:
        if path.name in KNOWN_LEGACY:
            continue
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert set(document) <= {"id", "schema_version", "description", "claims"}
        assert load_assumption(path)[2], path.name
