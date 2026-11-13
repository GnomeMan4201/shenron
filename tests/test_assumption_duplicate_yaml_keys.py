"""Duplicate YAML keys must be rejected in assumption files.

PyYAML keeps the last value of a duplicated mapping key without complaint. A
requirement visible in the file (`requires_signals: [x]`, or a whole `claims:`
list) could therefore be erased by a later duplicate, while every key is still
a known key, and the weakened claim reported SUPPORTED.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import warnings

import pytest

from core.assumptions.loader import load_assumption
from core.assumptions.model import AssumptionStatus
from core.assumptions.validator import validate_assumption

ROOT = Path(__file__).resolve().parents[1]
HEAD = 'id: probe\nschema_version: "1.0"\ndescription: probe\n'
# Technique present; the required signal is absent.
EVIDENCE = [{"artifact_id": "a", "mitre_techniques": ["T1059"], "behavior_class": "other_thing"}]

CONTROL = HEAD + ("claims:\n  - id: c\n    type: positive_evidence\n"
                  "    requires_techniques: [T1059]\n    requires_signals: [script_execution_sim]\n")
DUPLICATES = {
    "claim_key_last_empty": HEAD + (
        "claims:\n  - id: c\n    type: positive_evidence\n    requires_techniques: [T1059]\n"
        "    requires_signals: [script_execution_sim]\n    requires_signals: []\n"),
    "claims_list_last_weaker": HEAD + (
        "claims:\n  - id: c\n    type: positive_evidence\n    requires_techniques: [T1059]\n"
        "    requires_signals: [script_execution_sim]\n"
        "claims:\n  - id: c\n    type: positive_evidence\n    requires_techniques: [T1059]\n"),
    "claim_type_overridden": HEAD + (
        "claims:\n  - id: c\n    type: out_of_scope\n    type: positive_evidence\n"
        "    requires_techniques: [T1059]\n"),
    "document_id_duplicated": HEAD + "id: other\n" + CONTROL[len(HEAD):],
}


def _files(tmp_path, text):
    assumption = tmp_path / "a.yaml"
    assumption.write_text(text, encoding="utf-8")
    events = tmp_path / "e.jsonl"
    events.write_text("".join(json.dumps(r) + "\n" for r in EVIDENCE), encoding="utf-8")
    return assumption, events


def test_control_without_duplicates_is_not_supported(tmp_path):
    assumption, events = _files(tmp_path, CONTROL)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        assert validate_assumption(assumption, events).status != AssumptionStatus.SUPPORTED


@pytest.mark.parametrize("name", list(DUPLICATES))
def test_library_route_rejects_duplicate_keys(tmp_path, name):
    assumption, events = _files(tmp_path, DUPLICATES[name])
    with pytest.raises(ValueError, match="duplicate key"):
        validate_assumption(assumption, events)


@pytest.mark.parametrize("name", list(DUPLICATES))
def test_loader_rejects_duplicate_keys_in_both_modes(tmp_path, name):
    assumption, _ = _files(tmp_path, DUPLICATES[name])
    for strict in (False, True):
        with pytest.raises(ValueError, match="duplicate key"):
            load_assumption(assumption, require_current_schema=strict)


@pytest.mark.parametrize("name", list(DUPLICATES))
def test_cli_exits_malformed_input_code(tmp_path, name):
    assumption, events = _files(tmp_path, DUPLICATES[name])
    env = os.environ.copy()
    env.update(SHENRON_HOME=str(tmp_path / "home"), SHENRON_REPORT_DIR=str(tmp_path / "reports"),
               PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(
        [sys.executable, str(ROOT / "shenron.py"), "assumption", "validate",
         str(assumption), "--events", str(events)],
        cwd=ROOT, env=env, text=True, capture_output=True, timeout=30, check=False)
    assert result.returncode == 3, (result.returncode, result.stdout[-300:], result.stderr[-300:])


def test_merge_key_with_explicit_override_is_still_valid_yaml(tmp_path):
    # A YAML merge key plus an explicit key is not a duplicate: explicit wins by spec.
    text = HEAD + ("claims:\n  - id: c\n    type: positive_evidence\n"
                   "    requires_techniques: [T1059]\n    requires_signals: [script_execution_sim]\n"
                   "    <<: {requires_signals: []}\n")
    assumption, events = _files(tmp_path, text)
    _, _, claims = load_assumption(assumption, require_current_schema=True)
    assert claims[0].requires_signals == ["script_execution_sim"]
