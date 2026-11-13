"""Unknown claim keys must be rejected, never silently ignored.

A misspelled requirement key (e.g. `requires_signal`) or scope key
(`evidence_scop`) used to be dropped, which removed a requirement or widened
evidence aggregation. The weakened claim could then report SUPPORTED on
evidence where the correctly spelled claim is UNSUPPORTED.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import warnings

import pytest
import yaml

from core.assumptions.loader import load_assumption
from core.assumptions.model import AssumptionStatus
from core.assumptions.validator import validate_assumption

ROOT = Path(__file__).resolve().parents[1]

# Technique present; required signal absent from the same artifact set.
EVIDENCE_SIGNAL_MISSING = [{"artifact_id": "a", "mitre_techniques": ["T1059"],
                            "behavior_class": "other_thing"}]
# Technique and signal present, but in different artifacts.
EVIDENCE_SPLIT = [{"artifact_id": "a", "mitre_techniques": ["T1059"]},
                  {"artifact_id": "b", "behavior_class": "script_execution_sim"}]

CASES = {
    "requires_signal_singular": (
        {"id": "c", "type": "positive_evidence", "requires_techniques": ["T1059"],
         "requires_signal": ["script_execution_sim"]},
        {"id": "c", "type": "positive_evidence", "requires_techniques": ["T1059"],
         "requires_signals": ["script_execution_sim"]},
        EVIDENCE_SIGNAL_MISSING,
    ),
    "evidence_scop_typo": (
        {"id": "c", "type": "positive_evidence", "evidence_scop": "same_artifact",
         "requires_techniques": ["T1059"], "requires_signals": ["script_execution_sim"]},
        {"id": "c", "type": "positive_evidence", "evidence_scope": "same_artifact",
         "requires_techniques": ["T1059"], "requires_signals": ["script_execution_sim"]},
        EVIDENCE_SPLIT,
    ),
    "requires_technique_singular": (
        {"id": "c", "type": "positive_evidence", "requires_signals": ["script_execution_sim"],
         "requires_technique": ["T1003"]},
        {"id": "c", "type": "positive_evidence", "requires_signals": ["script_execution_sim"],
         "requires_techniques": ["T1003"]},
        [{"artifact_id": "a", "behavior_class": "script_execution_sim"}],
    ),
}


def _files(tmp_path, claim, records):
    assumption = tmp_path / "a.yaml"
    assumption.write_text(yaml.safe_dump({
        "id": "probe", "schema_version": "1.0", "description": "probe", "claims": [claim],
    }), encoding="utf-8")
    events = tmp_path / "e.jsonl"
    events.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    return assumption, events


@pytest.mark.parametrize("name", list(CASES))
def test_correct_spelling_control_is_not_supported(tmp_path, name):
    _, correct, records = CASES[name]
    assumption, events = _files(tmp_path, correct, records)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        result = validate_assumption(assumption, events)
    assert result.status != AssumptionStatus.SUPPORTED


@pytest.mark.parametrize("name", list(CASES))
def test_library_route_rejects_unknown_claim_key(tmp_path, name):
    typo, _, records = CASES[name]
    assumption, events = _files(tmp_path, typo, records)
    with pytest.raises(ValueError, match="unknown claim key"):
        validate_assumption(assumption, events)


@pytest.mark.parametrize("name", list(CASES))
def test_loader_rejects_unknown_claim_key_on_every_route(tmp_path, name):
    typo, _, records = CASES[name]
    assumption, _ = _files(tmp_path, typo, records)
    for strict in (False, True):
        with pytest.raises(ValueError, match="unknown claim key"):
            load_assumption(assumption, require_current_schema=strict)


@pytest.mark.parametrize("name", list(CASES))
def test_cli_exits_malformed_input_code(tmp_path, name):
    typo, _, records = CASES[name]
    assumption, events = _files(tmp_path, typo, records)
    env = os.environ.copy()
    env.update(SHENRON_HOME=str(tmp_path / "home"), SHENRON_REPORT_DIR=str(tmp_path / "reports"),
               PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(
        [sys.executable, str(ROOT / "shenron.py"), "assumption", "validate",
         str(assumption), "--events", str(events)],
        cwd=ROOT, env=env, text=True, capture_output=True, timeout=30, check=False)
    assert result.returncode == 3, (result.returncode, result.stdout[-400:], result.stderr[-400:])


def test_all_known_claim_keys_still_accepted(tmp_path):
    claim = {"id": "c", "type": "positive_evidence", "severity": "high", "description": "d",
             "requires_techniques": ["T1059"], "requires_signals": ["script_execution_sim"],
             "requires_metrics": [], "evidence_scope": "same_artifact"}
    assumption, _ = _files(tmp_path, claim, [])
    _, _, claims = load_assumption(assumption, require_current_schema=True)
    assert [c.id for c in claims] == ["c"]
