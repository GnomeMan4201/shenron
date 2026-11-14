"""Red-first: evidence-side inputs must never let a prohibited technique pass as absent.

Follow-up to reviewer C1. On main @ 79a4f67 each payload below, appended to
otherwise valid identity evidence, still produced a qualified SUPPORTED verdict
(ALL SUPPORTED, exit 0 through the seven-category CLI), while the exact form
{"mitre_techniques":["T1041"]} was correctly reported as out of scope.

Kill criterion: no malformed, duplicated, or explicitly prohibited technique
evidence may yield SUPPORTED. Controls ensure the correction does not simply
make every input fail.

Syntax validation of technique IDs establishes only their *form*. It does not
establish that an ID exists in ATT&CK or that its mapping is appropriate.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from core.assumptions import validator
from core.assumptions.model import AssumptionStatus, ClaimStatus
from core.ingest.jsonl import ArtifactInputError, load_jsonl_objects

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = ROOT / "assumptions/examples/identity_spoofing_coverage.yaml"
GOOD = {
    "mitre_techniques": ["T1542"],
    "detection_opportunities": [
        "bios_log_forge_sim", "bios_tamper_log_write_sim",
        "multi_identity_emit_sim", "trusted_name_rename_sim",
    ],
}
FIRMWARE_CLAIMS = {"firmware_log_forgery_evidence", "firmware_tamper_evidence"}

# Prohibited technique, written in a form that must be *recognized* as T1041/T1048.
RECOGNIZED_PROHIBITED = {
    "leading_space": '{"mitre_techniques":[" T1041"]}',
    "trailing_space": '{"technique":"T1041 "}',
    "subtechnique_of_prohibited": '{"mitre_techniques":["T1048.003"]}',
    "singular_field_list": '{"mitre_technique":["T1041"]}',
    "singular_field_string": '{"mitre_technique":"T1041"}',
}
# Inputs that cannot be interpreted and must be rejected as input errors.
REJECTED = {
    "duplicate_key": ('{"mitre_techniques":["T1041"],"mitre_techniques":[]}', "duplicate"),
    "duplicate_nested_key": ('{"meta":{"note":"a","note":"b"},"phase":"x"}', "duplicate"),
    "wrong_case_field": ('{"MITRE_techniques":["T1041"]}', "MITRE_techniques"),
    "wrong_case_singular": ('{"MITRE_technique":"T1041"}', "MITRE_technique"),
    "separator_variant": ('{"mitre-techniques":["T1041"]}', "mitre-techniques"),
    "wrong_case_signal_field": ('{"Phase":"exfil"}', "Phase"),
    "malformed_id_suffix": ('{"mitre_techniques":["T1041x"]}', "T1041x"),
    "malformed_id_short": ('{"mitre_techniques":["T104"]}', "T104"),
    "malformed_sub_id": ('{"mitre_techniques":["T1048.3"]}', "T1048.3"),
    "non_id_technique": ('{"technique":"exfil_over_c2"}', "exfil_over_c2"),
    "blank_id": ('{"techniques":["  "]}', "techniques"),
}


def _jsonl(tmp_path, *records, name="evidence.jsonl"):
    path = tmp_path / name
    path.write_text("\n".join(records) + "\n", encoding="utf-8")
    return path


# ── library: controls ────────────────────────────────────────────────────────

def test_control_clean_evidence_supported(tmp_path):
    result = validator.validate_assumption(IDENTITY, _jsonl(tmp_path, json.dumps(GOOD)))
    assert result.status == AssumptionStatus.SUPPORTED


@pytest.mark.parametrize("record", [
    '{"mitre_techniques":["T1027","T1036.005"]}',
    '{"technique":"T1036"}',
    '{"mitre_technique":"T1071.001"}',
    '{"unrelated_field":"T1041"}',
])
def test_control_genuine_absence_still_supported(tmp_path, record):
    result = validator.validate_assumption(IDENTITY, _jsonl(tmp_path, json.dumps(GOOD), record))
    assert result.status == AssumptionStatus.SUPPORTED, result.out_of_scope_violations


@pytest.mark.parametrize("record", [
    '{"mitre_techniques":["T1041"]}',
    '{"mitre_techniques":["t1048"]}',
])
def test_control_exact_prohibited_still_detected(tmp_path, record):
    result = validator.validate_assumption(IDENTITY, _jsonl(tmp_path, json.dumps(GOOD), record))
    assert result.status == AssumptionStatus.OUT_OF_SCOPE_VIOLATION


def test_control_subtechnique_does_not_satisfy_positive_parent(tmp_path):
    """The parent→sub-technique rule is for absence checks only."""
    good = dict(GOOD, mitre_techniques=["T1542.001"])
    result = validator.validate_assumption(IDENTITY, _jsonl(tmp_path, json.dumps(good)))
    firmware = [r for r in result.claim_results if r.claim.id in FIRMWARE_CLAIMS]
    assert firmware and all(r.status != ClaimStatus.SUPPORTED for r in firmware)
    assert result.status != AssumptionStatus.SUPPORTED


# ── library: payloads ────────────────────────────────────────────────────────

@pytest.mark.parametrize("record", RECOGNIZED_PROHIBITED.values(), ids=RECOGNIZED_PROHIBITED.keys())
def test_prohibited_technique_variant_is_detected(tmp_path, record):
    result = validator.validate_assumption(IDENTITY, _jsonl(tmp_path, json.dumps(GOOD), record))
    assert result.status == AssumptionStatus.OUT_OF_SCOPE_VIOLATION


@pytest.mark.parametrize("record,diagnostic", REJECTED.values(), ids=REJECTED.keys())
def test_uninterpretable_evidence_is_rejected(tmp_path, record, diagnostic):
    with pytest.raises(ValueError, match=diagnostic) as exc:
        validator.validate_assumption(IDENTITY, _jsonl(tmp_path, json.dumps(GOOD), record))
    assert "line 2" in str(exc.value)


def test_shared_loader_rejects_nested_duplicates_for_all_consumers(tmp_path):
    """Sigma ingestion uses the same loader; duplicates must not reach it either."""
    path = _jsonl(tmp_path, '{"a":{"b":{"c":1,"c":2}}}')
    with pytest.raises(ArtifactInputError, match=r"duplicate.*'c'.*line 1"):
        load_jsonl_objects(path)


# ── real CLI: seven-category gate and individual qualified validation ───────

def _cli(*args):
    proc = subprocess.run(
        [sys.executable, "shenron.py", *args],
        cwd=ROOT, capture_output=True, text=True, timeout=600,
    )
    return proc.returncode, proc.stdout + proc.stderr


@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    """Real seven-category generation, made deterministic for identity.

    Fresh identity generation is not repeatable (about 7/25 local runs were
    PARTIALLY SUPPORTED on main @ 79a4f67; see the repeatability census in
    draft #50). One known-good identity record is appended so the clean
    baseline is stable; every other category is used exactly as generated.
    """
    out = tmp_path_factory.mktemp("seven_categories")
    _cli("--validate-all-assumptions", "--scope-dir", str(out))
    with open(out / "shenron_identity.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(GOOD) + "\n")
    code, text = _cli("--validate-all-assumptions", "--no-rerun", "--scope-dir", str(out))
    assert code == 0 and "ALL SUPPORTED" in text, text[-2000:]
    return out


def _seven_with(tmp_path, generated, extra):
    scope = tmp_path / "scope"
    shutil.copytree(generated, scope)
    with open(scope / "shenron_identity.jsonl", "a", encoding="utf-8") as fh:
        fh.write(extra + "\n")
    return _cli("--validate-all-assumptions", "--no-rerun", "--scope-dir", str(scope))


@pytest.mark.parametrize("record", [
    '{"mitre_techniques":["T1027"]}',
    '{"unrelated_field":"T1041"}',
])
def test_cli_control_genuine_absence_all_supported(tmp_path, generated, record):
    code, text = _seven_with(tmp_path, generated, record)
    assert code == 0 and "ALL SUPPORTED" in text, text[-1500:]


_ALL_PAYLOADS = {**RECOGNIZED_PROHIBITED, **{k: v[0] for k, v in REJECTED.items()}}


@pytest.mark.parametrize("record", _ALL_PAYLOADS.values(), ids=_ALL_PAYLOADS.keys())
def test_cli_seven_category_gate_never_green(tmp_path, generated, record):
    code, text = _seven_with(tmp_path, generated, record)
    assert code != 0, text[-1500:]
    assert "ALL SUPPORTED" not in text


@pytest.mark.parametrize("record", _ALL_PAYLOADS.values(), ids=_ALL_PAYLOADS.keys())
def test_cli_assumption_validate_never_supported(tmp_path, generated, record):
    events = tmp_path / "identity.jsonl"
    events.write_text((generated / "shenron_identity.jsonl").read_text() + record + "\n")
    code, text = _cli("assumption", "validate", str(IDENTITY), "--events", str(events))
    assert code != 0, text[-1500:]
    assert "STATUS:     SUPPORTED" not in text
