"""
tests/test_cef_adapter.py

Tests for core/formats/cef_adapter.py — CEF (Common Event Format) adapter.
"""
import json
import tempfile
from pathlib import Path
import pytest
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.formats.cef_adapter import (
    to_cef,
    records_to_cef,
    write_cef,
    cef_summary,
    _cef_escape,
    _ext_escape,
    _epoch_ms,
    _resolve_tactic,
    _resolve_severity,
    CEF_VERSION,
    CEF_VENDOR,
    CEF_PRODUCT,
    CEF_DEV_VER,
)

DEMO_ARTIFACT    = Path(__file__).parent.parent / "artifacts" / "demo" / "shenron_demo_run.jsonl"
LLM_ARTIFACT     = Path(__file__).parent.parent / "artifacts" / "llm_manipulation" / "scenario_run.jsonl"
WINDOWS_ARTIFACT = Path(__file__).parent.parent / "artifacts" / "windows_events" / "scenario_run.jsonl"

SAMPLE_EVENT = {
    "artifact_id": "test-cef-001",
    "session_id": "sess-cef-001",
    "layer": "beacon_emitter_cloak",
    "phase": "OBSERVE",
    "behavior_class": "periodic_beacon_to_external_host",
    "detection_opportunities": ["periodic_beacon_to_external_host"],
    "mitre_techniques": ["T1071", "T1132"],
    "signal": "beacon_signal",
    "simulation_only": True,
    "executable": False,
    "timestamp": "2026-06-25T00:00:00+00:00",
}

WINDOWS_EVENT = {
    "artifact_id": "test-win-001",
    "session_id": "sess-win-001",
    "layer": "windows_event_log_sim",
    "phase": "SIMULATE",
    "behavior_class": "scheduled_task_creation_sim",
    "EventID": 4698,
    "Channel": "Security",
    "Provider_Name": "Microsoft-Windows-Security-Auditing",
    "TaskName": "\\WindowsUpdate_beacon_sim",
    "mitre_techniques": ["T1053", "T1053.005"],
    "detection_opportunities": ["scheduled_task_created_non_admin_tool"],
    "simulation_only": True,
    "executable": False,
    "timestamp": "2026-06-25T00:01:00+00:00",
}


# -- Constants -----------------------------------------------------------------

def test_cef_version():
    assert CEF_VERSION == "0"

def test_cef_vendor():
    assert "badBANANA" in CEF_VENDOR or "SHENRON" in CEF_VENDOR

def test_cef_product():
    assert CEF_PRODUCT == "SHENRON"


# -- Escape functions ----------------------------------------------------------

def test_cef_escape_pipe():
    assert "\\|" in _cef_escape("a|b")

def test_cef_escape_backslash():
    result = _cef_escape("a\\b")
    assert "\\\\" in result

def test_cef_escape_equals():
    assert "\\=" in _cef_escape("a=b")

def test_cef_escape_newline():
    assert "\n" not in _cef_escape("a\nb")

def test_ext_escape_equals():
    assert "\\=" in _ext_escape("key=value")

def test_ext_escape_preserves_normal():
    assert _ext_escape("normal text") == "normal text"


# -- Epoch conversion ----------------------------------------------------------

def test_epoch_ms_valid():
    result = _epoch_ms("2026-06-25T00:00:00+00:00")
    assert result.isdigit()
    assert len(result) == 13  # milliseconds since epoch

def test_epoch_ms_invalid_fallback():
    result = _epoch_ms("not-a-timestamp")
    assert result.isdigit()


# -- Tactic resolution ---------------------------------------------------------

def test_resolve_tactic_c2():
    assert _resolve_tactic(["T1071"]) == "command-and-control"

def test_resolve_tactic_persistence():
    assert _resolve_tactic(["T1053"]) == "persistence"

def test_resolve_tactic_exfil():
    assert _resolve_tactic(["T1041"]) == "exfiltration"

def test_resolve_tactic_unknown():
    assert _resolve_tactic(["T9999"]) == "unknown"

def test_resolve_tactic_empty():
    assert _resolve_tactic([]) == "unknown"

def test_resolve_tactic_subtechnique():
    assert _resolve_tactic(["T1053.005"]) == "persistence"


# -- Severity resolution -------------------------------------------------------

def test_resolve_severity_default():
    result = _resolve_severity(SAMPLE_EVENT)
    assert result.isdigit()
    assert 0 <= int(result) <= 10

def test_resolve_severity_exfil_phase():
    ev = dict(SAMPLE_EVENT)
    ev["phase"] = "EXFILTRATE"
    result = _resolve_severity(ev)
    assert int(result) >= 7

def test_resolve_severity_recon_phase():
    ev = dict(SAMPLE_EVENT)
    ev["phase"] = "RECONNAISSANCE"
    result = _resolve_severity(ev)
    assert int(result) >= 4


# -- CEF line format -----------------------------------------------------------

def test_to_cef_starts_with_cef():
    line = to_cef(SAMPLE_EVENT)
    assert line.startswith("CEF:0|")

def test_to_cef_has_eight_pipe_sections():
    line = to_cef(SAMPLE_EVENT)
    parts = line.split("|")
    assert len(parts) >= 8

def test_to_cef_vendor_field():
    line = to_cef(SAMPLE_EVENT)
    parts = line.split("|")
    assert parts[1] == CEF_VENDOR

def test_to_cef_product_field():
    line = to_cef(SAMPLE_EVENT)
    parts = line.split("|")
    assert parts[2] == CEF_PRODUCT

def test_to_cef_version_field():
    line = to_cef(SAMPLE_EVENT)
    parts = line.split("|")
    assert parts[3] == CEF_DEV_VER

def test_to_cef_signature_id():
    line = to_cef(SAMPLE_EVENT)
    parts = line.split("|")
    assert "T1071" in parts[4]

def test_to_cef_name_contains_behavior():
    line = to_cef(SAMPLE_EVENT)
    parts = line.split("|")
    assert "periodic_beacon" in parts[5] or "beacon" in parts[5]

def test_to_cef_severity_numeric():
    line = to_cef(SAMPLE_EVENT)
    parts = line.split("|")
    assert parts[6].isdigit()
    assert 0 <= int(parts[6]) <= 10

def test_to_cef_extension_has_rt():
    line = to_cef(SAMPLE_EVENT)
    assert "rt=" in line

def test_to_cef_extension_has_act():
    line = to_cef(SAMPLE_EVENT)
    assert "act=" in line

def test_to_cef_extension_has_cat():
    line = to_cef(SAMPLE_EVENT)
    assert "cat=" in line

def test_to_cef_extension_has_msg():
    line = to_cef(SAMPLE_EVENT)
    assert "msg=" in line

def test_to_cef_extension_has_custom_strings():
    line = to_cef(SAMPLE_EVENT)
    assert "cs1=" in line
    assert "cs1Label=" in line

def test_to_cef_extension_has_mitre():
    line = to_cef(SAMPLE_EVENT)
    assert "T1071" in line or "T1132" in line

def test_to_cef_simulation_only_in_extension():
    line = to_cef(SAMPLE_EVENT)
    assert "simulation_only" in line

def test_to_cef_windows_event_has_eventid():
    line = to_cef(WINDOWS_EVENT)
    assert "EventID" in line or "4698" in line

def test_to_cef_no_unescaped_pipe_in_extension():
    line = to_cef(SAMPLE_EVENT)
    # The extension (after 7th pipe) should not have unescaped pipes
    parts = line.split("|", 7)
    extension = parts[7] if len(parts) > 7 else ""
    # Count unescaped pipes in extension
    unescaped = len(re.findall(r"(?<!\\)\|", extension))
    assert unescaped == 0

def test_to_cef_returns_string():
    assert isinstance(to_cef(SAMPLE_EVENT), str)

def test_to_cef_no_newline():
    line = to_cef(SAMPLE_EVENT)
    assert "\n" not in line
    assert "\r" not in line


# -- Bulk conversion -----------------------------------------------------------

def test_records_to_cef_returns_list():
    result = records_to_cef([SAMPLE_EVENT, WINDOWS_EVENT])
    assert isinstance(result, list)
    assert len(result) == 2

def test_records_to_cef_all_valid():
    result = records_to_cef([SAMPLE_EVENT, WINDOWS_EVENT])
    for line in result:
        assert line.startswith("CEF:0|")


# -- Write CEF -----------------------------------------------------------------

def test_write_cef_creates_file():
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/test.cef"
        n = write_cef([SAMPLE_EVENT], path)
        assert Path(path).exists()
        assert n == 1

def test_write_cef_valid_lines():
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/test.cef"
        write_cef([SAMPLE_EVENT, WINDOWS_EVENT], path)
        lines = Path(path).read_text().splitlines()
        assert len(lines) == 2
        for line in lines:
            assert line.startswith("CEF:")

def test_write_cef_creates_parent_dirs():
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/nested/deep/test.cef"
        write_cef([SAMPLE_EVENT], path)
        assert Path(path).exists()

def test_write_cef_demo_artifact():
    if not DEMO_ARTIFACT.exists():
        pytest.skip("Demo artifact not present")
    with open(DEMO_ARTIFACT) as f:
        records = [json.loads(l) for l in f if l.strip()]
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/demo.cef"
        n = write_cef(records, path)
        assert n == len(records)
        summary = cef_summary(path)
        assert summary["cef_compliant"] is True


# -- CEF summary ---------------------------------------------------------------

def test_cef_summary_nonexistent():
    result = cef_summary("/nonexistent/path.cef")
    assert result["exists"] is False

def test_cef_summary_existing():
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/test.cef"
        write_cef([SAMPLE_EVENT, WINDOWS_EVENT], path)
        summary = cef_summary(path)
        assert summary["exists"] is True
        assert summary["lines"] == 2
        assert summary["cef_compliant"] is True
        assert summary["size_bytes"] > 0

def test_cef_summary_llm_artifact():
    if not LLM_ARTIFACT.exists():
        pytest.skip("LLM artifact not present")
    with open(LLM_ARTIFACT) as f:
        records = [json.loads(l) for l in f if l.strip()]
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/llm.cef"
        write_cef(records, path)
        summary = cef_summary(path)
        assert summary["cef_compliant"] is True
        assert summary["lines"] == len(records)


import re
