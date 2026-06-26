"""
core/formats/cef_adapter.py

SHENRON CEF (Common Event Format) Adapter.

Converts SHENRON JSONL telemetry to ArcSight CEF format, used by:
  - Micro Focus / OpenText ArcSight
  - IBM QRadar (CEF input)
  - HP ArcSight Logger
  - Many enterprise SIEM appliances

CEF format specification:
  CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

Extension key-value pairs follow ArcSight CEF field naming conventions:
  act, app, cat, cs1/cs1Label, deviceAction, dvc, dvchost,
  msg, outcome, rt, shost, spt, src, suser,
  cs1-cs6 (custom strings), cn1-cn3 (custom numbers)

Reference: https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/cef-implementation-standard/

Design constraints:
- New file only. Zero modifications to existing core files.
- No subprocess, no network calls.
- All output events preserve simulation_only provenance in CEF extension fields.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

CEF_VERSION    = "0"
CEF_VENDOR     = "badBANANA Research Collective"
CEF_PRODUCT    = "SHENRON"
CEF_DEV_VER    = "0.4.2"

# CEF severity: 0-3 Low, 4-6 Medium, 7-8 High, 9-10 Very High
_SEVERITY_MAP = {
    "critical": "10",
    "high":     "8",
    "medium":   "5",
    "low":      "2",
    "info":     "0",
    "unknown":  "3",
}

# MITRE tactic -> CEF deviceAction
_TACTIC_ACTION = {
    "command-and-control": "C2 Callback",
    "exfiltration":        "Data Exfiltration",
    "lateral-movement":    "Lateral Movement",
    "persistence":         "Persistence Established",
    "privilege-escalation":"Privilege Escalation",
    "defense-evasion":     "Defense Evasion",
    "execution":           "Code Execution",
    "collection":          "Data Collection",
    "discovery":           "Reconnaissance",
    "impact":              "Impact",
    "unknown":             "Simulation Event",
}

# MITRE technique -> tactic (abbreviated)
_TECH_TACTIC = {
    "T1071": "command-and-control",
    "T1095": "command-and-control",
    "T1132": "command-and-control",
    "T1572": "command-and-control",
    "T1573": "command-and-control",
    "T1041": "exfiltration",
    "T1048": "exfiltration",
    "T1021": "lateral-movement",
    "T1570": "lateral-movement",
    "T1053": "persistence",
    "T1543": "persistence",
    "T1547": "persistence",
    "T1055": "privilege-escalation",
    "T1134": "privilege-escalation",
    "T1027": "defense-evasion",
    "T1036": "defense-evasion",
    "T1070": "defense-evasion",
    "T1140": "defense-evasion",
    "T1059": "execution",
    "T1485": "impact",
    "T1565": "impact",
    "T1046": "discovery",
    "T1082": "discovery",
    "T1590": "discovery",
    "T1190": "execution",
}


def _cef_escape(value: str) -> str:
    """Escape CEF header field special characters."""
    value = str(value)
    value = value.replace("\\", "\\\\")
    value = value.replace("|",   "\\|")
    value = value.replace("=",   "\\=")
    value = value.replace("\n", " ")
    value = value.replace("\r", " ")
    return value


def _ext_escape(value: str) -> str:
    """Escape CEF extension field values."""
    value = str(value)
    value = value.replace("\\", "\\\\")
    value = value.replace("=",   "\\=")
    value = value.replace("\n", " ")
    value = value.replace("\r", " ")
    return value


def _epoch_ms(ts_iso: str) -> str:
    """Convert ISO timestamp to epoch milliseconds for CEF rt field."""
    try:
        dt = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
        return str(int(dt.timestamp() * 1000))
    except Exception:
        return str(int(datetime.now(timezone.utc).timestamp() * 1000))


def _resolve_tactic(techniques: list) -> str:
    """Resolve primary tactic from technique list."""
    for tech in techniques:
        parent = tech.split(".")[0]
        if parent in _TECH_TACTIC:
            return _TECH_TACTIC[parent]
    return "unknown"


def _resolve_severity(record: dict) -> str:
    """Resolve CEF severity from record fields."""
    sev = record.get("severity_sim", "").lower()
    if sev in _SEVERITY_MAP:
        return _SEVERITY_MAP[sev]
    phase = record.get("phase", "").upper()
    if phase in ("EXFIL", "EXFILTRATE", "EXFILTRATION_SIM"):
        return "8"
    if phase in ("EXECUTE", "INJECT", "INJECTION_ATTEMPT"):
        return "7"
    if phase in ("RECON", "RECONNAISSANCE"):
        return "4"
    return "5"


def to_cef(record: dict) -> str:
    """
    Convert a single SHENRON JSONL record to a CEF log line.

    Returns a single CEF-formatted string (no trailing newline).
    """
    techniques = record.get("mitre_techniques", [])
    technique_id = techniques[0] if techniques else "T0000"
    tactic = _resolve_tactic(techniques)
    action = _TACTIC_ACTION.get(tactic, "Simulation Event")
    severity = _resolve_severity(record)

    layer    = record.get("layer", "unknown")
    behavior = record.get("behavior_class", layer)
    phase    = record.get("phase", "UNKNOWN")
    session  = record.get("session_id", "")
    artifact = record.get("artifact_id", "")
    ts       = record.get("timestamp", datetime.now(timezone.utc).isoformat())

    # CEF header fields (pipe-delimited, special chars escaped)
    sig_id   = _cef_escape(technique_id)
    name     = _cef_escape(f"{behavior} [{layer}]")
    vendor   = _cef_escape(CEF_VENDOR)
    product  = _cef_escape(CEF_PRODUCT)
    dev_ver  = _cef_escape(CEF_DEV_VER)

    header = f"CEF:{CEF_VERSION}|{vendor}|{product}|{dev_ver}|{sig_id}|{name}|{severity}"

    # CEF extension fields (key=value pairs)
    ext_pairs = [
        f"rt={_epoch_ms(ts)}",
        f"act={_ext_escape(action)}",
        f"cat={_ext_escape(tactic)}",
        f"deviceAction={_ext_escape(action)}",
        f"outcome={_ext_escape('simulation')}",
        f"app={_ext_escape('SHENRON')}",
        f"dvc=shenron-synthetic",
        f"dvchost=shenron-synthetic",
        f"msg={_ext_escape(f'[SHENRON SYNTHETIC] {behavior} phase={phase}')}",
        # Custom strings for SHENRON-specific fields
        f"cs1={_ext_escape(layer)}",
        f"cs1Label=shenron_layer",
        f"cs2={_ext_escape(phase)}",
        f"cs2Label=shenron_phase",
        f"cs3={_ext_escape(session[:64])}",
        f"cs3Label=shenron_session",
        f"cs4={_ext_escape(artifact[:64])}",
        f"cs4Label=shenron_artifact",
        f"cs5={_ext_escape(' '.join(techniques[:5]))}",
        f"cs5Label=mitre_techniques",
        f"cs6={_ext_escape(' '.join(record.get('detection_opportunities', [])[:3]))}",
        f"cs6Label=detection_opps",
        # Custom numbers
        f"cn1={_ext_escape('1')}",
        f"cn1Label=simulation_only",
        f"cn2={_ext_escape('0')}",
        f"cn2Label=executable",
    ]

    # Add Windows Event fields if present
    event_id = record.get("EventID") or record.get("event_id_sim")
    if event_id:
        ext_pairs.append(f"cs1={_ext_escape(str(event_id))}")
        ext_pairs.append(f"cs1Label=EventID")
        channel = record.get("Channel") or record.get("channel_sim", "")
        if channel:
            ext_pairs.append(f"cs2={_ext_escape(channel)}")
            ext_pairs.append(f"cs2Label=Channel")

    extension = " ".join(ext_pairs)
    return f"{header}|{extension}"


def records_to_cef(records: list) -> List[str]:
    """Convert a list of SHENRON records to CEF log lines."""
    return [to_cef(r) for r in records]


def write_cef(records: list, path: str) -> int:
    """
    Write SHENRON records as CEF log lines to a file.
    Returns number of records written.
    Compatible with ArcSight Logger flat file input and syslog forwarders.
    """
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = records_to_cef(records)
    with open(out, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    return len(lines)


def cef_summary(path: str) -> dict:
    """Return summary stats for a CEF output file."""
    p = Path(path)
    if not p.exists():
        return {"exists": False}
    lines = [l for l in p.read_text().splitlines() if l.strip()]
    return {
        "exists":        True,
        "path":          str(p),
        "lines":         len(lines),
        "size_bytes":    p.stat().st_size,
        "cef_compliant": all(l.startswith("CEF:") for l in lines),
    }
