#!/usr/bin/env python3
# SHENRON: Format adapter — ECS and Splunk HEC export
# Maps synthetic SHENRON telemetry to Elastic Common Schema and Splunk HEC format.
# No subprocess, no network, no execution.
#
# ECS spec reference: https://www.elastic.co/guide/en/ecs/current/index.html
# Splunk HEC reference: https://docs.splunk.com/Documentation/Splunk/latest/Data/HECExamples

import json
from datetime import datetime, timezone
from typing import Optional

VERSION = "shenron-v0.3.0"
DATASET = "shenron.synthetic"

# ── MITRE → ECS field mapping ─────────────────────────────────────────────────
# Maps technique ID prefix → (event.category, event.type, threat.tactic.name)
# ECS event.category and event.type are arrays in spec; stored as lists here.

_MITRE_ECS_MAP = {
    # Command and Control
    "T1001":  (["network"],  ["info"],       "command-and-control"),
    "T1071":  (["network"],  ["connection"], "command-and-control"),
    "T1090":  (["network"],  ["connection"], "command-and-control"),
    "T1095":  (["network"],  ["connection"], "command-and-control"),
    "T1102":  (["network"],  ["connection"], "command-and-control"),
    "T1132":  (["network"],  ["info"],       "command-and-control"),
    "T1572":  (["network"],  ["connection"], "command-and-control"),
    "T1573":  (["network"],  ["connection"], "command-and-control"),

    # Exfiltration
    "T1041":  (["network"],  ["connection"], "exfiltration"),
    "T1048":  (["network"],  ["connection"], "exfiltration"),

    # Lateral Movement
    "T1021":  (["network"],  ["connection"], "lateral-movement"),
    "T1570":  (["file"],     ["transfer"],   "lateral-movement"),

    # Discovery
    "T1046":  (["network"],  ["info"],       "discovery"),
    "T1119":  (["file"],     ["access"],     "discovery"),
    "T1135":  (["network"],  ["info"],       "discovery"),

    # Collection
    "T1005":  (["file"],     ["access"],     "collection"),

    # Persistence
    "T1053":  (["process"],  ["start"],      "persistence"),
    "T1078":  (["authentication"], ["start"], "persistence"),
    "T1105":  (["file"],     ["creation"],   "persistence"),
    "T1542":  (["process"],  ["start"],      "persistence"),
    "T1543":  (["process"],  ["start"],      "persistence"),
    "T1547":  (["process"],  ["start"],      "persistence"),

    # Privilege Escalation
    "T1055":  (["process"],  ["start"],      "privilege-escalation"),
    "T1134":  (["process"],  ["change"],     "privilege-escalation"),

    # Defense Evasion
    "T1014":  (["process"],  ["info"],       "defense-evasion"),
    "T1027":  (["file"],     ["change"],     "defense-evasion"),
    "T1036":  (["process"],  ["info"],       "defense-evasion"),
    "T1070":  (["file"],     ["deletion"],   "defense-evasion"),
    "T1107":  (["file"],     ["deletion"],   "defense-evasion"),
    "T1140":  (["file"],     ["change"],     "defense-evasion"),
    "T1564":  (["file"],     ["creation"],   "defense-evasion"),
    "T1620":  (["process"],  ["change"],     "defense-evasion"),

    # Execution
    "T1059":  (["process"],  ["start"],      "execution"),

    # Impact
    "T1485":  (["file"],     ["deletion"],   "impact"),
    "T1565":  (["file"],     ["change"],     "impact"),

    # Exfiltration / C2 overlap
    "T1001":  (["network"],  ["info"],       "command-and-control"),
}

# Technique name lookup (display names for threat.technique.name)
_TECHNIQUE_NAMES = {
    "T1001":  "Data Obfuscation",
    "T1005":  "Data from Local System",
    "T1014":  "Rootkit",
    "T1021":  "Remote Services",
    "T1027":  "Obfuscated Files or Information",
    "T1036":  "Masquerading",
    "T1041":  "Exfiltration Over C2 Channel",
    "T1046":  "Network Service Discovery",
    "T1048":  "Exfiltration Over Alternative Protocol",
    "T1053":  "Scheduled Task/Job",
    "T1055":  "Process Injection",
    "T1059":  "Command and Scripting Interpreter",
    "T1070":  "Indicator Removal",
    "T1071":  "Application Layer Protocol",
    "T1078":  "Valid Accounts",
    "T1090":  "Proxy",
    "T1095":  "Non-Application Layer Protocol",
    "T1102":  "Web Service",
    "T1105":  "Ingress Tool Transfer",
    "T1107":  "File Deletion",
    "T1119":  "Automated Collection",
    "T1132":  "Data Encoding",
    "T1134":  "Access Token Manipulation",
    "T1135":  "Network Share Discovery",
    "T1140":  "Deobfuscate/Decode Files or Information",
    "T1485":  "Data Destruction",
    "T1542":  "Pre-OS Boot",
    "T1543":  "Create or Modify System Process",
    "T1547":  "Boot or Logon Autostart Execution",
    "T1564":  "Hide Artifacts",
    "T1565":  "Data Manipulation",
    "T1570":  "Lateral Tool Transfer",
    "T1572":  "Protocol Tunneling",
    "T1573":  "Encrypted Channel",
    "T1620":  "Reflective Code Loading",
    # Sub-techniques
    "T1027.002": "Software Packing",
    "T1036.005": "Match Legitimate Name or Location",
    "T1055.003": "Thread Execution Hijacking",
    "T1070.001": "Clear Windows Event Logs",
    "T1564.001": "Hidden Files and Directories",
}


def _resolve_technique(technique_id: str) -> tuple:
    """
    Resolve a technique ID to ECS fields.
    Tries exact match, then parent technique (strip sub-technique).
    Returns (categories, types, tactic_name, technique_name).
    """
    tid = technique_id.strip()

    # Try exact match
    if tid in _MITRE_ECS_MAP:
        cats, types, tactic = _MITRE_ECS_MAP[tid]
        name = _TECHNIQUE_NAMES.get(tid, tid)
        return cats, types, tactic, name

    # Try parent (e.g. T1036.005 → T1036)
    parent = tid.split(".")[0]
    if parent in _MITRE_ECS_MAP:
        cats, types, tactic = _MITRE_ECS_MAP[parent]
        name = _TECHNIQUE_NAMES.get(tid, _TECHNIQUE_NAMES.get(parent, tid))
        return cats, types, tactic, name

    # Unknown — default to generic
    return ["host"], ["info"], "unknown", tid


# ── ECS formatter ─────────────────────────────────────────────────────────────

def to_ecs(record: dict) -> dict:
    """
    Convert a single SHENRON JSONL record to ECS format.
    Preserves the full SHENRON safety contract in labels.*.
    Field mapping is aligned to real SHENRON event schema (flat safety fields,
    mitre_techniques array, behavior_class, session_id).
    """
    # SHENRON uses mitre_techniques (list); take first for primary ECS mapping
    techniques = record.get("mitre_techniques", [])
    technique_id = techniques[0] if techniques else ""
    cats, types, tactic, tech_name = _resolve_technique(technique_id) \
        if technique_id else (["host"], ["info"], "unknown", "")

    ts_raw = record.get("timestamp", "")
    try:
        ts = ts_raw if ts_raw else datetime.now(timezone.utc).isoformat()
    except Exception:
        ts = datetime.now(timezone.utc).isoformat()

    layer    = record.get("layer", "")
    phase    = record.get("phase", "")
    behavior = record.get("behavior_class", "")
    session  = record.get("session_id", "")
    desc     = f"{behavior} — {layer}" if behavior else layer

    ecs = {
        "@timestamp": ts,

        "event.kind":     "event",
        "event.category": cats,
        "event.type":     types,
        "event.dataset":  DATASET,
        "event.module":   "shenron",
        "event.provider": VERSION,
        "event.sequence": record.get("event_index", 0),
        "event.reason":   desc,
        "event.severity": 50,

        "message": f"[SHENRON SYNTHETIC] {behavior} — {layer}",

        "threat.framework":      "MITRE ATT&CK",
        "threat.technique.id":   techniques,
        "threat.technique.name": [_TECHNIQUE_NAMES.get(t, t) for t in techniques],
        "threat.tactic.name":    [tactic] if tactic else [],

        # Safety contract — flat fields on real SHENRON events
        "labels.simulation_only":    record.get("simulation_only", True),
        "labels.executable":         record.get("executable", False),
        "labels.no_payload_present": record.get("no_payload_present", True),
        "labels.subprocess_spawned": record.get("subprocess_spawned", False),
        "labels.subprocess_called":  record.get("subprocess_called", False),

        "labels.shenron_layer":   layer,
        "labels.shenron_phase":   phase,
        "labels.shenron_behavior":behavior,
        "labels.shenron_session": session,
        "labels.shenron_version": VERSION,
        "labels.artifact_id":     record.get("artifact_id", ""),

        "observer.type":    "synthetic-telemetry-generator",
        "observer.version": VERSION,
        "observer.name":    "shenron",
    }

    return ecs


# ── Splunk HEC formatter ──────────────────────────────────────────────────────

def to_splunk_hec(record: dict) -> dict:
    """
    Convert a SHENRON JSONL record to Splunk HEC event format.
    Aligned to real SHENRON event schema (flat safety fields, mitre_techniques array).
    Compatible with Splunk HTTP Event Collector /services/collector/event endpoint.
    """
    ts_raw = record.get("timestamp", "")
    try:
        if ts_raw:
            dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            epoch = dt.timestamp()
        else:
            epoch = datetime.now(timezone.utc).timestamp()
    except Exception:
        epoch = datetime.now(timezone.utc).timestamp()

    techniques = record.get("mitre_techniques", [])
    technique_id = techniques[0] if techniques else ""
    _, _, tactic, _ = _resolve_technique(technique_id) \
        if technique_id else ([], [], "unknown", "")

    layer    = record.get("layer", "")
    behavior = record.get("behavior_class", "")

    event_body = {
        "shenron_layer":    layer,
        "shenron_phase":    record.get("phase", ""),
        "shenron_behavior": behavior,
        "shenron_session":  record.get("session_id", ""),
        "artifact_id":      record.get("artifact_id", ""),
        "mitre_techniques": techniques,
        "mitre_tactic":     tactic,
        "message":          f"[SHENRON SYNTHETIC] {behavior} — {layer}",
        "simulation_only":  record.get("simulation_only", True),
        "no_payload_present": record.get("no_payload_present", True),
        "executable":       record.get("executable", False),
        "subprocess_spawned": record.get("subprocess_spawned", False),
    }

    return {
        "time":       epoch,
        "host":       "shenron-synthetic",
        "source":     "shenron",
        "sourcetype": "shenron:synthetic:telemetry",
        "index":      "shenron_demo",
        "event":      event_body,
    }


# ── Bulk formatters ───────────────────────────────────────────────────────────

def records_to_ecs(records: list) -> list:
    """Convert a list of SHENRON records to ECS dicts."""
    return [to_ecs(r) for r in records]


def records_to_splunk_hec(records: list) -> list:
    """Convert a list of SHENRON records to Splunk HEC event dicts."""
    return [to_splunk_hec(r) for r in records]


def write_ecs_bulk(records: list, path: str):
    """
    Write Elastic bulk API format:
    {"index": {"_index": "shenron-synthetic"}}
    {... ecs event ...}
    """
    with open(path, "w", encoding="utf-8") as f:
        for ecs_event in records_to_ecs(records):
            f.write(json.dumps({"index": {"_index": "shenron-synthetic"}}) + "\n")
            f.write(json.dumps(ecs_event) + "\n")


def write_ecs_array(records: list, path: str):
    """Write ECS events as a JSON array (for direct Elastic import or inspection)."""
    ecs_events = records_to_ecs(records)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(ecs_events, f, indent=2)


def write_splunk_hec(records: list, path: str):
    """
    Write Splunk HEC format — newline-delimited JSON.
    Compatible with Splunk HEC /services/collector/event endpoint.
    """
    with open(path, "w", encoding="utf-8") as f:
        for hec_event in records_to_splunk_hec(records):
            f.write(json.dumps(hec_event) + "\n")


# ── CLI summary ───────────────────────────────────────────────────────────────

def print_format_summary(records: list, out_paths: dict):
    print()
    print(f"  [FORMAT]      Export complete")
    print(f"  [RECORDS]     {len(records)}")
    for fmt, path in out_paths.items():
        print(f"  [{fmt.upper():<12}] {path}")
    print()
    print(f"  Elastic import:")
    if "ecs_bulk" in out_paths:
        print(f"    curl -X POST 'http://localhost:9200/_bulk' \\")
        print(f"         -H 'Content-Type: application/x-ndjson' \\")
        print(f"         --data-binary @{out_paths['ecs_bulk']}")
    if "splunk_hec" in out_paths:
        print()
        print(f"  Splunk HEC import:")
        print(f"    curl -X POST 'https://splunk:8088/services/collector/event' \\")
        print(f"         -H 'Authorization: Splunk YOUR_HEC_TOKEN' \\")
        print(f"         -d @{out_paths['splunk_hec']}")
    print()
    print(f"  ⚠  All events carry simulation_only: true")
    print(f"     These are SYNTHETIC records. No real adversarial activity occurred.")
    print()
