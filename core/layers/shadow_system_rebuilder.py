from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Shadow System Rebuilder — synthetic filesystem integrity simulation
# PURPOSE: Emit realistic-shaped file tampering and restoration telemetry
# PRINCIPLE: Represent adversarial shape without adversarial capability
# MITRE: T1547 (Boot Autostart), T1543 (Create System Process)
# NO FILESYSTEM WRITES — no real file copies, no timestamp modification

import os
import json
import uuid
import random
import hashlib
from datetime import datetime, timezone
from pathlib import Path

ARTIFACT_LOG = Path("/home/gnomeman4201/SHENRON/logs/simulation_artifacts.jsonl")

def _get_artifact_log():
    ARTIFACT_LOG.parent.mkdir(parents=True, exist_ok=True)
    return ARTIFACT_LOG

FAKE_SYSTEM_FILES = [
    {"path": "/etc/systemd/system/update.service", "type": "systemd_unit"},
    {"path": "/etc/cron.d/syscheck",               "type": "cron_job"},
    {"path": "/etc/rc.local",                       "type": "rc_script"},
    {"path": "/usr/local/bin/sysmon",               "type": "binary"},
    {"path": "/etc/profile.d/env.sh",               "type": "profile_script"},
    {"path": "C:\\Windows\\System32\\svchost.exe",  "type": "windows_binary"},
    {"path": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\update", "type": "registry_service"},
]

FAKE_HASH_STATES = [
    {"state": "match",    "label": "file integrity verified"},
    {"state": "mismatch", "label": "hash mismatch detected — restoration triggered"},
    {"state": "missing",  "label": "file absent — shadow copy deployed"},
]

def _fake_hash():
    return hashlib.sha256(os.urandom(32)).hexdigest()

def simulate_shadow_rebuild():
    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: Integrity scan
    files_to_scan = random.sample(FAKE_SYSTEM_FILES, random.randint(3, 5))
    scan_results = []
    for f in files_to_scan:
        state = random.choice(FAKE_HASH_STATES)
        scan_results.append({
            "path": f["path"],
            "type": f["type"],
            "state": state["state"],
            "label": state["label"],
            "hash_orig_sim": _fake_hash(),
            "hash_current_sim": _fake_hash() if state["state"] != "match" else None,
        })

    scan_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "shadow_system_rebuilder",
        "phase": "integrity_scan",
        "mitre_techniques": ["T1547"],
        "files_scanned": len(scan_results),
        "results": scan_results,
        "safe": True,
        "simulation_only": True,
        "filesystem_modified": False,
    }
    events.append(scan_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(scan_event) + "\n")

    # Phase 2: Restoration events for mismatches
    for result in scan_results:
        if result["state"] in ("mismatch", "missing"):
            restore_event = {
                "artifact_id": str(uuid.uuid4()),
                "session_id": session_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "layer": "shadow_system_rebuilder",
                "phase": "shadow_restore",
                "mitre_techniques": ["T1543"],
                "target_path_sim": result["path"],
                "file_type": result["type"],
                "action_sim": "copy_from_shadow_backup",
                "timestamp_adjusted_sim": True,
                "safe": True,
                "simulation_only": True,
                "filesystem_modified": False,
            }
            events.append(restore_event)
            with open(_get_artifact_log(), "a") as f:
                f.write(json.dumps(restore_event) + "\n")

    return session_id, scan_results, events

def print_simulation(session_id, scan_results, events):
    mismatches = [r for r in scan_results if r["state"] != "match"]
    print(f"\n  [SIMULATION]  shadow_system_rebuilder")
    print(f"  [SESSION]     {session_id}")
    print(f"  [FILES_SIM]   {len(scan_results)} scanned, {len(mismatches)} restored")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1547, T1543")
    print(f"  [FILESYSTEM]  NOT MODIFIED — synthetic only")
    print()
    print(f"  [PHASE 1: INTEGRITY SCAN]")
    for r in scan_results:
        flag = "✓" if r["state"] == "match" else "!"
        print(f"    [{flag}] {r['path']:<50} {r['label']}")
    if mismatches:
        print(f"\n  [PHASE 2: SHADOW RESTORE]")
        for e in events:
            if e["phase"] == "shadow_restore":
                print(f"    restored      : {e['target_path_sim']}")
                print(f"    action_sim    : {e['action_sim']}")
                print(f"    ts_adjusted   : {e['timestamp_adjusted_sim']}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no filesystem writes — simulation only")

@register_payload(name="shadow_system_rebuilder")
def main():
    session_id, scan_results, events = simulate_shadow_rebuild()
    print_simulation(session_id, scan_results, events)

if __name__ == "__main__":
    main()
