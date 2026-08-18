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

from core.config import artifact_log_path as _artifact_log_path

def _get_artifact_log():
    p = _artifact_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

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

    # The persistence validation contract requires at least one restoration-
    # shaped event (T1543). Preserve randomized file states, but prevent an
    # all-match draw from making required category coverage probabilistic.
    if scan_results and all(result["state"] == "match" for result in scan_results):
        forced = scan_results[0]
        forced["state"] = "mismatch"
        forced["label"] = "hash mismatch detected — restoration triggered"
        forced["hash_current_sim"] = _fake_hash()

    scan_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "system_rebuild_sim",
        "phase": "integrity_scan",
        "mitre_techniques": ["T1547"],
        "files_scanned": len(scan_results),
        "results": scan_results,
        "safe": True,
        "simulation_only": True,
        "behavior_class": "shadow_restore_sim",
        "detection_opportunities": ["autostart_registry_modification_sim", "shadow_copy_restoration_sim", "filesystem_integrity_check_sim", "service_persistence_sim"],
        "executable": False,
        "no_payload_present": True,
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
                "layer": "system_rebuild_sim",
                "phase": "shadow_restore",
                "mitre_techniques": ["T1543"],
                "target_path_sim": result["path"],
                "file_type": result["type"],
                "action_sim": "copy_from_shadow_backup",
                "timestamp_adjusted_sim": True,
                "safe": True,
                "simulation_only": True,
        "behavior_class": "shadow_restore_sim",
        "detection_opportunities": ["autostart_registry_modification_sim", "shadow_copy_restoration_sim", "filesystem_integrity_check_sim", "service_persistence_sim"],
        "executable": False,
        "no_payload_present": True,
                "filesystem_modified": False,
            }
            events.append(restore_event)
            with open(_get_artifact_log(), "a") as f:
                f.write(json.dumps(restore_event) + "\n")

    return session_id, scan_results, events

def print_simulation(session_id, scan_results, events):
    mismatches = [r for r in scan_results if r["state"] != "match"]
    print(f"\n  [SIMULATION]  system_rebuild_sim")
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

@register_payload(name="system_rebuild_sim")
def main():
    session_id, scan_results, events = simulate_shadow_rebuild()
    print_simulation(session_id, scan_results, events)

if __name__ == "__main__":
    main()
