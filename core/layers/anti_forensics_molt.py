from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Anti-Forensics Molt — synthetic log tampering and history wiping simulator
# PURPOSE: Emit realistic-shaped anti-forensics telemetry for detection testing
# PRINCIPLE: Represent adversarial shape without adversarial capability
# MITRE: T1070 (Indicator Removal), T1107 (File Deletion)
# NO FILE WRITES — no real log deletion, no real history modification

import os
import json
import uuid
import random
from datetime import datetime, timezone
from pathlib import Path

from core.config import artifact_log_path as _artifact_log_path

def _get_artifact_log():
    p = _artifact_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

FAKE_LOG_TARGETS = [
    {"path": "~/.bash_history",           "type": "shell_history"},
    {"path": "~/.zsh_history",            "type": "shell_history"},
    {"path": "/var/log/auth.log",         "type": "system_log"},
    {"path": "/var/log/syslog",           "type": "system_log"},
    {"path": "/var/log/wtmp",             "type": "login_log"},
    {"path": "/var/log/btmp",             "type": "failed_login_log"},
    {"path": "~/.local/share/recently-used.xbel", "type": "file_access_log"},
    {"path": "/tmp/.bash_sessions",       "type": "session_log"},
]

FAKE_DECOY_COMMANDS = [
    "echo hello world",
    "ls -la",
    "git status",
    "python3 test.py",
    "cd /tmp",
    "cat /etc/hostname",
]

FAKE_WIPE_METHODS = [
    "truncate_to_zero",
    "overwrite_with_decoys",
    "secure_delete_sim",
    "shred_sim",
    "rmtree_sim",
]

FAKE_TIMESTAMP_ACTIONS = [
    "mtime_rollback_24h",
    "atime_clear",
    "ctime_spoof",
]

def simulate_anti_forensics():
    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: Target enumeration
    targets = random.sample(FAKE_LOG_TARGETS, random.randint(3, 5))
    enum_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "anti_forensics_molt",
        "phase": "target_enumeration",
        "mitre_techniques": ["T1070"],
        "behavior_class": "target_enumeration",
        "detection_opportunities": ["target_enumeration"],
        "targets_identified": len(targets),
        "target_paths_sim": [t["path"] for t in targets],
        "safe": True,
        "simulation_only": True,
        "files_modified": False,
    }
    events.append(enum_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(enum_event) + "\n")

    # Phase 2: Log wiping per target
    for target in targets:
        method = random.choice(FAKE_WIPE_METHODS)
        wipe_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "anti_forensics_molt",
            "phase": "log_wipe",
            "mitre_techniques": ["T1070", "T1070.004"],
            "behavior_class": "log_wipe",
            "detection_opportunities": ["log_wipe"],
            "target_path_sim": target["path"],
            "target_type": target["type"],
            "wipe_method_sim": method,
            "decoy_injected": method == "overwrite_with_decoys",
            "decoy_commands_sim": random.sample(FAKE_DECOY_COMMANDS, 3) if method == "overwrite_with_decoys" else [],
            "safe": True,
            "simulation_only": True,
            "files_modified": False,
        }
        events.append(wipe_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(wipe_event) + "\n")

    # Phase 3: Timestamp manipulation
    ts_action = random.choice(FAKE_TIMESTAMP_ACTIONS)
    ts_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "anti_forensics_molt",
        "phase": "timestamp_manipulation",
        "mitre_techniques": ["T1070"],
        "behavior_class": "timestamp_manipulation",
        "detection_opportunities": ["timestamp_manipulation"],
        "action_sim": ts_action,
        "targets_affected_sim": len(targets),
        "safe": True,
        "simulation_only": True,
        "files_modified": False,
    }
    events.append(ts_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(ts_event) + "\n")

    return session_id, targets, events

def print_simulation(session_id, targets, events):
    print(f"\n  [SIMULATION]  anti_forensics_molt")
    print(f"  [SESSION]     {session_id}")
    print(f"  [TARGETS_SIM] {len(targets)}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1070, T1107")
    print(f"  [FILES]       NOT MODIFIED — synthetic only")
    print()
    for e in events:
        phase = e["phase"]
        if phase == "target_enumeration":
            print(f"  [PHASE 1: TARGET ENUMERATION]")
            for p in e["target_paths_sim"]:
                print(f"    {p}")
        elif phase == "log_wipe":
            print(f"\n  [PHASE 2: LOG WIPE]")
            print(f"    target_sim    : {e['target_path_sim']}")
            print(f"    type          : {e['target_type']}")
            print(f"    method_sim    : {e['wipe_method_sim']}")
            if e["decoy_injected"]:
                print(f"    decoys_sim    : {e['decoy_commands_sim']}")
        elif phase == "timestamp_manipulation":
            print(f"\n  [PHASE 3: TIMESTAMP MANIPULATION]")
            print(f"    action_sim    : {e['action_sim']}")
            print(f"    targets_sim   : {e['targets_affected_sim']}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no file writes, no log deletion — simulation only")

@register_payload(name="anti_forensics_molt")
def main():
    session_id, targets, events = simulate_anti_forensics()
    print_simulation(session_id, targets, events)

if __name__ == "__main__":
    main()
