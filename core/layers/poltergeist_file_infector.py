from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Poltergeist File Infector — synthetic file infection simulator
# PURPOSE: Emit realistic-shaped file modification telemetry for detection testing
# PRINCIPLE: Represent adversarial shape without adversarial capability
# MITRE: T1027 (Obfuscated Files), T1564.001 (Hidden Files)
# NO FILE WRITES — no real file modification, no filesystem traversal

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

FAKE_TARGET_FILES = [
    {"path": "~/scripts/backup.sh",          "type": "shell_script"},
    {"path": "~/scripts/deploy.sh",          "type": "shell_script"},
    {"path": "~/.bashrc",                    "type": "profile_script"},
    {"path": "~/.bash_profile",              "type": "profile_script"},
    {"path": "~/research_hub/utils/scan.py", "type": "python_script"},
    {"path": "/usr/local/bin/update.sh",     "type": "system_script"},
    {"path": "/etc/profile.d/aliases.sh",    "type": "system_profile"},
]

FAKE_INFECTION_MARKERS = [
    "# POLTERGEIST_PRESENCE_SIM",
    "# SYS_UPDATE_HOOK_SIM",
    "# LOADER_STUB_SIM",
    "# ENV_INJECT_SIM",
]

FAKE_SCAN_OUTCOMES = [
    "candidate identified — not selected",
    "candidate identified — not selected",
    "candidate selected for infection (simulated)",
]

def _fake_hash():
    return hashlib.sha256(os.urandom(32)).hexdigest()

def simulate_poltergeist():
    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: Filesystem scan simulation
    candidates = random.sample(FAKE_TARGET_FILES, random.randint(4, 6))
    scan_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "poltergeist_file_infector",
        "phase": "candidate_scan",
        "mitre_techniques": ["T1027"],
        "files_scanned_sim": len(candidates),
        "extensions_targeted_sim": [".sh", ".py"],
        "scan_path_sim": "~/",
        "safe": True,
        "simulation_only": True,
        "behavior_class": "file_infection_sim",
        "detection_opportunities": ["script_file_modification_sim", "loader_stub_injection_sim", "hash_modification_sim", "file_candidate_scan_sim"],
        "executable": False,
        "no_payload_present": True,
        "files_modified": False,
    }
    events.append(scan_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(scan_event) + "\n")

    # Phase 2: Candidate evaluation
    target = None
    for i, candidate in enumerate(candidates):
        outcome = FAKE_SCAN_OUTCOMES[min(i, len(FAKE_SCAN_OUTCOMES)-1)]
        selected = "selected" in outcome
        if selected:
            target = candidate

        eval_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "poltergeist_file_infector",
            "phase": "candidate_evaluation",
            "mitre_techniques": ["T1027"],
            "file_path_sim": candidate["path"],
            "file_type": candidate["type"],
            "outcome_sim": outcome,
            "selected": selected,
            "safe": True,
            "simulation_only": True,
        "behavior_class": "file_infection_sim",
        "detection_opportunities": ["script_file_modification_sim", "loader_stub_injection_sim", "hash_modification_sim", "file_candidate_scan_sim"],
        "executable": False,
        "no_payload_present": True,
            "files_modified": False,
        }
        events.append(eval_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(eval_event) + "\n")

    # Phase 3: Infection simulation
    if target:
        marker = random.choice(FAKE_INFECTION_MARKERS)
        infect_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "poltergeist_file_infector",
            "phase": "infection_sim",
            "mitre_techniques": ["T1564.001"],
            "target_path_sim": target["path"],
            "file_type": target["type"],
            "marker_sim": marker,
            "append_position_sim": "EOF",
            "hash_before_sim": _fake_hash(),
            "hash_after_sim": _fake_hash(),
            "safe": True,
            "simulation_only": True,
        "behavior_class": "file_infection_sim",
        "detection_opportunities": ["script_file_modification_sim", "loader_stub_injection_sim", "hash_modification_sim", "file_candidate_scan_sim"],
        "executable": False,
        "no_payload_present": True,
            "files_modified": False,
        }
        events.append(infect_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(infect_event) + "\n")

    return session_id, target, events

def print_simulation(session_id, target, events):
    print(f"\n  [SIMULATION]  poltergeist_file_infector")
    print(f"  [SESSION]     {session_id}")
    print(f"  [TARGET_SIM]  {target['path'] if target else 'none selected'}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1027, T1564.001")
    print(f"  [FILES]       NOT MODIFIED — synthetic only")
    print()
    for e in events:
        phase = e["phase"]
        if phase == "candidate_scan":
            print(f"  [PHASE 1: CANDIDATE SCAN]")
            print(f"    files_scanned : {e['files_scanned_sim']}")
            print(f"    extensions    : {e['extensions_targeted_sim']}")
            print(f"    scan_path_sim : {e['scan_path_sim']}")
        elif phase == "candidate_evaluation":
            flag = "→" if e["selected"] else " "
            print(f"    [{flag}] {e['file_path_sim']:<45} {e['outcome_sim']}")
        elif phase == "infection_sim":
            print(f"\n  [PHASE 3: INFECTION SIM]")
            print(f"    target_sim    : {e['target_path_sim']}")
            print(f"    marker_sim    : {e['marker_sim']}")
            print(f"    position_sim  : {e['append_position_sim']}")
            print(f"    hash_delta    : {e['hash_before_sim'][:16]}... → {e['hash_after_sim'][:16]}...")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no file writes, no filesystem traversal — simulation only")

@register_payload(name="poltergeist_file_infector")
def main():
    session_id, target, events = simulate_poltergeist()
    print_simulation(session_id, target, events)

if __name__ == "__main__":
    main()
