from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Ethereal Payload Reanimator — dormant process revival telemetry simulator
# PURPOSE: Emit defender-observable telemetry for reflective loading and process revival
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1055 (Process Injection), T1620 (Reflective Code Loading)
# DETECTION NOTES:
#   - Blue teams should alert on: processes spawned from unusual parent paths
#   - Python/interpreter processes with no visible script argument
#   - Sequential process spawning with fixed sleep intervals from single parent
#   - Payload directories in non-standard locations under home or SHENRON paths
#   - Stdout/stderr both redirected to /dev/null on spawned processes

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

FAKE_PAYLOAD_NAMES_SIM = [
    "stealth_module_sim.py", "revival_agent_sim.py",
    "persist_hook_sim.py", "signal_monitor_sim.py"
]

FAKE_PAYLOAD_DIR_SIM = "~/SHENRON/core/payloads/stealth_sim/"

REANIMATION_BEHAVIOR_CLASSES = [
    "reflective_load_from_disk_sim",
    "dormant_process_revival_sim",
    "subprocess_popen_devnull_spawn_sim",
    "interpreter_spawn_no_script_arg_sim",
]

DETECTION_OPPORTUNITIES = [
    "python_process_spawned_with_no_visible_script",
    "stdout_stderr_both_devnull_on_spawned_process",
    "sequential_process_spawn_fixed_interval_single_parent",
    "process_parent_path_non_standard",
    "payload_dir_in_non_standard_home_subdir",
]

def simulate_reanimator():
    session_id = str(uuid.uuid4())
    events = []

    payloads_sim = random.sample(FAKE_PAYLOAD_NAMES_SIM,
                                  random.randint(2, len(FAKE_PAYLOAD_NAMES_SIM)))

    # Phase 1: Payload directory enumeration
    enum_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "payload_revival_sim",
        "phase": "payload_dir_enum",
        "mitre_techniques": ["T1055"],
        "behavior_class": "payload_directory_scan_sim",
        "payload_dir_sim": FAKE_PAYLOAD_DIR_SIM,
        "payloads_found_sim": len(payloads_sim),
        "payload_names_sim": payloads_sim,
        "detection_opportunities": [
            "payload_dir_in_non_standard_home_subdir",
            "directory_listing_of_stealth_payload_dir",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "processes_spawned": False,
    }
    events.append(enum_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(enum_event) + "\n")

    # Phase 2: Revival attempts per payload
    for i, payload_sim in enumerate(payloads_sim):
        behavior = random.choice(REANIMATION_BEHAVIOR_CLASSES)
        interval_sim = random.randint(3, 7)
        revive_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "payload_revival_sim",
            "phase": "revival_attempt",
            "mitre_techniques": ["T1620"],
            "behavior_class": behavior,
            "payload_sim": payload_sim,
            "full_path_sim": f"{FAKE_PAYLOAD_DIR_SIM}{payload_sim}",
            "spawn_index": i + 1,
            "spawn_interval_sim": interval_sim,
            "stdout_redirect_sim": "devnull",
            "stderr_redirect_sim": "devnull",
            "parent_path_sim": FAKE_PAYLOAD_DIR_SIM,
            "script_arg_visible": False,
            "detection_opportunities": [
                "python_process_spawned_with_no_visible_script",
                "stdout_stderr_both_devnull_on_spawned_process",
                "sequential_process_spawn_fixed_interval_single_parent",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "processes_spawned": False,
        }
        events.append(revive_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(revive_event) + "\n")

    return session_id, payloads_sim, events

def print_simulation(session_id, payloads_sim, events):
    print(f"\n  [SIMULATION]  payload_revival_sim")
    print(f"  [SESSION]     {session_id}")
    print(f"  [PAYLOADS]    {len(payloads_sim)} found in dir_sim")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1055, T1620")
    print(f"  [PROCESSES]   NONE SPAWNED — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no subprocess calls")
    print()
    for e in events:
        if e["phase"] == "payload_dir_enum":
            print(f"  [PHASE 1: DIR ENUMERATION]")
            print(f"    dir_sim       : {e['payload_dir_sim']}")
            print(f"    found_sim     : {e['payloads_found_sim']}")
            for p in e["payload_names_sim"]:
                print(f"      {p}")
        elif e["phase"] == "revival_attempt":
            print(f"\n  [PHASE 2: REVIVAL #{e['spawn_index']}]")
            print(f"    behavior      : {e['behavior_class']}")
            print(f"    payload_sim   : {e['payload_sim']}")
            print(f"    interval_sim  : {e['spawn_interval_sim']}s")
            print(f"    stdout_sim    : {e['stdout_redirect_sim']}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no subprocess calls — telemetry only")

@register_payload(name="payload_revival_sim")
def main():
    session_id, payloads_sim, events = simulate_reanimator()
    print_simulation(session_id, payloads_sim, events)

if __name__ == "__main__":
    main()
