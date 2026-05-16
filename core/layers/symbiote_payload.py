from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Symbiote Payload — shell profile injection telemetry simulator
# PURPOSE: Emit defender-observable telemetry for profile/rc injection persistence patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1055 (Process Injection), T1027 (Obfuscated Files)
# DETECTION NOTES:
#   - Blue teams should alert on: unexpected modifications to shell rc files
#   - Background process launch patterns appended to profile files
#   - Revival scripts in hidden dotdirs (~/.shenron/, ~/.cache/)
#   - Boot/init scripts modified by non-package-manager processes
#   - Injection idempotency checks (read before write) indicate deliberate persistence

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

FAKE_INJECTION_TARGETS_SIM = [
    {"path_sim": "~/.bashrc_sim",           "type": "user_shell_rc"},
    {"path_sim": "~/.zshrc_sim",            "type": "user_shell_rc"},
    {"path_sim": "~/.profile_sim",          "type": "user_profile"},
    {"path_sim": "/etc/bash.bashrc_sim",    "type": "system_shell_rc"},
    {"path_sim": "/etc/motd_sim",           "type": "motd"},
    {"path_sim": "/etc/init.d/00boot_sim",  "type": "init_script"},
]

INJECT_BEHAVIOR_CLASSES = [
    "background_process_launch_append_sim",
    "revival_script_hook_append_sim",
    "loader_stub_append_sim",
]

REVIVAL_SCRIPT_BEHAVIORS_SIM = [
    "hidden_dotdir_script_create_sim",
    "chain_script_reference_create_sim",
]

DETECTION_OPPORTUNITIES = [
    "rc_file_modified_by_non_shell_process",
    "background_launch_pattern_in_rc_file",
    "hidden_revival_script_in_dotdir",
    "idempotency_check_before_rc_append",
    "boot_script_modified_by_non_package_manager",
    "new_exec_reference_in_profile_file",
]

def simulate_symbiote():
    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: Revival script staging simulation
    revival_behavior = random.choice(REVIVAL_SCRIPT_BEHAVIORS_SIM)
    revival_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "symbiote_payload",
        "phase": "revival_script_stage_sim",
        "mitre_techniques": ["T1055"],
        "behavior_class": revival_behavior,
        "revival_path_sim": "~/.hidden_dotdir_sim/.revive_sim.py",
        "hidden_dir_sim": True,
        "script_content_description": "invokes_chain_script_via_os_exec_sim",
        "command_string_present": False,
        "detection_opportunities": [
            "hidden_revival_script_in_dotdir",
            "new_executable_in_hidden_homedir_subdir",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "files_created": False,
    }
    events.append(revival_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(revival_event) + "\n")

    # Phase 2: RC file injection sequence
    targets = random.sample(FAKE_INJECTION_TARGETS_SIM, random.randint(3, 5))
    for target in targets:
        behavior = random.choice(INJECT_BEHAVIOR_CLASSES)
        already_injected = random.choice([True, False])
        inject_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "symbiote_payload",
            "phase": "rc_injection_sim",
            "mitre_techniques": ["T1027"],
            "behavior_class": behavior,
            "target_path_sim": target["path_sim"],
            "target_type": target["type"],
            "idempotency_check_performed": True,
            "already_injected_sim": already_injected,
            "injection_skipped": already_injected,
            "append_pattern_sim": "background_process_launch_nohup_devnull_sim",
            "command_string_present": False,
            "inject_line_description": "launches_revival_script_in_background_discards_output_sim",
            "detection_opportunities": [
                "rc_file_modified_by_non_shell_process",
                "idempotency_check_before_rc_append",
                "background_launch_pattern_in_rc_file",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "files_created": False,
        }
        events.append(inject_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(inject_event) + "\n")

    return session_id, targets, events

def print_simulation(session_id, targets, events):
    injected = sum(1 for e in events
                   if e["phase"] == "rc_injection_sim" and not e["injection_skipped"])
    print(f"\n  [SIMULATION]  symbiote_payload")
    print(f"  [SESSION]     {session_id}")
    print(f"  [TARGETS_SIM] {len(targets)}")
    print(f"  [INJECTED]    {injected} (skipped {len(targets)-injected} already-present)")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1055, T1027")
    print(f"  [FILES]       NOT MODIFIED — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no rc writes, no inject lines, no shell strings")
    print()
    for e in events:
        if e["phase"] == "revival_script_stage_sim":
            print(f"  [PHASE 1: REVIVAL SCRIPT STAGE]")
            print(f"    behavior      : {e['behavior_class']}")
            print(f"    path_sim      : {e['revival_path_sim']}")
            print(f"    description   : {e['script_content_description']}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
        elif e["phase"] == "rc_injection_sim":
            flag = "SKIP" if e["injection_skipped"] else "INJECT"
            print(f"\n  [PHASE 2: RC INJECT [{flag}]] {e['target_path_sim']}")
            print(f"    type          : {e['target_type']}")
            print(f"    behavior      : {e['behavior_class']}")
            print(f"    idempotent    : {e['idempotency_check_performed']}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no bashrc writes, no inject strings — telemetry only")

@register_payload(name="symbiote_payload")
def main():
    session_id, targets, events = simulate_symbiote()
    print_simulation(session_id, targets, events)

if __name__ == "__main__":
    main()
