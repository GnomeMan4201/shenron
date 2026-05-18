from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Self-Sealing Nano Sandbox — synthetic sandbox isolation simulator
# PURPOSE: Emit realistic-shaped sandbox creation and teardown telemetry
# PRINCIPLE: Represent adversarial shape without adversarial capability
# MITRE: T1055 (Process Injection), T1564 (Hide Artifacts)
# NO SUBPROCESS CALLS — no real sandbox creation, no real command execution

import os
import json
import uuid
import random
import string
from datetime import datetime, timezone
from pathlib import Path

from core.config import artifact_log_path as _artifact_log_path

def _get_artifact_log():
    p = _artifact_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

FAKE_SANDBOX_TYPES = [
    "tmpfs_mount_sim", "chroot_sim", "namespace_sim", "cgroup_sim", "firejail_sim"
]

FAKE_COMMANDS_SIM = [
    ["ls", "-la"],
    ["id"],
    ["uname", "-a"],
    ["ps", "aux"],
    ["cat", "/etc/passwd"],
]

FAKE_SEAL_METHODS = [
    "rmtree_sim", "secure_delete_sim", "tmpfs_unmount_sim", "overlay_collapse_sim"
]

def _random_dirname():
    return ".sandbox_" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))

def simulate_nano_sandbox():
    session_id = str(uuid.uuid4())
    sandbox_name = _random_dirname()
    sandbox_path_sim = f"/tmp/{sandbox_name}"
    sandbox_type = random.choice(FAKE_SANDBOX_TYPES)
    events = []

    # Phase 1: Sandbox setup
    setup_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "self_sealing_nano_sandbox",
        "phase": "sandbox_setup",
        "mitre_techniques": ["T1564"],
        "sandbox_path_sim": sandbox_path_sim,
        "sandbox_type_sim": sandbox_type,
        "hidden": True,
        "safe": True,
        "simulation_only": True,
        "behavior_class": "sandbox_execution_sim",
        "detection_opportunities": ["process_injection_attempt_sim", "hidden_sandbox_creation_sim", "chroot_sim", "sandbox_seal_destroy_sim"],
        "executable": False,
        "no_payload_present": True,
        "filesystem_modified": False,
        "subprocess_called": False,
    }
    events.append(setup_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(setup_event) + "\n")

    # Phase 2: Command execution inside sandbox
    n_commands = random.randint(2, 3)
    commands = random.sample(FAKE_COMMANDS_SIM, n_commands)
    for cmd in commands:
        exec_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "self_sealing_nano_sandbox",
            "phase": "sandboxed_execution",
            "mitre_techniques": ["T1055"],
            "sandbox_path_sim": sandbox_path_sim,
            "command_sim": cmd,
            "stdout_sim": f"[synthetic output for {cmd[0]}]",
            "exit_code_sim": 0,
            "safe": True,
            "simulation_only": True,
        "behavior_class": "sandbox_execution_sim",
        "detection_opportunities": ["process_injection_attempt_sim", "hidden_sandbox_creation_sim", "chroot_sim", "sandbox_seal_destroy_sim"],
        "executable": False,
        "no_payload_present": True,
            "filesystem_modified": False,
            "subprocess_called": False,
        }
        events.append(exec_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(exec_event) + "\n")

    # Phase 3: Seal and destroy
    seal_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "self_sealing_nano_sandbox",
        "phase": "sandbox_seal",
        "mitre_techniques": ["T1564"],
        "sandbox_path_sim": sandbox_path_sim,
        "seal_method_sim": random.choice(FAKE_SEAL_METHODS),
        "artifacts_removed_sim": True,
        "safe": True,
        "simulation_only": True,
        "behavior_class": "sandbox_execution_sim",
        "detection_opportunities": ["process_injection_attempt_sim", "hidden_sandbox_creation_sim", "chroot_sim", "sandbox_seal_destroy_sim"],
        "executable": False,
        "no_payload_present": True,
        "filesystem_modified": False,
        "subprocess_called": False,
    }
    events.append(seal_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(seal_event) + "\n")

    return session_id, sandbox_path_sim, sandbox_type, events

def print_simulation(session_id, sandbox_path_sim, sandbox_type, events):
    print(f"\n  [SIMULATION]  self_sealing_nano_sandbox")
    print(f"  [SESSION]     {session_id}")
    print(f"  [SANDBOX_SIM] {sandbox_path_sim}")
    print(f"  [TYPE_SIM]    {sandbox_type}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1055, T1564")
    print(f"  [SUBPROCESS]  NOT CALLED — synthetic only")
    print(f"  [FILESYSTEM]  NOT MODIFIED — synthetic only")
    print()
    for e in events:
        phase = e["phase"]
        if phase == "sandbox_setup":
            print(f"  [PHASE 1: SANDBOX SETUP]")
            print(f"    path_sim      : {e['sandbox_path_sim']}")
            print(f"    type_sim      : {e['sandbox_type_sim']}")
            print(f"    hidden        : {e['hidden']}")
        elif phase == "sandboxed_execution":
            print(f"\n  [PHASE 2: SANDBOXED EXEC]")
            print(f"    command_sim   : {' '.join(e['command_sim'])}")
            print(f"    stdout_sim    : {e['stdout_sim']}")
            print(f"    exit_code_sim : {e['exit_code_sim']}")
        elif phase == "sandbox_seal":
            print(f"\n  [PHASE 3: SEAL AND DESTROY]")
            print(f"    method_sim    : {e['seal_method_sim']}")
            print(f"    artifacts_rm  : {e['artifacts_removed_sim']}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no subprocess calls, no filesystem writes — simulation only")

@register_payload(name="self_sealing_nano_sandbox")
def main():
    session_id, sandbox_path_sim, sandbox_type, events = simulate_nano_sandbox()
    print_simulation(session_id, sandbox_path_sim, sandbox_type, events)

if __name__ == "__main__":
    main()
