from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Spectral Rootkit Shroud — synthetic rootkit activity simulator
# PURPOSE: Emit realistic-shaped rootkit telemetry for detection testing
# PRINCIPLE: Represent adversarial shape without adversarial capability
# MITRE: T1014 (Rootkit), T1564 (Hide Artifacts)
# NO KERNEL INTERACTION — no real hooking, no real hiding, no real syscall manipulation

import os
import json
import uuid
import random
from datetime import datetime, timezone
from pathlib import Path

ARTIFACT_LOG = Path("/home/gnomeman4201/SHENRON/logs/simulation_artifacts.jsonl")

def _get_artifact_log():
    ARTIFACT_LOG.parent.mkdir(parents=True, exist_ok=True)
    return ARTIFACT_LOG

FAKE_HOOK_TARGETS = [
    {"syscall": "getdents64",  "purpose": "hide_files"},
    {"syscall": "read",        "purpose": "intercept_reads"},
    {"syscall": "write",       "purpose": "intercept_writes"},
    {"syscall": "kill",        "purpose": "protect_process"},
    {"syscall": "open",        "purpose": "redirect_open"},
    {"syscall": "stat",        "purpose": "spoof_attributes"},
]

FAKE_HIDDEN_ARTIFACTS = [
    {"path": "/proc/13337",              "type": "process"},
    {"path": "/dev/.hidden_socket",      "type": "socket"},
    {"path": "/lib/.ld_preload_hook.so", "type": "library"},
    {"path": "/etc/.shadow_config",      "type": "config"},
    {"path": "C:\\Windows\\System32\\drivers\\rootkit.sys", "type": "driver"},
]

FAKE_NOISE_EVENTS = [
    "spectral noise injected — scanner confused",
    "entropy spike generated — analysis delayed",
    "fake module listing injected",
    "lkm_hide triggered (simulated)",
]

def simulate_rootkit_shroud():
    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: Syscall hook simulation
    hooks = random.sample(FAKE_HOOK_TARGETS, random.randint(2, 4))
    hook_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "spectral_rootkit_shroud",
        "phase": "syscall_hook_sim",
        "mitre_techniques": ["T1014"],
        "hooks_installed_sim": len(hooks),
        "hook_targets_sim": [h["syscall"] for h in hooks],
        "hook_purposes_sim": [h["purpose"] for h in hooks],
        "safe": True,
        "simulation_only": True,
        "kernel_modified": False,
    }
    events.append(hook_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(hook_event) + "\n")

    # Phase 2: Artifact hiding simulation
    hidden = random.sample(FAKE_HIDDEN_ARTIFACTS, random.randint(2, 3))
    hide_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "spectral_rootkit_shroud",
        "phase": "artifact_hiding_sim",
        "mitre_techniques": ["T1564"],
        "artifacts_hidden_sim": len(hidden),
        "hidden_paths_sim": [h["path"] for h in hidden],
        "hidden_types_sim": [h["type"] for h in hidden],
        "safe": True,
        "simulation_only": True,
        "kernel_modified": False,
    }
    events.append(hide_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(hide_event) + "\n")

    # Phase 3: Spectral noise injection
    n_noise = random.randint(2, 3)
    for i in range(n_noise):
        noise = random.choice(FAKE_NOISE_EVENTS)
        noise_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "spectral_rootkit_shroud",
            "phase": "noise_injection",
            "mitre_techniques": ["T1014"],
            "noise_event_sim": noise,
            "iteration": i + 1,
            "safe": True,
            "simulation_only": True,
            "kernel_modified": False,
        }
        events.append(noise_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(noise_event) + "\n")

    return session_id, hooks, hidden, events

def print_simulation(session_id, hooks, hidden, events):
    print(f"\n  [SIMULATION]  spectral_rootkit_shroud")
    print(f"  [SESSION]     {session_id}")
    print(f"  [HOOKS_SIM]   {len(hooks)}")
    print(f"  [HIDDEN_SIM]  {len(hidden)}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1014, T1564")
    print(f"  [KERNEL]      NOT MODIFIED — synthetic only")
    print()
    for e in events:
        phase = e["phase"]
        if phase == "syscall_hook_sim":
            print(f"  [PHASE 1: SYSCALL HOOK SIM]")
            for syscall, purpose in zip(e["hook_targets_sim"], e["hook_purposes_sim"]):
                print(f"    hook_sim      : {syscall:<15} purpose={purpose}")
        elif phase == "artifact_hiding_sim":
            print(f"\n  [PHASE 2: ARTIFACT HIDING SIM]")
            for path, typ in zip(e["hidden_paths_sim"], e["hidden_types_sim"]):
                print(f"    hidden_sim    : {path} [{typ}]")
        elif phase == "noise_injection":
            print(f"\n  [PHASE 3: NOISE INJECTION #{e['iteration']}]")
            print(f"    event_sim     : {e['noise_event_sim']}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no kernel interaction, no hooking — simulation only")

@register_payload(name="spectral_rootkit_shroud")
def main():
    session_id, hooks, hidden, events = simulate_rootkit_shroud()
    print_simulation(session_id, hooks, hidden, events)

if __name__ == "__main__":
    main()
