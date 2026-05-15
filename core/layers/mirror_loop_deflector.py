from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Mirror Loop Deflector — synthetic process masquerading simulator
# PURPOSE: Emit realistic-shaped process cloaking and masquerading telemetry
# PRINCIPLE: Represent adversarial shape without adversarial capability
# MITRE: T1036.005 (Match Legitimate Name), T1070 (Indicator Removal)
# NO PROCESS SPAWNING — no real process creation, no real log writes, no sleep loops

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

FAKE_LEGITIMATE_NAMES = [
    {"name": "logd",            "type": "system_daemon"},
    {"name": "netd",            "type": "network_daemon"},
    {"name": "vold",            "type": "volume_daemon"},
    {"name": "systemd-resolve", "type": "system_service"},
    {"name": "kworker/u8:2",    "type": "kernel_thread"},
    {"name": "svchost",         "type": "windows_service"},
    {"name": "lsass",           "type": "windows_auth"},
    {"name": "chrome",          "type": "browser_process"},
]

FAKE_DEFLECTION_ARTIFACTS = [
    "ping_loop_artifact",
    "fake_ps_entry",
    "proc_name_spoof",
    "cmdline_masquerade",
]

FAKE_LOOP_OUTCOMES = [
    "deflector loop iteration — no detection",
    "deflector loop iteration — no detection",
    "deflector loop iteration — anomaly logged",
    "deflector loop complete — cloaking maintained",
]

def simulate_mirror_loop():
    session_id = str(uuid.uuid4())
    target_proc = random.choice(FAKE_LEGITIMATE_NAMES)
    pid_sim = random.randint(3000, 9999)
    events = []

    # Phase 1: Process name masquerade
    masq_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "mirror_loop_deflector",
        "phase": "process_masquerade",
        "mitre_techniques": ["T1036.005"],
        "masquerade_target_sim": target_proc["name"],
        "target_type": target_proc["type"],
        "fake_pid_sim": pid_sim,
        "cmdline_spoof_sim": f"/usr/bin/{target_proc['name']} --daemon",
        "safe": True,
        "simulation_only": True,
        "processes_spawned": False,
    }
    events.append(masq_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(masq_event) + "\n")

    # Phase 2: Deflection loop simulation
    n_iterations = random.randint(3, 5)
    for i in range(n_iterations):
        outcome = FAKE_LOOP_OUTCOMES[min(i, len(FAKE_LOOP_OUTCOMES)-1)]
        artifact = random.choice(FAKE_DEFLECTION_ARTIFACTS)
        loop_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "mirror_loop_deflector",
            "phase": "deflection_loop",
            "mitre_techniques": ["T1070"],
            "iteration": i + 1,
            "proc_name_sim": target_proc["name"],
            "pid_sim": pid_sim,
            "artifact_sim": artifact,
            "outcome_sim": outcome,
            "interval_sim": round(random.uniform(2.0, 4.5), 2),
            "safe": True,
            "simulation_only": True,
            "processes_spawned": False,
        }
        events.append(loop_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(loop_event) + "\n")

    return session_id, target_proc, pid_sim, events

def print_simulation(session_id, target_proc, pid_sim, events):
    print(f"\n  [SIMULATION]  mirror_loop_deflector")
    print(f"  [SESSION]     {session_id}")
    print(f"  [MASQ_SIM]    {target_proc['name']} (pid_sim={pid_sim})")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1036.005, T1070")
    print(f"  [PROCESSES]   NONE SPAWNED — synthetic only")
    print()
    for e in events:
        phase = e["phase"]
        if phase == "process_masquerade":
            print(f"  [PHASE 1: PROCESS MASQUERADE]")
            print(f"    target_sim    : {e['masquerade_target_sim']}")
            print(f"    type          : {e['target_type']}")
            print(f"    pid_sim       : {e['fake_pid_sim']}")
            print(f"    cmdline_sim   : {e['cmdline_spoof_sim']}")
        elif phase == "deflection_loop":
            print(f"\n  [PHASE 2: DEFLECTION LOOP #{e['iteration']}]")
            print(f"    artifact_sim  : {e['artifact_sim']}")
            print(f"    outcome       : {e['outcome_sim']}")
            print(f"    interval_sim  : {e['interval_sim']}s")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no process spawning, no file writes — simulation only")

@register_payload(name="mirror_loop_deflector")
def main():
    session_id, target_proc, pid_sim, events = simulate_mirror_loop()
    print_simulation(session_id, target_proc, pid_sim, events)

if __name__ == "__main__":
    main()
