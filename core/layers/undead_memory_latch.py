from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Undead Memory Latch — synthetic process watchdog simulator
# PURPOSE: Emit realistic-shaped process injection and revival telemetry for detection testing
# PRINCIPLE: Represent adversarial shape without adversarial capability
# MITRE: T1055 (Process Injection), T1547 (Boot Autostart)
# NO PROCESS SPAWNING — no subprocess calls, no signal manipulation, no real watchdog

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

# ── Synthetic data pools ──────────────────────────────────────────────────────
FAKE_TARGET_PROCESSES = [
    {"name": "svchost.exe",    "pid_sim": random.randint(800, 1200),  "arch": "x64"},
    {"name": "explorer.exe",   "pid_sim": random.randint(1400, 2000), "arch": "x64"},
    {"name": "lsass.exe",      "pid_sim": random.randint(600, 800),   "arch": "x64"},
    {"name": "winlogon.exe",   "pid_sim": random.randint(500, 700),   "arch": "x64"},
    {"name": "systemd",        "pid_sim": 1,                          "arch": "x64"},
    {"name": "python3",        "pid_sim": random.randint(2000, 5000), "arch": "x64"},
]

FAKE_INJECTION_TECHNIQUES = [
    "dll_injection_sim",
    "process_hollowing_sim",
    "thread_hijacking_sim",
    "apc_injection_sim",
    "reflective_loading_sim",
]

FAKE_REVIVAL_OUTCOMES = [
    "target_process_running — watchdog idle",
    "target_process_running — watchdog idle",
    "target_process_terminated — revival triggered (simulated)",
    "revival_complete — process restarted (simulated)",
]

FAKE_SIGNAL_BLOCKS = ["SIGINT", "SIGTERM", "SIGKILL_sim", "SIGHUP"]

# ── Simulation core ───────────────────────────────────────────────────────────
def simulate_memory_latch():
    session_id = str(uuid.uuid4())
    target = random.choice(FAKE_TARGET_PROCESSES)
    injection_technique = random.choice(FAKE_INJECTION_TECHNIQUES)
    events = []

    # Event 1: Injection attempt
    inject_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "undead_memory_latch",
        "phase": "injection_sim",
        "mitre_techniques": ["T1055"],
        "target_process_sim": target["name"],
        "target_pid_sim": target["pid_sim"],
        "injection_technique_sim": injection_technique,
        "success_sim": random.choice([True, True, False]),
        "safe": True,
        "simulation_only": True,
        "behavior_class": "process_injection_watchdog_sim",
        "detection_opportunities": ["process_injection_attempt_sim", "watchdog_revival_sim", "signal_block_sim", "process_hollowing_sim"],
        "executable": False,
        "no_payload_present": True,
        "processes_spawned": False,
        "signals_manipulated": False,
    }
    events.append(inject_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(inject_event) + "\n")

    # Event 2: Signal blocking simulation
    blocked = random.sample(FAKE_SIGNAL_BLOCKS, random.randint(2, 3))
    cloak_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "undead_memory_latch",
        "phase": "signal_block_sim",
        "mitre_techniques": ["T1055"],
        "signals_blocked_sim": blocked,
        "effect": "process_immune_to_termination_sim",
        "safe": True,
        "simulation_only": True,
        "behavior_class": "process_injection_watchdog_sim",
        "detection_opportunities": ["process_injection_attempt_sim", "watchdog_revival_sim", "signal_block_sim", "process_hollowing_sim"],
        "executable": False,
        "no_payload_present": True,
        "processes_spawned": False,
        "signals_manipulated": False,
    }
    events.append(cloak_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(cloak_event) + "\n")

    # Event 3: Watchdog revival cycles
    n_cycles = random.randint(2, 4)
    for i in range(n_cycles):
        outcome = FAKE_REVIVAL_OUTCOMES[min(i, len(FAKE_REVIVAL_OUTCOMES)-1)]
        watch_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "undead_memory_latch",
            "phase": "watchdog_cycle",
            "mitre_techniques": ["T1547"],
            "cycle": i + 1,
            "target_process_sim": target["name"],
            "outcome_sim": outcome,
            "revival_triggered": "revival triggered" in outcome,
            "check_interval_sim": random.randint(3, 7),
            "safe": True,
            "simulation_only": True,
        "behavior_class": "process_injection_watchdog_sim",
        "detection_opportunities": ["process_injection_attempt_sim", "watchdog_revival_sim", "signal_block_sim", "process_hollowing_sim"],
        "executable": False,
        "no_payload_present": True,
            "processes_spawned": False,
            "signals_manipulated": False,
        }
        events.append(watch_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(watch_event) + "\n")

    return session_id, target, events

def print_simulation(session_id, target, events):
    print(f"\n  [SIMULATION]  undead_memory_latch")
    print(f"  [SESSION]     {session_id}")
    print(f"  [TARGET_SIM]  {target['name']} (pid_sim={target['pid_sim']})")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1055, T1547")
    print(f"  [PROCESSES]   NONE SPAWNED — synthetic only")
    print(f"  [SIGNALS]     NOT MANIPULATED — synthetic only")
    print()
    for e in events:
        phase = e["phase"]
        if phase == "injection_sim":
            print(f"  [PHASE 1: INJECTION SIM]")
            print(f"    target        : {e['target_process_sim']} pid={e['target_pid_sim']}")
            print(f"    technique_sim : {e['injection_technique_sim']}")
            print(f"    success_sim   : {e['success_sim']}")
        elif phase == "signal_block_sim":
            print(f"\n  [PHASE 2: SIGNAL BLOCK SIM]")
            print(f"    blocked_sim   : {', '.join(e['signals_blocked_sim'])}")
            print(f"    effect_sim    : {e['effect']}")
        elif phase == "watchdog_cycle":
            print(f"\n  [PHASE 3: WATCHDOG CYCLE #{e['cycle']}]")
            print(f"    outcome       : {e['outcome_sim']}")
            print(f"    revival       : {e['revival_triggered']}")
            print(f"    interval_sim  : {e['check_interval_sim']}s")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no process spawning, no signal manipulation — simulation only")

@register_payload(name="undead_memory_latch")
def main():
    session_id, target, events = simulate_memory_latch()
    print_simulation(session_id, target, events)

if __name__ == "__main__":
    main()
