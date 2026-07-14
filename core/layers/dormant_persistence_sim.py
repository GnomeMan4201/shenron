from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Dormant Sleeper Seed — synthetic persistence trigger simulator
# PURPOSE: Emit realistic-shaped persistence and trigger telemetry for detection testing
# PRINCIPLE: Represent adversarial shape without adversarial capability
# MITRE: T1053 (Scheduled Task), T1547 (Boot Autostart)
# NO EXECUTION — no shell calls, no loops, no real trigger monitoring

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
FAKE_TRIGGER_TYPES = [
    "time_based", "file_hash_match", "network_beacon_response",
    "registry_key_change", "user_login_event", "process_termination"
]

FAKE_PERSISTENCE_MECHANISMS = [
    {"type": "scheduled_task",    "path": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache"},
    {"type": "registry_run_key",  "path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
    {"type": "startup_folder",    "path": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"},
    {"type": "systemd_unit",      "path": "/etc/systemd/system/update-check.service"},
    {"type": "cron_job",          "path": "/etc/cron.d/syscheck"},
    {"type": "launchd_plist",     "path": "/Library/LaunchDaemons/com.system.update.plist"},
]

FAKE_TRIGGER_CONDITIONS = [
    {"condition": "time_match",     "value": "03:33:00", "check_interval_sim": 30},
    {"condition": "file_present",   "value": "/tmp/.trigger", "check_interval_sim": 15},
    {"condition": "hash_match",     "value": "md5:badc0ffee00000000", "check_interval_sim": 60},
    {"condition": "port_open",      "value": "localhost:4444", "check_interval_sim": 45},
    {"condition": "env_var_set",    "value": "SHENRON_ARMED=1", "check_interval_sim": 10},
]

FAKE_ACTIVATION_EVENTS = [
    "trigger condition evaluated — not met",
    "trigger condition evaluated — not met",
    "trigger condition evaluated — not met",
    "trigger condition met — activation simulated",
]

# ── Simulation core ───────────────────────────────────────────────────────────
def simulate_sleeper_seed():
    session_id = str(uuid.uuid4())
    events = []

    # Event 1: Persistence installation
    mechanism = random.choice(FAKE_PERSISTENCE_MECHANISMS)
    install_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "dormant_persistence_sim",
        "phase": "persistence_install",
        "mitre_techniques": ["T1053", "T1547"],
        "mechanism_type": mechanism["type"],
        "synthetic_path": mechanism["path"],
        "armed": True,
        "safe": True,
        "simulation_only": True,
        "behavior_class": "persistence_trigger_sim",
        "detection_opportunities": ["scheduled_task_creation", "cron_modification_sim", "autostart_registry_modification_sim", "persistence_mechanism_install_sim"],
        "executable": False,
        "no_payload_present": True,
        "shell_commands_executed": False,
    }
    events.append(install_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(install_event) + "\n")

    # Event 2: Trigger registration
    trigger = random.choice(FAKE_TRIGGER_CONDITIONS)
    trigger_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "dormant_persistence_sim",
        "phase": "trigger_registration",
        "mitre_techniques": ["T1053"],
        "trigger_type": random.choice(FAKE_TRIGGER_TYPES),
        "trigger_condition": trigger["condition"],
        "trigger_value_sim": trigger["value"],
        "check_interval_sim": trigger["check_interval_sim"],
        "safe": True,
        "simulation_only": True,
        "behavior_class": "persistence_trigger_sim",
        "detection_opportunities": ["scheduled_task_creation", "cron_modification_sim", "autostart_registry_modification_sim", "persistence_mechanism_install_sim"],
        "executable": False,
        "no_payload_present": True,
        "shell_commands_executed": False,
    }
    events.append(trigger_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(trigger_event) + "\n")

    # Event 3: Trigger evaluation cycles (simulated, not real loop)
    n_checks = random.randint(2, 4)
    for i in range(n_checks):
        outcome = FAKE_ACTIVATION_EVENTS[min(i, len(FAKE_ACTIVATION_EVENTS)-1)]
        check_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "dormant_persistence_sim",
            "phase": "trigger_evaluation",
            "mitre_techniques": ["T1053"],
            "check_number": i + 1,
            "outcome_sim": outcome,
            "activated": "activation simulated" in outcome,
            "safe": True,
            "simulation_only": True,
        "behavior_class": "persistence_trigger_sim",
        "detection_opportunities": ["scheduled_task_creation", "cron_modification_sim", "autostart_registry_modification_sim", "persistence_mechanism_install_sim"],
        "executable": False,
        "no_payload_present": True,
            "shell_commands_executed": False,
        }
        events.append(check_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(check_event) + "\n")

    return session_id, events

def print_simulation(session_id, events):
    print(f"\n  [SIMULATION]  dormant_persistence_sim")
    print(f"  [SESSION]     {session_id}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1053, T1547")
    print(f"  [NETWORK]     NO CALLS MADE — synthetic only")
    print(f"  [EXECUTION]   NO SHELL COMMANDS — synthetic only")
    print()
    for e in events:
        phase = e["phase"]
        if phase == "persistence_install":
            print(f"  [PHASE 1: PERSISTENCE INSTALL]")
            print(f"    mechanism     : {e['mechanism_type']}")
            print(f"    synthetic_path: {e['synthetic_path']}")
            print(f"    armed         : {e['armed']}")
        elif phase == "trigger_registration":
            print(f"\n  [PHASE 2: TRIGGER REGISTRATION]")
            print(f"    trigger_type  : {e['trigger_type']}")
            print(f"    condition     : {e['trigger_condition']}")
            print(f"    value_sim     : {e['trigger_value_sim']}")
            print(f"    check_interval: {e['check_interval_sim']}s")
        elif phase == "trigger_evaluation":
            print(f"\n  [PHASE 3: TRIGGER EVAL #{e['check_number']}]")
            print(f"    outcome       : {e['outcome_sim']}")
            print(f"    activated     : {e['activated']}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no execution, no loops — simulation artifact only")

@register_payload(name="dormant_persistence_sim")
def main():
    session_id, events = simulate_sleeper_seed()
    print_simulation(session_id, events)

if __name__ == "__main__":
    main()
