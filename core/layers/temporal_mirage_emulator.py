from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Temporal Mirage Emulator — synthetic clock drift and timestamp forgery simulator
# PURPOSE: Emit realistic-shaped timestamp manipulation telemetry for detection testing
# PRINCIPLE: Represent adversarial shape without adversarial capability
# MITRE: T1070 (Indicator Removal), T1036 (Masquerading)
# NO FILE WRITES — no real timestamp changes, no utime calls

import os
import json
import uuid
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path

from core.config import artifact_log_path as _artifact_log_path

def _get_artifact_log():
    p = _artifact_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

FAKE_TIMESTAMP_TARGETS = [
    {"path": "/var/log/auth.log",          "type": "system_log"},
    {"path": "/var/log/syslog",            "type": "system_log"},
    {"path": "~/.bash_history",            "type": "shell_history"},
    {"path": "/tmp/cache_file",            "type": "temp_file"},
    {"path": "/etc/cron.d/syscheck",       "type": "cron_job"},
    {"path": "C:\\Windows\\System32\\evil.dll", "type": "pe_binary"},
]

FAKE_DRIFT_DIRECTIONS = [
    "past_24h", "past_7d", "past_30d", "future_1h", "epoch_reset"
]

FAKE_CLOCK_SOURCES = [
    "ntp_spoof_sim", "hwclock_drift_sim", "kernel_time_sim", "fake_rtc_sim"
]

def _fake_drift_time(direction):
    now = datetime.now(timezone.utc)
    if direction == "past_24h":
        return now - timedelta(hours=random.randint(1, 24))
    elif direction == "past_7d":
        return now - timedelta(days=random.randint(1, 7))
    elif direction == "past_30d":
        return now - timedelta(days=random.randint(7, 30))
    elif direction == "future_1h":
        return now + timedelta(hours=random.randint(1, 6))
    else:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)

def simulate_temporal_mirage():
    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: Clock source manipulation
    clock_source = random.choice(FAKE_CLOCK_SOURCES)
    drift_dir = random.choice(FAKE_DRIFT_DIRECTIONS)
    fake_time = _fake_drift_time(drift_dir)
    drift_minutes = int((fake_time - datetime.now(timezone.utc)).total_seconds() / 60)

    clock_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "temporal_mirage_emulator",
        "phase": "clock_drift_sim",
        "mitre_techniques": ["T1070"],
        "behavior_class": "clock_drift_sim",
        "detection_opportunities": ["clock_drift_sim"],
        "clock_source_sim": clock_source,
        "drift_direction_sim": drift_dir,
        "drift_minutes_sim": drift_minutes,
        "fake_time_sim": fake_time.isoformat(),
        "safe": True,
        "simulation_only": True,
        "filesystem_modified": False,
        "system_time_changed": False,
    }
    events.append(clock_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(clock_event) + "\n")

    # Phase 2: Timestamp forgery on files
    targets = random.sample(FAKE_TIMESTAMP_TARGETS, random.randint(2, 4))
    for target in targets:
        forged_time = fake_time + timedelta(seconds=random.randint(-300, 300))
        forge_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "temporal_mirage_emulator",
            "phase": "timestamp_forge",
            "mitre_techniques": ["T1036"],
            "behavior_class": "timestamp_forge",
            "detection_opportunities": ["timestamp_forge"],
            "target_path_sim": target["path"],
            "target_type": target["type"],
            "forged_mtime_sim": forged_time.isoformat(),
            "forged_atime_sim": forged_time.isoformat(),
            "safe": True,
            "simulation_only": True,
            "filesystem_modified": False,
            "system_time_changed": False,
        }
        events.append(forge_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(forge_event) + "\n")

    return session_id, drift_dir, drift_minutes, targets, events

def print_simulation(session_id, drift_dir, drift_minutes, targets, events):
    print(f"\n  [SIMULATION]  temporal_mirage_emulator")
    print(f"  [SESSION]     {session_id}")
    print(f"  [DRIFT_SIM]   {drift_dir} ({drift_minutes:+}min)")
    print(f"  [TARGETS_SIM] {len(targets)}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1070, T1036")
    print(f"  [FILESYSTEM]  NOT MODIFIED — synthetic only")
    print(f"  [SYSTEM_TIME] NOT CHANGED — synthetic only")
    print()
    for e in events:
        phase = e["phase"]
        if phase == "clock_drift_sim":
            print(f"  [PHASE 1: CLOCK DRIFT SIM]")
            print(f"    source_sim    : {e['clock_source_sim']}")
            print(f"    direction_sim : {e['drift_direction_sim']}")
            print(f"    drift_sim     : {e['drift_minutes_sim']:+}min")
            print(f"    fake_time_sim : {e['fake_time_sim'][:19]}")
        elif phase == "timestamp_forge":
            print(f"\n  [PHASE 2: TIMESTAMP FORGE]")
            print(f"    target_sim    : {e['target_path_sim']}")
            print(f"    type          : {e['target_type']}")
            print(f"    forged_mtime  : {e['forged_mtime_sim'][:19]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no file writes, no system time changes — simulation only")

@register_payload(name="temporal_mirage_emulator")
def main():
    session_id, drift_dir, drift_minutes, targets, events = simulate_temporal_mirage()
    print_simulation(session_id, drift_dir, drift_minutes, targets, events)

if __name__ == "__main__":
    main()
