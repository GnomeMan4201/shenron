from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Hologram Emitter — fake process and log activity telemetry simulator
# PURPOSE: Emit defender-observable telemetry for synthetic process spoofing patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1036 (Masquerading), T1027 (Obfuscated Files)
# DETECTION NOTES:
#   - Blue teams should alert on: multiple daemon-named threads from single non-daemon process
#   - Fake process entries with PIDs in non-standard ranges (4000-6000)
#   - Log files containing synthetic system events from non-system sources
#   - Memory allocation/deallocation cycles at fixed jitter intervals (fingerprint)
#   - Thread-per-fake-proc pattern with sleep-based activity simulation

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

FAKE_PROCESS_NAMES_SIM = [
    "com.termux.analytics_sim", "update_engine_d_sim",
    "bluetoothd_ble_cache_sim", "usbmuxd_sync_sim",
    "logd.relay_sim", "zygote_shell32_sim",
    "dropbear_sshd_sim", "mdns_cache_sim",
]

FAKE_LOG_EVENTS_SIM = [
    {"source_sim": "systemd_sim",  "event_sim": "Updated timezone rules"},
    {"source_sim": "kernel_sim",   "event_sim": "CPU temperature nominal"},
    {"source_sim": "auditd_sim",   "event_sim": "Audit trail rotation complete"},
    {"source_sim": "cron_sim",     "event_sim": "Finished backup run: user=shd"},
    {"source_sim": "netd_sim",     "event_sim": "DNS resolver reloaded"},
]

HOLOGRAM_BEHAVIOR_CLASSES = [
    "daemon_named_thread_spawn_sim",
    "fake_pid_process_entry_sim",
    "memory_alloc_dealloc_cycle_sim",
]

LOG_MIMIC_BEHAVIOR_CLASSES = [
    "synthetic_system_log_inject_sim",
    "fake_source_log_write_sim",
]

DETECTION_OPPORTUNITIES = [
    "multiple_daemon_named_threads_single_non_daemon_process",
    "fake_process_entries_pid_nonstandard_range_4000_6000",
    "log_synthetic_system_events_from_non_system_source",
    "memory_alloc_dealloc_fixed_jitter_interval_fingerprint",
    "thread_per_fake_proc_sleep_activity_simulation_pattern",
]

def simulate_holo_emitter():
    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: Fake process hologram simulation
    n_procs = random.randint(3, len(FAKE_PROCESS_NAMES_SIM))
    proc_names = random.sample(FAKE_PROCESS_NAMES_SIM, n_procs)

    for proc_name in proc_names:
        pid_sim = random.randint(4000, 6000)
        behavior = random.choice(HOLOGRAM_BEHAVIOR_CLASSES)
        mem_size_sim = random.randint(30000, 60000)

        proc_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "shenron_holo_emitter",
            "phase": "fake_proc_hologram_sim",
            "mitre_techniques": ["T1036"],
            "behavior_class": behavior,
            "proc_name_sim": proc_name,
            "pid_sim": pid_sim,
            "thread_type_sim": "daemon_thread",
            "memory_cycle_sim": f"{mem_size_sim}b alloc → sleep → dealloc",
            "sleep_interval_sim": round(random.uniform(3.0, 6.0), 2),
            "infinite_loop_sim": True,
            "detection_opportunities": [
                "multiple_daemon_named_threads_single_non_daemon_process",
                "fake_process_entries_pid_nonstandard_range_4000_6000",
                "memory_alloc_dealloc_fixed_jitter_interval_fingerprint",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "threads_spawned": False,
            "memory_allocated": False,
        }
        events.append(proc_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(proc_event) + "\n")

    # Phase 2: Fake log activity simulation
    n_log_events = random.randint(3, 6)
    log_events_sim = random.choices(FAKE_LOG_EVENTS_SIM, k=n_log_events)

    log_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "shenron_holo_emitter",
        "phase": "fake_log_activity_sim",
        "mitre_techniques": ["T1027"],
        "behavior_class": random.choice(LOG_MIMIC_BEHAVIOR_CLASSES),
        "target_log_sim": "~/SHENRON/logs/hologram_activity_sim.log",
        "events_count_sim": n_log_events,
        "events_sim": [
            {
                "source_sim": e["source_sim"],
                "event_sim": e["event_sim"],
                "interval_sim": round(random.uniform(2.0, 5.0), 2),
            }
            for e in log_events_sim
        ],
        "loop_type_sim": "infinite_write_loop",
        "detection_opportunities": [
            "log_synthetic_system_events_from_non_system_source",
            "thread_per_fake_proc_sleep_activity_simulation_pattern",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "threads_spawned": False,
        "files_written": False,
    }
    events.append(log_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(log_event) + "\n")

    return session_id, proc_names, events

def print_simulation(session_id, proc_names, events):
    proc_events = [e for e in events if e["phase"] == "fake_proc_hologram_sim"]
    print(f"\n  [SIMULATION]  shenron_holo_emitter")
    print(f"  [SESSION]     {session_id}")
    print(f"  [PROCS_SIM]   {len(proc_names)}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1036, T1027")
    print(f"  [THREADS]     NONE SPAWNED — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no threads, no memory alloc, no log writes")
    print()
    print(f"  [PHASE 1: FAKE PROCESS HOLOGRAMS]")
    for e in proc_events:
        print(f"    pid_sim={e['pid_sim']}  name={e['proc_name_sim']}")
        print(f"      behavior    : {e['behavior_class']}")
        print(f"      mem_sim     : {e['memory_cycle_sim']}")
        print(f"      detection   : {e['detection_opportunities'][0]}")
    for e in events:
        if e["phase"] == "fake_log_activity_sim":
            print(f"\n  [PHASE 2: FAKE LOG ACTIVITY]")
            print(f"    target_sim    : {e['target_log_sim']}")
            print(f"    events_sim    : {e['events_count_sim']}")
            for le in e["events_sim"][:3]:
                print(f"    [{le['source_sim']}] {le['event_sim']}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no threads, no memory alloc, no file writes — telemetry only")

@register_payload(name="shenron_holo_emitter")
def main():
    session_id, proc_names, events = simulate_holo_emitter()
    print_simulation(session_id, proc_names, events)

if __name__ == "__main__":
    main()
