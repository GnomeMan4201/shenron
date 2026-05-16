from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Entropy Flux Disruptor — ML/SIEM confusion telemetry simulator
# PURPOSE: Emit defender-observable telemetry for multi-vector entropy disruption patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1027.002 (Software Packing / entropy manipulation)
# DETECTION NOTES:
#   - Blue teams should alert on: simultaneous I/O, CPU, and memory anomalies from single process
#   - High-volume hash writes to log files with no corresponding application activity
#   - CPU spike threads spawned at same time as I/O burst — multi-vector signature
#   - Memory allocation patterns inconsistent with process type
#   - Timer-based sleep jitter from non-timer processes

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

DISRUPTION_VECTORS = [
    {
        "vector": "io_noise_sim",
        "desc": "burst hash writes to log file",
        "detection": "high_volume_hash_writes_no_application_activity",
    },
    {
        "vector": "cpu_spike_sim",
        "desc": "compute-intensive loop threads",
        "detection": "cpu_spike_threads_concurrent_with_io_burst",
    },
    {
        "vector": "mem_noise_sim",
        "desc": "large buffer allocation and deallocation",
        "detection": "memory_alloc_pattern_inconsistent_with_process_type",
    },
    {
        "vector": "timer_jitter_sim",
        "desc": "random sleep intervals from non-timer process",
        "detection": "sleep_jitter_from_non_timer_process",
    },
]

DETECTION_OPPORTUNITIES = [
    "simultaneous_io_cpu_memory_anomalies_single_process",
    "high_volume_hash_writes_no_corresponding_application_activity",
    "cpu_spike_concurrent_with_io_burst_multi_vector_signature",
    "memory_allocation_inconsistent_with_process_type",
]

def _sim_hash():
    return hashlib.sha512(os.urandom(32)).hexdigest()[:32]

def simulate_flux_disruptor():
    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: Multi-vector disruption launch
    selected_vectors = random.sample(DISRUPTION_VECTORS, random.randint(2, 4))
    launch_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "entropy_flux_disruptor",
        "phase": "disruption_launch",
        "mitre_techniques": ["T1027.002"],
        "behavior_class": "multi_vector_entropy_disruption_sim",
        "vectors_active_sim": [v["vector"] for v in selected_vectors],
        "thread_count_sim": len(selected_vectors),
        "concurrent_launch_sim": True,
        "detection_opportunities": [
            "simultaneous_io_cpu_memory_anomalies_single_process",
            "cpu_spike_concurrent_with_io_burst_multi_vector_signature",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "threads_spawned": False,
    }
    events.append(launch_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(launch_event) + "\n")

    # Phase 2: Per-vector telemetry
    for vector in selected_vectors:
        vector_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "entropy_flux_disruptor",
            "phase": "vector_execution_sim",
            "mitre_techniques": ["T1027.002"],
            "behavior_class": vector["vector"],
            "vector_desc": vector["desc"],
            "magnitude_sim": random.randint(10, 100),
            "duration_sim": round(random.uniform(1.0, 5.0), 2),
            "hash_sample_sim": _sim_hash() if "io" in vector["vector"] else None,
            "buffer_size_sim": random.randint(256, 4096) if "mem" in vector["vector"] else None,
            "sleep_jitter_sim": round(random.uniform(0.05, 2.0), 3) if "timer" in vector["vector"] else None,
            "detection_opportunities": [
                vector["detection"],
                "simultaneous_io_cpu_memory_anomalies_single_process",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "threads_spawned": False,
        }
        events.append(vector_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(vector_event) + "\n")

    return session_id, selected_vectors, events

def print_simulation(session_id, selected_vectors, events):
    print(f"\n  [SIMULATION]  entropy_flux_disruptor")
    print(f"  [SESSION]     {session_id}")
    print(f"  [VECTORS_SIM] {len(selected_vectors)}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1027.002")
    print(f"  [THREADS]     NONE SPAWNED — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no thread launch, no I/O, no CPU spike")
    print()
    for e in events:
        if e["phase"] == "disruption_launch":
            print(f"  [PHASE 1: DISRUPTION LAUNCH]")
            print(f"    vectors_sim   : {e['vectors_active_sim']}")
            print(f"    concurrent    : {e['concurrent_launch_sim']}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
        elif e["phase"] == "vector_execution_sim":
            print(f"\n  [VECTOR: {e['behavior_class']}]")
            print(f"    desc          : {e['vector_desc']}")
            print(f"    magnitude_sim : {e['magnitude_sim']}")
            print(f"    duration_sim  : {e['duration_sim']}s")
            if e.get("hash_sample_sim"):
                print(f"    hash_sim      : {e['hash_sample_sim'][:16]}...")
            print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no threads, no I/O — telemetry only")

@register_payload(name="entropy_flux_disruptor")
def main():
    session_id, selected_vectors, events = simulate_flux_disruptor()
    print_simulation(session_id, selected_vectors, events)

if __name__ == "__main__":
    main()
