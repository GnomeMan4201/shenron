from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Quantum Entropy Distorter — entropy injection telemetry simulator
# PURPOSE: Emit defender-observable telemetry for entropy manipulation and signal noise patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1027 (Obfuscated Files), T1001 (Data Obfuscation)
# DETECTION NOTES:
#   - Blue teams should alert on: log files with artificially high entropy content
#   - Burst writes to log files from non-logging processes
#   - Synthetic entropy patterns that don't match real system entropy sources
#   - Processes generating high-entropy output at regular intervals (timing fingerprint)

import os
import json
import uuid
import random
import hashlib
from datetime import datetime, timezone
from pathlib import Path

ARTIFACT_LOG = Path("/home/gnomeman4201/SHENRON/logs/simulation_artifacts.jsonl")

def _get_artifact_log():
    ARTIFACT_LOG.parent.mkdir(parents=True, exist_ok=True)
    return ARTIFACT_LOG

ENTROPY_ACTION_CLASSES = [
    "entropy_injected_sim",
    "memory_defrag_ghosted_sim",
    "pseudo_thread_resync_sim",
    "signal_noise_amplified_sim",
    "decoy_interrupt_burst_sim",
    "temporal_splay_vector_sim",
]

LOG_TARGET_BEHAVIORS_SIM = [
    "burst_write_to_log_non_logging_process_sim",
    "high_entropy_pattern_write_sim",
    "timing_fingerprint_interval_write_sim",
]

DETECTION_OPPORTUNITIES = [
    "log_file_high_entropy_content_non_logging_source",
    "burst_writes_to_log_from_non_logging_process",
    "synthetic_entropy_pattern_not_matching_system_sources",
    "process_generating_high_entropy_output_regular_interval",
]

def _sim_entropy_pattern():
    return hashlib.sha256(os.urandom(16)).hexdigest()[:random.randint(12, 32)]

def simulate_entropy_distorter():
    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: Distortion session init
    log_behavior = random.choice(LOG_TARGET_BEHAVIORS_SIM)
    n_events = random.randint(5, 12)

    init_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "quantum_entropy_distorter",
        "phase": "distortion_init",
        "mitre_techniques": ["T1027"],
        "behavior_class": log_behavior,
        "target_log_sim": "~/SHENRON/logs/entropy_distort_sim.log",
        "planned_event_count_sim": n_events,
        "write_interval_sim": round(random.uniform(0.5, 1.5), 2),
        "detection_opportunities": [
            "burst_writes_to_log_from_non_logging_process",
            "timing_fingerprint_interval_write_sim",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "files_created": False,
    }
    events.append(init_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(init_event) + "\n")

    # Phase 2: Entropy event sequence
    for i in range(min(n_events, 6)):
        action = random.choice(ENTROPY_ACTION_CLASSES)
        pattern_sim = _sim_entropy_pattern()
        entropy_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "quantum_entropy_distorter",
            "phase": "entropy_injection",
            "mitre_techniques": ["T1001"],
            "behavior_class": action,
            "event_index": i + 1,
            "entropy_pattern_sim": pattern_sim,
            "pattern_entropy_score_sim": round(random.uniform(0.88, 0.98), 4),
            "write_target_sim": "~/SHENRON/logs/entropy_distort_sim.log",
            "interval_sim": round(random.uniform(0.5, 1.5), 2),
            "detection_opportunities": [
                "log_file_high_entropy_content_non_logging_source",
                "synthetic_entropy_pattern_not_matching_system_sources",
                "process_generating_high_entropy_output_regular_interval",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "files_created": False,
        }
        events.append(entropy_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(entropy_event) + "\n")

    return session_id, n_events, events

def print_simulation(session_id, n_events, events):
    print(f"\n  [SIMULATION]  quantum_entropy_distorter")
    print(f"  [SESSION]     {session_id}")
    print(f"  [EVENTS_SIM]  {n_events} planned, {len(events)-1} emitted")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1027, T1001")
    print(f"  [FILES]       NOT WRITTEN — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no file writes, no sleep loops")
    print()
    for e in events:
        if e["phase"] == "distortion_init":
            print(f"  [PHASE 1: DISTORTION INIT]")
            print(f"    behavior      : {e['behavior_class']}")
            print(f"    target_sim    : {e['target_log_sim']}")
            print(f"    interval_sim  : {e['write_interval_sim']}s")
        elif e["phase"] == "entropy_injection":
            print(f"\n  [EVENT #{e['event_index']}] {e['behavior_class']}")
            print(f"    pattern_sim   : {e['entropy_pattern_sim']}")
            print(f"    entropy_score : {e['pattern_entropy_score_sim']}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no file writes, no sleep — telemetry only")

@register_payload(name="quantum_entropy_distorter")
def main():
    session_id, n_events, events = simulate_entropy_distorter()
    print_simulation(session_id, n_events, events)

if __name__ == "__main__":
    main()
