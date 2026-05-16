from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Neural Entropy Seeder — ML-targeted entropy seeding telemetry simulator
# PURPOSE: Emit defender-observable telemetry for ML model confusion and entropy seeding patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1027 (Obfuscated Files), T1036 (Masquerading)
# DETECTION NOTES:
#   - Blue teams should alert on: structured noise injected into paths ML/SIEM systems monitor
#   - High-entropy synthetic log entries that match real log schema but contain noise data
#   - Entropy seeds timed to coincide with known ML model retraining windows
#   - Files with neural-noise patterns in monitored directories

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

FAKE_ML_TARGET_PATHS_SIM = [
    "/var/log/syslog_sim",
    "/var/log/auth.log_sim",
    "/var/log/kern.log_sim",
    "~/SHENRON/logs/ml_feed_sim.log",
]

NEURAL_SEED_PATTERNS = [
    "gaussian_noise_pattern_sim",
    "adversarial_feature_injection_sim",
    "distribution_shift_seed_sim",
    "boundary_case_poison_sim",
    "label_confusion_seed_sim",
]

SEED_TIMING_BEHAVIORS = [
    "timed_to_model_retrain_window_sim",
    "burst_during_low_baseline_sim",
    "gradual_drift_injection_sim",
]

DETECTION_OPPORTUNITIES = [
    "structured_noise_in_ml_monitored_paths",
    "high_entropy_log_entries_matching_real_schema",
    "entropy_seed_timing_coincides_model_retrain_window",
    "neural_noise_pattern_in_monitored_directory",
    "distribution_shift_in_log_feature_space",
]

def _sim_neural_pattern():
    return hashlib.sha256(os.urandom(16)).hexdigest()

def simulate_neural_seeder():
    session_id = str(uuid.uuid4())
    events = []

    seed_timing = random.choice(SEED_TIMING_BEHAVIORS)
    n_seeds = random.randint(4, 8)
    targets = random.sample(FAKE_ML_TARGET_PATHS_SIM, random.randint(2, 3))

    # Phase 1: Seeding session init
    init_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "neural_entropy_seeder",
        "phase": "seed_session_init",
        "mitre_techniques": ["T1027"],
        "behavior_class": "neural_seed_session_init_sim",
        "target_paths_sim": targets,
        "seed_timing_behavior_sim": seed_timing,
        "planned_seeds_sim": n_seeds,
        "detection_opportunities": [
            "entropy_seed_timing_coincides_model_retrain_window",
            "structured_noise_in_ml_monitored_paths",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "files_created": False,
    }
    events.append(init_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(init_event) + "\n")

    # Phase 2: Seed injection events
    for i in range(min(n_seeds, 5)):
        pattern = random.choice(NEURAL_SEED_PATTERNS)
        target = random.choice(targets)
        seed_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "neural_entropy_seeder",
            "phase": "seed_injection",
            "mitre_techniques": ["T1036"],
            "behavior_class": pattern,
            "seed_index": i + 1,
            "target_sim": target,
            "neural_pattern_sim": _sim_neural_pattern(),
            "entropy_score_sim": round(random.uniform(0.87, 0.99), 4),
            "schema_match_sim": True,
            "detection_opportunities": [
                "high_entropy_log_entries_matching_real_schema",
                "neural_noise_pattern_in_monitored_directory",
                "distribution_shift_in_log_feature_space",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "files_created": False,
        }
        events.append(seed_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(seed_event) + "\n")

    return session_id, targets, events

def print_simulation(session_id, targets, events):
    print(f"\n  [SIMULATION]  neural_entropy_seeder")
    print(f"  [SESSION]     {session_id}")
    print(f"  [TARGETS_SIM] {len(targets)}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1027, T1036")
    print(f"  [FILES]       NOT WRITTEN — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no file writes, no model interaction")
    print()
    for e in events:
        if e["phase"] == "seed_session_init":
            print(f"  [PHASE 1: SESSION INIT]")
            print(f"    targets_sim   : {e['target_paths_sim']}")
            print(f"    timing_sim    : {e['seed_timing_behavior_sim']}")
            print(f"    seeds_sim     : {e['planned_seeds_sim']}")
        elif e["phase"] == "seed_injection":
            print(f"\n  [SEED #{e['seed_index']}] {e['behavior_class']}")
            print(f"    target_sim    : {e['target_sim']}")
            print(f"    entropy_sim   : {e['entropy_score_sim']}")
            print(f"    schema_match  : {e['schema_match_sim']}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no file writes — telemetry only")

@register_payload(name="neural_entropy_seeder")
def main():
    session_id, targets, events = simulate_neural_seeder()
    print_simulation(session_id, targets, events)

if __name__ == "__main__":
    main()
