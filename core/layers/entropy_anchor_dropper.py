from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Entropy Anchor Dropper — timing camouflage and noise file telemetry simulator
# PURPOSE: Emit defender-observable telemetry for entropy anchoring and noise artifact patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1027 (Obfuscated Files), T1140 (Deobfuscate/Decode)
# DETECTION NOTES:
#   - Blue teams should alert on: temp files created and deleted within short windows
#   - Noise files in hidden subdirectories of ~/.shenron/, ~/.noise/
#   - Artificial timing delays with fixed random range (jitter fingerprint)
#   - Hash writes to anchor log from non-hashing process
#   - Create-write-delete file lifecycle under 5 seconds

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

NOISE_DIR_SIM = "~/SHENRON/.noise_sim/"
ANCHOR_LOG_SIM = "~/SHENRON/logs/entropy_anchor_sim.log"

ANCHOR_BEHAVIOR_CLASSES = [
    "junk_hash_write_to_anchor_log_sim",
    "temp_noise_file_create_delete_cycle_sim",
    "timing_jitter_decoy_sleep_sim",
]

DETECTION_OPPORTUNITIES = [
    "temp_file_create_delete_under_5s_hidden_dir",
    "noise_files_in_hidden_dotdir_shenron_noise",
    "artificial_timing_delay_fixed_random_range_fingerprint",
    "hash_writes_to_anchor_log_non_hashing_process",
    "create_write_delete_lifecycle_fast_cycle",
]

def _sim_hash():
    return hashlib.sha256(os.urandom(16)).hexdigest()

def simulate_anchor_dropper():
    session_id = str(uuid.uuid4())
    events = []

    n_rounds = 2
    for round_idx in range(n_rounds):
        # Entropy hash generation sim
        hash_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "entropy_anchor_dropper",
            "phase": "entropy_hash_gen",
            "mitre_techniques": ["T1027"],
            "behavior_class": "junk_hash_write_to_anchor_log_sim",
            "round": round_idx + 1,
            "junk_input_length_sim": 512,
            "hash_output_sim": _sim_hash(),
            "write_target_sim": ANCHOR_LOG_SIM,
            "detection_opportunities": [
                "hash_writes_to_anchor_log_non_hashing_process",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "files_created": False,
        }
        events.append(hash_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(hash_event) + "\n")

        # Timing delay sim
        delay_sim = random.randint(5, 15)
        delay_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "entropy_anchor_dropper",
            "phase": "timing_delay_sim",
            "mitre_techniques": ["T1027"],
            "behavior_class": "timing_jitter_decoy_sleep_sim",
            "round": round_idx + 1,
            "delay_sim": delay_sim,
            "delay_range_sim": "5-15s",
            "detection_opportunities": [
                "artificial_timing_delay_fixed_random_range_fingerprint",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "files_created": False,
        }
        events.append(delay_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(delay_event) + "\n")

        # Noise file lifecycle sim
        n_noise = 3
        for i in range(n_noise):
            fname_sim = f"noise_{random.randint(1000,9999)}_sim.tmp"
            lifecycle_event = {
                "artifact_id": str(uuid.uuid4()),
                "session_id": session_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "layer": "entropy_anchor_dropper",
                "phase": "noise_file_lifecycle_sim",
                "mitre_techniques": ["T1140"],
                "behavior_class": "temp_noise_file_create_delete_cycle_sim",
                "round": round_idx + 1,
                "noise_index": i + 1,
                "noise_dir_sim": NOISE_DIR_SIM,
                "filename_sim": fname_sim,
                "full_path_sim": f"{NOISE_DIR_SIM}{fname_sim}",
                "lifecycle_duration_sim": round(random.uniform(0.5, 2.0), 2),
                "content_sim": _sim_hash(),
                "deleted_after_write_sim": True,
                "detection_opportunities": [
                    "temp_file_create_delete_under_5s_hidden_dir",
                    "noise_files_in_hidden_dotdir_shenron_noise",
                    "create_write_delete_lifecycle_fast_cycle",
                ],
                "simulation_only": True,
                "executable": False,
                "no_payload_present": True,
                "files_created": False,
            }
            events.append(lifecycle_event)
            with open(_get_artifact_log(), "a") as f:
                f.write(json.dumps(lifecycle_event) + "\n")

    return session_id, n_rounds, events

def print_simulation(session_id, n_rounds, events):
    print(f"\n  [SIMULATION]  entropy_anchor_dropper")
    print(f"  [SESSION]     {session_id}")
    print(f"  [ROUNDS_SIM]  {n_rounds}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1027, T1140")
    print(f"  [FILES]       NOT CREATED — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no file writes, no sleep, no delete")
    print()
    for e in events:
        phase = e["phase"]
        if phase == "entropy_hash_gen":
            print(f"  [ROUND {e['round']} | HASH GEN]")
            print(f"    hash_sim      : {e['hash_output_sim'][:24]}...")
            print(f"    target_sim    : {e['write_target_sim']}")
        elif phase == "timing_delay_sim":
            print(f"  [ROUND {e['round']} | TIMING DELAY]")
            print(f"    delay_sim     : {e['delay_sim']}s ({e['delay_range_sim']})")
            print(f"    detection     : {e['detection_opportunities'][0]}")
        elif phase == "noise_file_lifecycle_sim":
            print(f"  [ROUND {e['round']} | NOISE FILE #{e['noise_index']}]")
            print(f"    path_sim      : {e['full_path_sim']}")
            print(f"    lifecycle_sim : {e['lifecycle_duration_sim']}s → deleted")
            print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no file writes, no sleep, no delete — telemetry only")

@register_payload(name="entropy_anchor_dropper")
def main():
    session_id, n_rounds, events = simulate_anchor_dropper()
    print_simulation(session_id, n_rounds, events)

if __name__ == "__main__":
    main()
