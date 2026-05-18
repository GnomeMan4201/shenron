from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Quantum State Shuffler — payload hash randomization telemetry simulator
# PURPOSE: Emit defender-observable telemetry for dynamic payload state shuffling
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1027 (Obfuscated Files), T1001 (Data Obfuscation)
# DETECTION NOTES:
#   - Blue teams should alert on: multiple binary files with salted-hash names in single dir
#   - Payload directory containing .bin files with MD5-derived names (evasion fingerprint)
#   - Frequent hash-renamed file creation in stealth payload directories
#   - State shuffle output directory appearing alongside known bad paths

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

FAKE_PAYLOAD_DIR_SIM = "~/SHENRON/core/payloads/stealth_sim/"
FAKE_SHUFFLED_DIR_SIM = "~/SHENRON/core/payloads/shuffled_states_sim/"

FAKE_PAYLOAD_NAMES_SIM = [
    "stealth_beacon_sim.py", "persist_hook_sim.py",
    "signal_relay_sim.py", "revival_stub_sim.py"
]

SHUFFLE_BEHAVIOR_CLASSES = [
    "salt_hash_rename_sim",
    "binary_state_derive_sim",
    "shuffled_output_write_sim",
]

DETECTION_OPPORTUNITIES = [
    "multiple_bin_files_salted_hash_names_single_dir",
    "md5_derived_filename_pattern_in_payload_dir",
    "frequent_hash_renamed_file_creation_stealth_dir",
    "shuffle_output_dir_adjacent_to_known_bad_path",
]

def _sim_hash():
    return hashlib.sha256(os.urandom(16)).hexdigest()

def _sim_md5():
    return hashlib.md5(os.urandom(16)).hexdigest()

def simulate_state_shuffler():
    session_id = str(uuid.uuid4())
    events = []

    payloads = random.sample(FAKE_PAYLOAD_NAMES_SIM,
                             random.randint(2, len(FAKE_PAYLOAD_NAMES_SIM)))

    # Phase 1: Directory scan
    scan_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "quantum_state_shuffler",
        "phase": "payload_dir_scan",
        "mitre_techniques": ["T1027"],
        "behavior_class": "payload_directory_enumerate_sim",
        "source_dir_sim": FAKE_PAYLOAD_DIR_SIM,
        "output_dir_sim": FAKE_SHUFFLED_DIR_SIM,
        "payloads_found_sim": len(payloads),
        "payload_names_sim": payloads,
        "detection_opportunities": [
            "shuffle_output_dir_adjacent_to_known_bad_path",
            "payload_dir_enumerate_from_non_build_process",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "files_created": False,
    }
    events.append(scan_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(scan_event) + "\n")

    # Phase 2: Shuffle per payload
    for payload_sim in payloads:
        salt_sim = _sim_hash()[:32]
        shuffled_hash_sim = _sim_hash()
        output_name_sim = _sim_md5() + "_sim.bin"
        shuffle_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "quantum_state_shuffler",
            "phase": "state_shuffle",
            "mitre_techniques": ["T1001"],
            "behavior_class": "salt_hash_shuffle_derive_sim",
            "source_payload_sim": payload_sim,
            "source_path_sim": f"{FAKE_PAYLOAD_DIR_SIM}{payload_sim}",
            "salt_sim": salt_sim,
            "shuffled_hash_sim": shuffled_hash_sim,
            "output_name_sim": output_name_sim,
            "output_path_sim": f"{FAKE_SHUFFLED_DIR_SIM}{output_name_sim}",
            "detection_opportunities": [
                "multiple_bin_files_salted_hash_names_single_dir",
                "md5_derived_filename_pattern_in_payload_dir",
                "frequent_hash_renamed_file_creation_stealth_dir",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "files_created": False,
        }
        events.append(shuffle_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(shuffle_event) + "\n")

    return session_id, payloads, events

def print_simulation(session_id, payloads, events):
    print(f"\n  [SIMULATION]  quantum_state_shuffler")
    print(f"  [SESSION]     {session_id}")
    print(f"  [PAYLOADS]    {len(payloads)}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1027, T1001")
    print(f"  [FILES]       NOT CREATED — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no file reads or writes")
    print()
    for e in events:
        if e["phase"] == "payload_dir_scan":
            print(f"  [PHASE 1: DIR SCAN]")
            print(f"    source_sim    : {e['source_dir_sim']}")
            print(f"    output_sim    : {e['output_dir_sim']}")
            for p in e["payload_names_sim"]:
                print(f"      {p}")
        elif e["phase"] == "state_shuffle":
            print(f"\n  [SHUFFLE] {e['source_payload_sim']}")
            print(f"    salt_sim      : {e['salt_sim'][:16]}...")
            print(f"    output_sim    : {e['output_name_sim']}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no file reads or writes — telemetry only")

@register_payload(name="quantum_state_shuffler")
def main():
    session_id, payloads, events = simulate_state_shuffler()
    print_simulation(session_id, payloads, events)

if __name__ == "__main__":
    main()
