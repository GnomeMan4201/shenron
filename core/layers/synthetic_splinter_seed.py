from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Synthetic Splinter Seed — polymorphic micro-propagation telemetry simulator
# PURPOSE: Emit defender-observable telemetry for worm-style seed propagation patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1027 (Obfuscated Files), T1105 (Ingress Tool Transfer)
# DETECTION NOTES:
#   - Blue teams should alert on: base64-encoded shell scripts dropped to media/shared paths
#   - Hidden dot-prefixed .sh files with chmod 700 in shared storage directories
#   - Self-decoding execution chains (base64 -d | bash pattern) in dropped files
#   - Splinter seeds in DCIM, Music, Downloads — unusual executable presence
#   - Log entries tracking successful seed drops with timestamps
# NOTE: Original implementation contained executable embedded bash payload.
#       This simulator represents the tradecraft shape as non-executable telemetry.
#       No shell code, no base64-encoded payloads, no seed files are produced.

import os
import json
import uuid
import random
import hashlib
import base64
from datetime import datetime, timezone
from pathlib import Path

ARTIFACT_LOG = Path("/home/gnomeman4201/SHENRON/logs/simulation_artifacts.jsonl")

def _get_artifact_log():
    ARTIFACT_LOG.parent.mkdir(parents=True, exist_ok=True)
    return ARTIFACT_LOG

FAKE_DEPLOY_PATHS_SIM = [
    "~/storage/shared/Documents_sim/",
    "~/storage/shared/Download_sim/",
    "~/storage/shared/Music_sim/",
    "~/storage/shared/DCIM_sim/",
    "~/SHENRON/.stealth_seeds_sim/",
]

SEED_BEHAVIOR_CLASSES = [
    "base64_encoded_script_drop_sim",
    "self_decoding_exec_chain_drop_sim",
    "trigger_file_plant_sim",
]

ENCODED_PAYLOAD_DESCRIPTIONS = [
    "bash_script_with_marker_touch_sim",
    "shell_activation_trigger_sim",
    "persistence_hook_script_sim",
]

DETECTION_OPPORTUNITIES = [
    "base64_encoded_shell_script_in_shared_media_path",
    "hidden_dotfile_sh_chmod700_shared_storage",
    "self_decoding_exec_chain_base64_d_pipe_bash_pattern",
    "executable_seed_in_dcim_music_downloads",
    "splinter_log_tracking_drop_timestamps",
    "base64_encoded_payload_string_in_dropped_file",
]

def _sim_encoded_payload_shape():
    raw = os.urandom(64)
    return base64.b64encode(raw).decode()

def _sim_hash():
    return hashlib.md5(os.urandom(8)).hexdigest()

def simulate_splinter_seed():
    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: Payload encoding simulation
    payload_desc = random.choice(ENCODED_PAYLOAD_DESCRIPTIONS)
    encoded_shape_sim = _sim_encoded_payload_shape()

    encode_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "synthetic_splinter_seed",
        "phase": "payload_encoding_sim",
        "mitre_techniques": ["T1027"],
        "behavior_class": "base64_payload_encode_sim",
        "payload_description_sim": payload_desc,
        "encoded_shape_sim": encoded_shape_sim,
        "encoded_length_sim": len(encoded_shape_sim),
        "encoding_method_sim": "base64_standard",
        "command_string_present": False,
        "shell_code_present": False,
        "detection_opportunities": [
            "base64_encoded_payload_string_in_dropped_file",
            "self_decoding_exec_chain_base64_d_pipe_bash_pattern",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "files_created": False,
    }
    events.append(encode_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(encode_event) + "\n")

    # Phase 2: Seed drop simulation per path
    for path_sim in FAKE_DEPLOY_PATHS_SIM:
        seed_filename_sim = f".seed_{random.randint(1000,9999)}_sim.sh"
        full_path_sim = path_sim + seed_filename_sim
        behavior = random.choice(SEED_BEHAVIOR_CLASSES)

        drop_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "synthetic_splinter_seed",
            "phase": "seed_drop_sim",
            "mitre_techniques": ["T1105"],
            "behavior_class": behavior,
            "deploy_path_sim": path_sim,
            "seed_filename_sim": seed_filename_sim,
            "full_seed_path_sim": full_path_sim,
            "perms_sim": "chmod_700",
            "content_shape_sim": "base64_decode_pipe_exec_chain_sim",
            "log_entry_written_sim": True,
            "log_path_sim": "~/SHENRON/logs/splinter_seed_sim.log",
            "command_string_present": False,
            "shell_code_present": False,
            "detection_opportunities": [
                "base64_encoded_shell_script_in_shared_media_path",
                "hidden_dotfile_sh_chmod700_shared_storage",
                "executable_seed_in_dcim_music_downloads",
                "splinter_log_tracking_drop_timestamps",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "files_created": False,
        }
        events.append(drop_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(drop_event) + "\n")

    return session_id, events

def print_simulation(session_id, events):
    drops = [e for e in events if e["phase"] == "seed_drop_sim"]
    print(f"\n  [SIMULATION]  synthetic_splinter_seed")
    print(f"  [SESSION]     {session_id}")
    print(f"  [SEEDS_SIM]   {len(drops)} paths")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1027, T1105")
    print(f"  [FILES]       NOT CREATED — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no shell code, no base64 payloads, no chmod")
    print()
    for e in events:
        if e["phase"] == "payload_encoding_sim":
            print(f"  [PHASE 1: PAYLOAD ENCODING SIM]")
            print(f"    desc_sim      : {e['payload_description_sim']}")
            print(f"    encoded_len   : {e['encoded_length_sim']} chars")
            print(f"    method_sim    : {e['encoding_method_sim']}")
            print(f"    shell_code    : {e['shell_code_present']} ← no payload in telemetry")
            print(f"    detection     : {e['detection_opportunities'][0]}")
        elif e["phase"] == "seed_drop_sim":
            print(f"\n  [SEED DROP] {e['deploy_path_sim']}")
            print(f"    filename_sim  : {e['seed_filename_sim']}")
            print(f"    behavior      : {e['behavior_class']}")
            print(f"    perms_sim     : {e['perms_sim']}")
            print(f"    content_sim   : {e['content_shape_sim']}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no shell code, no chmod, no file drops — telemetry only")

@register_payload(name="synthetic_splinter_seed")
def main():
    session_id, events = simulate_splinter_seed()
    print_simulation(session_id, events)

if __name__ == "__main__":
    main()
