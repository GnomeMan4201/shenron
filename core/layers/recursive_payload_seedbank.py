from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Recursive Payload Seedbank — nested payload planting telemetry simulator
# PURPOSE: Emit defender-observable telemetry for recursive hidden directory payload burial
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1027 (Obfuscated Files), T1547 (Boot or Logon Autostart)
# DETECTION NOTES:
#   - Blue teams should alert on: deeply nested hidden directories in shared writable paths
#   - Dot-prefixed directories created recursively (obfuscation via depth)
#   - Shell scripts with timestamps backdated 2+ days
#   - Executable scripts planted in Documents/Downloads/shared directories
#   - chmod +x on hidden files in shared storage paths

import os
import json
import uuid
import random
import string
from datetime import datetime, timezone, timedelta
from pathlib import Path

from core.config import artifact_log_path as _artifact_log_path

def _get_artifact_log():
    p = _artifact_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

FAKE_SEED_ROOTS_SIM = [
    "/tmp/shared_sim/Documents_sim/seedbank_sim/",
    "~/storage/shared_sim/Downloads_sim/",
    "/var/tmp/shared_sim/",
]

BURIAL_BEHAVIOR_CLASSES = [
    "recursive_dotdir_nesting_sim",
    "depth_obfuscation_via_random_dotnames_sim",
    "hidden_path_depth_fingerprint_sim",
]

SEED_BEHAVIOR_CLASSES = [
    "shell_script_plant_with_backdated_mtime_sim",
    "executable_drop_in_shared_storage_sim",
    "hidden_dotfile_with_exec_content_sim",
]

DETECTION_OPPORTUNITIES = [
    "deeply_nested_hidden_dirs_in_shared_writable_path",
    "dot_prefix_dirs_created_recursively",
    "shell_script_mtime_backdated_2plus_days",
    "executable_planted_in_documents_downloads_dir",
    "chmod_plus_x_on_hidden_file_in_shared_storage",
]

def _fake_dotname():
    return '.' + ''.join(random.choices(string.ascii_lowercase, k=5))

def simulate_seedbank():
    session_id = str(uuid.uuid4())
    events = []
    root_sim = random.choice(FAKE_SEED_ROOTS_SIM)
    n_seeds = random.randint(3, 6)

    for seed_idx in range(n_seeds):
        # Build nested path simulation
        depth = random.randint(3, 6)
        path_parts = [root_sim] + [_fake_dotname() for _ in range(depth)]
        buried_path_sim = "/".join(path_parts) + "/"
        seed_name_sim = f".{''.join(random.choices(string.ascii_letters + string.digits, k=10))}_sim.sh"
        full_seed_path_sim = buried_path_sim + seed_name_sim

        # Backdated timestamp sim (2 days in past)
        backdated_sim = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()

        burial_behavior = random.choice(BURIAL_BEHAVIOR_CLASSES)
        seed_behavior = random.choice(SEED_BEHAVIOR_CLASSES)

        seed_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "recursive_payload_seedbank",
            "phase": "seed_plant_sim",
            "mitre_techniques": ["T1027", "T1547"],
            "seed_index": seed_idx + 1,
            "behavior_class": burial_behavior,
            "burial_behavior_class": burial_behavior,
            "seed_behavior_class": seed_behavior,
            "root_path_sim": root_sim,
            "nesting_depth_sim": depth,
            "buried_path_sim": buried_path_sim,
            "seed_filename_sim": seed_name_sim,
            "full_seed_path_sim": full_seed_path_sim,
            "mtime_backdated_sim": backdated_sim,
            "mtime_offset_days_sim": -2,
            "perms_sim": "executable_bit_set",
            "content_description_sim": "bash_script_with_activation_log_marker_sim",
            "command_string_present": False,
            "detection_opportunities": [
                "deeply_nested_hidden_dirs_in_shared_writable_path",
                "shell_script_mtime_backdated_2plus_days",
                "executable_planted_in_documents_downloads_dir",
                "dot_prefix_dirs_created_recursively",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "files_created": False,
        }
        events.append(seed_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(seed_event) + "\n")

    return session_id, root_sim, events

def print_simulation(session_id, root_sim, events):
    print(f"\n  [SIMULATION]  recursive_payload_seedbank")
    print(f"  [SESSION]     {session_id}")
    print(f"  [ROOT_SIM]    {root_sim}")
    print(f"  [SEEDS_SIM]   {len(events)}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1027, T1547")
    print(f"  [FILES]       NOT CREATED — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no file writes, no chmod")
    print()
    for e in events:
        print(f"  [SEED #{e['seed_index']}]")
        print(f"    burial        : {e['burial_behavior_class']}")
        print(f"    seed          : {e['seed_behavior_class']}")
        print(f"    depth_sim     : {e['nesting_depth_sim']} levels")
        print(f"    path_sim      : {e['full_seed_path_sim'][-60:]}")
        print(f"    mtime_sim     : {e['mtime_backdated_sim'][:19]} ({e['mtime_offset_days_sim']}d)")
        print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no file writes, no chmod, no utime — telemetry only")

@register_payload(name="recursive_payload_seedbank")
def main():
    session_id, root_sim, events = simulate_seedbank()
    print_simulation(session_id, root_sim, events)

if __name__ == "__main__":
    main()
