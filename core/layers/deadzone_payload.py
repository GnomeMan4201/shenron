from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Deadzone Payload — inert staging zone and dead-drop telemetry simulator
# PURPOSE: Emit defender-observable telemetry for payload staging and dead-drop patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1027 (Obfuscated Files), T1140 (Deobfuscate/Decode)
# DETECTION NOTES:
#   - Blue teams should alert on: files written to hidden directories with obfuscated names
#   - Dead-drop zones in shared writable paths (tmp, Downloads, Documents)
#   - Staging files with high entropy that are written then immediately read elsewhere
#   - Log marker files written from non-logging processes

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

FAKE_DEADZONE_PATHS_SIM = [
    "/tmp/.deadzone_sim/stage_a/",
    "/var/tmp/.dz_sim/",
    "/dev/shm/.staging_sim/",
    "~/.cache/.dz_sim/",
]

FAKE_STAGING_BEHAVIORS = [
    "obfuscated_blob_write_sim",
    "encoded_config_drop_sim",
    "marker_file_create_sim",
    "dead_drop_zone_init_sim",
]

FAKE_LOG_MARKER_BEHAVIORS = [
    "status_append_to_hidden_log_sim",
    "heartbeat_marker_write_sim",
    "activation_flag_create_sim",
]

DETECTION_OPPORTUNITIES = [
    "hidden_dir_with_high_entropy_files",
    "non_logging_process_writing_log_marker",
    "staging_file_written_then_read_cross_process",
    "dead_drop_zone_in_world_writable_path",
    "obfuscated_filename_in_tmp",
]

def _sim_hash():
    return hashlib.sha256(os.urandom(16)).hexdigest()

def simulate_deadzone():
    session_id = str(uuid.uuid4())
    events = []
    zone_path_sim = random.choice(FAKE_DEADZONE_PATHS_SIM)

    # Phase 1: Zone initialization
    init_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "deadzone_payload",
        "phase": "zone_init",
        "mitre_techniques": ["T1027"],
        "behavior_class": "dead_drop_zone_init_sim",
        "zone_path_sim": zone_path_sim,
        "hidden_dir_sim": True,
        "world_writable_sim": random.choice([True, False]),
        "detection_opportunities": [
            "hidden_dir_creation_in_writable_path",
            "dead_drop_zone_in_world_writable_path",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "files_created": False,
    }
    events.append(init_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(init_event) + "\n")

    # Phase 2: Staging behavior
    n_stages = random.randint(2, 3)
    for i in range(n_stages):
        behavior = random.choice(FAKE_STAGING_BEHAVIORS)
        entropy_sim = round(random.uniform(0.82, 0.98), 4)
        stage_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "deadzone_payload",
            "phase": "staging",
            "mitre_techniques": ["T1140"],
            "behavior_class": behavior,
            "stage_index": i + 1,
            "stage_path_sim": f"{zone_path_sim}.s{i:02d}_sim",
            "entropy_sim": entropy_sim,
            "hash_sim": _sim_hash(),
            "cross_process_read_expected_sim": True,
            "detection_opportunities": [
                "hidden_dir_with_high_entropy_files",
                "staging_file_written_then_read_cross_process",
                "obfuscated_filename_in_tmp",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "files_created": False,
        }
        events.append(stage_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(stage_event) + "\n")

    # Phase 3: Log marker behavior
    marker_behavior = random.choice(FAKE_LOG_MARKER_BEHAVIORS)
    marker_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "deadzone_payload",
        "phase": "log_marker",
        "mitre_techniques": ["T1027"],
        "behavior_class": marker_behavior,
        "marker_path_sim": f"{zone_path_sim}.status_sim",
        "writing_process_type_sim": "non_logging_process",
        "detection_opportunities": [
            "non_logging_process_writing_log_marker",
            "hidden_log_in_staging_zone",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "files_created": False,
    }
    events.append(marker_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(marker_event) + "\n")

    return session_id, zone_path_sim, events

def print_simulation(session_id, zone_path_sim, events):
    print(f"\n  [SIMULATION]  deadzone_payload")
    print(f"  [SESSION]     {session_id}")
    print(f"  [ZONE_SIM]    {zone_path_sim}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1027, T1140")
    print(f"  [FILES]       NOT CREATED — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no os.system, no shell calls")
    print()
    for e in events:
        print(f"  [{e['phase'].upper()}]")
        print(f"    behavior      : {e['behavior_class']}")
        if "stage_path_sim" in e:
            print(f"    path_sim      : {e['stage_path_sim']}")
            print(f"    entropy_sim   : {e['entropy_sim']}")
        if "marker_path_sim" in e:
            print(f"    marker_sim    : {e['marker_path_sim']}")
        print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no file writes, no os.system — telemetry only")

@register_payload(name="deadzone_payload")
def main():
    session_id, zone_path_sim, events = simulate_deadzone()
    print_simulation(session_id, zone_path_sim, events)

if __name__ == "__main__":
    main()
