from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Quantum Trace Rewinder — timeline spoofing and anti-forensics telemetry simulator
# PURPOSE: Emit defender-observable telemetry for timestamp manipulation and trace erasure
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1070 (Indicator Removal), T1027 (Obfuscated Files)
# DETECTION NOTES:
#   - Blue teams should alert on: recursive mtime modification across entire tool directories
#   - Files in log and layer dirs with timestamps 7-90 days in the past vs creation date
#   - Decoy timeline files with timestamps 1 year old in home directory
#   - os.utime called across directories by non-filesystem process
#   - Batch timestamp modification (many files, single time window) is a strong indicator

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

FAKE_TARGET_DIRS_SIM = [
    "~/SHENRON/logs_sim/",
    "~/SHENRON/core/layers_sim/",
    "~/SHENRON/core/ai_module_sim/",
    "~/SHENRON/core/propagation_sim/",
]

FAKE_FILE_TYPES_SIM = [
    "log_file_sim", "python_layer_sim", "config_sim", "manifest_sim"
]

REWIND_BEHAVIOR_CLASSES = [
    "recursive_utime_walk_sim",
    "batch_mtime_modification_sim",
    "decoy_timeline_artifact_create_sim",
]

DETECTION_OPPORTUNITIES = [
    "recursive_mtime_modification_across_tool_directory",
    "files_with_timestamps_7_90_days_past_vs_creation_date",
    "decoy_timeline_file_1yr_old_in_home_dir",
    "batch_timestamp_modification_many_files_single_window",
    "utime_called_across_dirs_by_non_filesystem_process",
]

def _backdated_iso(days_back):
    return (datetime.now(timezone.utc) - timedelta(
        days=days_back,
        hours=random.randint(1, 12)
    )).isoformat()

def simulate_trace_rewinder():
    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: Directory walk and timestamp rewind
    targets = random.sample(FAKE_TARGET_DIRS_SIM, random.randint(2, 4))
    for target_dir in targets:
        n_files_sim = random.randint(3, 12)
        back_days = random.randint(7, 90)
        rewind_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "quantum_trace_rewinder",
            "phase": "directory_rewind_sim",
            "mitre_techniques": ["T1070"],
            "behavior_class": "recursive_utime_walk_sim",
            "target_dir_sim": target_dir,
            "files_affected_sim": n_files_sim,
            "file_types_sim": random.sample(FAKE_FILE_TYPES_SIM, 2),
            "backdated_to_sim": _backdated_iso(back_days),
            "days_back_sim": back_days,
            "utime_calls_sim": n_files_sim,
            "detection_opportunities": [
                "recursive_mtime_modification_across_tool_directory",
                "files_with_timestamps_7_90_days_past_vs_creation_date",
                "batch_timestamp_modification_many_files_single_window",
                "utime_called_across_dirs_by_non_filesystem_process",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "filesystem_modified": False,
        }
        events.append(rewind_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(rewind_event) + "\n")

    # Phase 2: Decoy timeline artifact
    decoy_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "quantum_trace_rewinder",
        "phase": "decoy_artifact_sim",
        "mitre_techniques": ["T1027"],
        "behavior_class": "decoy_timeline_artifact_create_sim",
        "decoy_path_sim": f"~/SHENRON/.decoy_timeline_{random.randint(1000,9999)}_sim",
        "backdated_to_sim": _backdated_iso(365),
        "days_back_sim": 365,
        "content_description_sim": "timestamp_decoy_marker_text_sim",
        "detection_opportunities": [
            "decoy_timeline_file_1yr_old_in_home_dir",
            "files_with_timestamps_7_90_days_past_vs_creation_date",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "filesystem_modified": False,
    }
    events.append(decoy_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(decoy_event) + "\n")

    return session_id, targets, events

def print_simulation(session_id, targets, events):
    print(f"\n  [SIMULATION]  quantum_trace_rewinder")
    print(f"  [SESSION]     {session_id}")
    print(f"  [DIRS_SIM]    {len(targets)}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1070, T1027")
    print(f"  [FILESYSTEM]  NOT MODIFIED — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no utime calls, no file writes")
    print()
    for e in events:
        if e["phase"] == "directory_rewind_sim":
            print(f"  [DIR REWIND] {e['target_dir_sim']}")
            print(f"    files_sim     : {e['files_affected_sim']}")
            print(f"    backdated_sim : {e['backdated_to_sim'][:19]} (-{e['days_back_sim']}d)")
            print(f"    utime_calls   : {e['utime_calls_sim']}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
        elif e["phase"] == "decoy_artifact_sim":
            print(f"\n  [DECOY ARTIFACT]")
            print(f"    path_sim      : {e['decoy_path_sim']}")
            print(f"    backdated_sim : {e['backdated_to_sim'][:19]} (-{e['days_back_sim']}d)")
            print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no utime calls, no file writes — telemetry only")

@register_payload(name="quantum_trace_rewinder")
def main():
    session_id, targets, events = simulate_trace_rewinder()
    print_simulation(session_id, targets, events)

if __name__ == "__main__":
    main()
