from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Payload Skinwalker — polymorphic clone telemetry simulator
# PURPOSE: Emit defender-observable telemetry representing payload morphing behavior
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1027 (Obfuscated Files), T1059 (Command and Scripting Interpreter)
# DETECTION NOTES:
#   - Blue teams should alert on: new executables with system-like names in temp dirs
#   - Entropy increases on modified files indicate packing or junk insertion
#   - Timestamp spoofing to match system binaries is a strong indicator
#   - Multiple near-identical files with varying hashes suggest morphing activity

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

FAKE_SYSTEM_NAMES_SIM = [
    "svcmanager_sim.sh", "netd_sync_sim", "dalvik_stub_sim",
    "vold_patch_sim.sh", "cron.daily_sim.sh", "logpersistd_sim.sh"
]

MUTATION_BEHAVIOR_CLASSES = [
    "junk_comment_insert",
    "whitespace_padding",
    "noop_injection",
    "variable_rename",
    "dead_branch_insert",
    "string_literal_split",
]

TIMESTAMP_SPOOF_REFS_SIM = [
    "/etc/hostname", "/usr/bin/ls", "/bin/sh",
    "/etc/passwd", "/proc/version"
]

OUTPUT_PATHS_SIM = [
    "/tmp/.shenron/morphs_sim/",
    "/dev/shm/.cache_sim/",
    "/var/tmp/.sys_sim/",
]

DETECTION_NOTES = [
    "new_executable_in_tmp_with_system_name",
    "entropy_increase_on_modified_file",
    "timestamp_matches_system_binary",
    "multiple_near_identical_files_varying_hash",
    "executable_bit_set_on_script_in_tmp",
]

def _sim_hash():
    return hashlib.sha256(os.urandom(16)).hexdigest()

def simulate_skinwalker():
    session_id = str(uuid.uuid4())
    events = []

    base_name_sim = random.choice(FAKE_SYSTEM_NAMES_SIM)
    ops = random.sample(MUTATION_BEHAVIOR_CLASSES, random.randint(2, 4))
    output_dir_sim = random.choice(OUTPUT_PATHS_SIM)
    entropy_before = round(random.uniform(0.48, 0.68), 4)

    analysis_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "payload_skinwalker",
        "phase": "base_analysis",
        "mitre_techniques": ["T1027"],
        "behavior_class": "payload_morphing_analysis",
        "base_name_sim": base_name_sim,
        "line_count_sim": random.randint(20, 80),
        "entropy_before_sim": entropy_before,
        "mutation_ops_planned_sim": ops,
        "detection_opportunities": [
            "enumerate_tmp_for_system_named_files",
            "baseline_entropy_comparison",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "files_created": False,
    }
    events.append(analysis_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(analysis_event) + "\n")

    n_clones = random.randint(2, 4)
    for i in range(n_clones):
        clone_name_sim = random.choice(FAKE_SYSTEM_NAMES_SIM)
        ref_sim = random.choice(TIMESTAMP_SPOOF_REFS_SIM)
        entropy_after = round(entropy_before + random.uniform(0.12, 0.28), 4)
        clone_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "payload_skinwalker",
            "phase": "clone_generation",
            "mitre_techniques": ["T1027", "T1059"],
            "behavior_class": "morphed_clone_drop_sim",
            "clone_index": i + 1,
            "clone_name_sim": clone_name_sim,
            "output_path_sim": f"{output_dir_sim}{clone_name_sim}",
            "mutation_applied_sim": random.choice(ops),
            "timestamp_spoof_ref_sim": ref_sim,
            "hash_before_sim": _sim_hash(),
            "hash_after_sim": _sim_hash(),
            "entropy_before_sim": entropy_before,
            "entropy_after_sim": entropy_after,
            "perms_sim": "executable_bit_set",
            "detection_opportunities": [
                "new_executable_in_writable_tmp_path",
                "entropy_delta_exceeds_threshold",
                "mtime_matches_unrelated_system_binary",
                "filename_mimics_known_daemon",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "files_created": False,
        }
        events.append(clone_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(clone_event) + "\n")

    return session_id, base_name_sim, events

def print_simulation(session_id, base_name_sim, events):
    print(f"\n  [SIMULATION]  payload_skinwalker")
    print(f"  [SESSION]     {session_id}")
    print(f"  [BASE_SIM]    {base_name_sim}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1027, T1059")
    print(f"  [FILES]       NOT CREATED — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no payload strings present")
    print()
    for e in events:
        if e["phase"] == "base_analysis":
            print(f"  [PHASE 1: BASE ANALYSIS]")
            print(f"    behavior      : {e['behavior_class']}")
            print(f"    mutations_sim : {e['mutation_ops_planned_sim']}")
            print(f"    entropy_sim   : {e['entropy_before_sim']}")
            print(f"    detection     : {e['detection_opportunities']}")
        elif e["phase"] == "clone_generation":
            print(f"\n  [PHASE 2: CLONE #{e['clone_index']}]")
            print(f"    behavior      : {e['behavior_class']}")
            print(f"    path_sim      : {e['output_path_sim']}")
            print(f"    mutation_sim  : {e['mutation_applied_sim']}")
            print(f"    entropy_delta : {e['entropy_before_sim']} → {e['entropy_after_sim']}")
            print(f"    ts_spoof_sim  : mimics {e['timestamp_spoof_ref_sim']}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no file writes, no mutations — telemetry only")

@register_payload(name="payload_skinwalker")
def main():
    session_id, base_name_sim, events = simulate_skinwalker()
    print_simulation(session_id, base_name_sim, events)

if __name__ == "__main__":
    main()
