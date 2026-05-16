from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Manifest Vampire — filesystem collection and mimic telemetry simulator
# PURPOSE: Emit defender-observable telemetry for file leeching and script mimicry patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1005 (Data from Local System), T1119 (Automated Collection)
# DETECTION NOTES:
#   - Blue teams should alert on: recursive home directory walk from non-backup process
#   - Script files (.sh .py .conf .rc) being read and cached in hidden dotdir
#   - Mimic scripts generated in ~/.shenron_manifest_cache/mimics/
#   - Hash-deduplication pattern during file collection indicates systematic leeching
#   - Collection targeting shell configs, rc files, and Python scripts specifically

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

FAKE_SEARCH_PATHS_SIM = [
    "~/home_sim/",
    "~/storage_sim/",
    "/data/local/etc_sim/",
    "~/bin_sim/",
]

TARGET_EXTENSIONS_SIM = [".sh", ".conf", ".py", ".rc", ".bashrc", ".zshrc", ".json"]

FAKE_COLLECTED_FILES_SIM = [
    {"path_sim": "~/.bashrc_sim",            "ext": ".bashrc", "size_sim": 2048},
    {"path_sim": "~/.zshrc_sim",             "ext": ".zshrc",  "size_sim": 1536},
    {"path_sim": "~/bin/deploy_sim.sh",      "ext": ".sh",     "size_sim": 4096},
    {"path_sim": "~/config/settings_sim.py", "ext": ".py",     "size_sim": 3072},
    {"path_sim": "/etc/cron.d/jobs_sim.conf","ext": ".conf",   "size_sim": 512},
    {"path_sim": "~/scripts/update_sim.sh",  "ext": ".sh",     "size_sim": 1024},
]

VAMPIRE_CACHE_SIM = "~/.shenron_manifest_cache_sim/"
MIMIC_OUTPUT_SIM = "~/.shenron_manifest_cache_sim/mimics_sim/"

COLLECTION_BEHAVIOR_CLASSES = [
    "recursive_walk_home_collect_scripts_sim",
    "hash_dedup_file_collection_sim",
    "targeted_extension_filter_sim",
]

MIMIC_BEHAVIOR_CLASSES = [
    "strip_comments_generate_mimic_sim",
    "suppress_destructive_commands_sim",
    "replace_output_stubs_sim",
]

DETECTION_OPPORTUNITIES = [
    "recursive_home_walk_non_backup_process",
    "script_files_read_cached_hidden_dotdir",
    "mimic_scripts_generated_shenron_cache",
    "hash_dedup_during_collection_systematic_leeching",
    "collection_targeting_shell_configs_rc_python_specifically",
]

def _sim_hash():
    return hashlib.sha256(os.urandom(16)).hexdigest()

def simulate_manifest_vampire():
    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: Filesystem scan simulation
    scan_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "manifest_vampire",
        "phase": "filesystem_scan_sim",
        "mitre_techniques": ["T1119"],
        "behavior_class": "recursive_walk_home_collect_scripts_sim",
        "search_paths_sim": FAKE_SEARCH_PATHS_SIM,
        "target_extensions_sim": TARGET_EXTENSIONS_SIM,
        "cache_dir_sim": VAMPIRE_CACHE_SIM,
        "mimic_dir_sim": MIMIC_OUTPUT_SIM,
        "detection_opportunities": [
            "recursive_home_walk_non_backup_process",
            "collection_targeting_shell_configs_rc_python_specifically",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "files_read": False,
        "files_written": False,
    }
    events.append(scan_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(scan_event) + "\n")

    # Phase 2: Collection and mimic generation
    collected = random.sample(FAKE_COLLECTED_FILES_SIM,
                               random.randint(3, len(FAKE_COLLECTED_FILES_SIM)))
    seen_hashes_sim = set()

    for file_sim in collected:
        hash_sim = _sim_hash()
        is_dup = hash_sim in seen_hashes_sim
        seen_hashes_sim.add(hash_sim)
        collect_behavior = random.choice(COLLECTION_BEHAVIOR_CLASSES)
        mimic_behavior = random.choice(MIMIC_BEHAVIOR_CLASSES)

        leech_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "manifest_vampire",
            "phase": "leech_and_mimic_sim",
            "mitre_techniques": ["T1005"],
            "collect_behavior_class": collect_behavior,
            "mimic_behavior_class": mimic_behavior,
            "source_path_sim": file_sim["path_sim"],
            "extension_sim": file_sim["ext"],
            "size_sim": file_sim["size_sim"],
            "hash_sim": hash_sim,
            "duplicate_sim": is_dup,
            "skipped_sim": is_dup,
            "leech_output_sim": f"{VAMPIRE_CACHE_SIM}{Path(file_sim['path_sim']).name}_sim.leech",
            "mimic_output_sim": f"{MIMIC_OUTPUT_SIM}mimic_{Path(file_sim['path_sim']).name}_sim",
            "mimic_transformations_sim": [
                "strip_comments", "suppress_rm_cp_mv", "replace_echo_with_stub"
            ],
            "detection_opportunities": [
                "script_files_read_cached_hidden_dotdir",
                "mimic_scripts_generated_shenron_cache",
                "hash_dedup_during_collection_systematic_leeching",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "files_read": False,
            "files_written": False,
        }
        events.append(leech_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(leech_event) + "\n")

    return session_id, collected, events

def print_simulation(session_id, collected, events):
    leeched = [e for e in events if e["phase"] == "leech_and_mimic_sim" and not e["skipped_sim"]]
    print(f"\n  [SIMULATION]  manifest_vampire")
    print(f"  [SESSION]     {session_id}")
    print(f"  [SCANNED_SIM] {len(collected)} files")
    print(f"  [LEECHED_SIM] {len(leeched)} unique")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1005, T1119")
    print(f"  [FILES]       NOT READ OR WRITTEN — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no filesystem access")
    print()
    for e in events:
        if e["phase"] == "filesystem_scan_sim":
            print(f"  [PHASE 1: FILESYSTEM SCAN]")
            print(f"    paths_sim     : {e['search_paths_sim']}")
            print(f"    extensions    : {e['target_extensions_sim']}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
        elif e["phase"] == "leech_and_mimic_sim":
            flag = "SKIP" if e["skipped_sim"] else "LEECH"
            print(f"\n  [{flag}] {e['source_path_sim']}")
            print(f"    collect       : {e['collect_behavior_class']}")
            print(f"    mimic         : {e['mimic_behavior_class']}")
            print(f"    transforms    : {e['mimic_transformations_sim']}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no filesystem access — telemetry only")

@register_payload(name="manifest_vampire")
def main():
    session_id, collected, events = simulate_manifest_vampire()
    print_simulation(session_id, collected, events)

if __name__ == "__main__":
    main()
