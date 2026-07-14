from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Cognitive Replicator — self-replication telemetry simulator
# PURPOSE: Emit defender-observable telemetry for payload self-replication patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1036 (Masquerading), T1078 (Valid Accounts)
# DETECTION NOTES:
#   - Blue teams should alert on: files copied from payload staging dir to shared storage
#   - Hostname-prefixed filenames appearing in Download/Documents paths
#   - Executable files with system-daemon names dropped in non-standard locations
#   - shutil.copy2 + chmod pattern from non-installer process
#   - Replica files appearing across multiple target paths simultaneously

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

FAKE_REPLICATION_TARGETS_SIM = [
    "/storage/emulated/0/Download_sim/",
    "/data/local/tmp_sim/.replica_sim/",
    "/sdcard/Documents_sim/",
    "/tmp/shenron_replica_sim/",
]

FAKE_SOURCE_PAYLOADS_SIM = [
    "stealth_beacon_sim.py", "persist_hook_sim.py",
    "signal_relay_sim.py", "revival_stub_sim.py"
]

REPLICA_BEHAVIOR_CLASSES = [
    "hostname_prefixed_replica_drop_sim",
    "timestamp_suffixed_copy_sim",
    "mutated_clone_plant_sim",
]

DETECTION_OPPORTUNITIES = [
    "file_copied_from_payload_staging_to_shared_storage",
    "hostname_prefixed_filename_in_download_documents",
    "executable_system_daemon_name_in_nonstandard_location",
    "shutil_copy_chmod_pattern_non_installer_process",
    "replica_files_across_multiple_target_paths_simultaneously",
]

def _sim_hash():
    return hashlib.sha256(os.urandom(16)).hexdigest()

def simulate_file_replica_dropper():
    session_id = str(uuid.uuid4())
    hostname_sim = f"shenron_host_sim_{random.randint(1000,9999)}"
    events = []

    source_payloads = random.sample(FAKE_SOURCE_PAYLOADS_SIM,
                                     random.randint(2, len(FAKE_SOURCE_PAYLOADS_SIM)))
    targets = random.sample(FAKE_REPLICATION_TARGETS_SIM,
                            random.randint(2, len(FAKE_REPLICATION_TARGETS_SIM)))

    # Phase 1: Source enumeration
    enum_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "file_replica_dropper",
        "phase": "source_enumeration",
        "mitre_techniques": ["T1036"],
        "behavior_class": "mutated_payload_dir_scan_sim",
        "source_dir_sim": "~/SHENRON/core/payloads/mutated_sim/",
        "payloads_found_sim": len(source_payloads),
        "payload_names_sim": source_payloads,
        "hostname_sim": hostname_sim,
        "detection_opportunities": [
            "payload_staging_dir_enumeration_non_installer",
            "file_copied_from_payload_staging_to_shared_storage",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "files_created": False,
    }
    events.append(enum_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(enum_event) + "\n")

    # Phase 2: Replication per target
    for target in targets:
        for payload_sim in source_payloads:
            behavior = random.choice(REPLICA_BEHAVIOR_CLASSES)
            replica_name_sim = f"{hostname_sim}_{random.randint(1000000,9999999)}_{payload_sim}"
            drop_event = {
                "artifact_id": str(uuid.uuid4()),
                "session_id": session_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "layer": "file_replica_dropper",
                "phase": "replica_drop_sim",
                "mitre_techniques": ["T1078"],
                "behavior_class": behavior,
                "source_sim": f"~/SHENRON/core/payloads/mutated_sim/{payload_sim}",
                "target_dir_sim": target,
                "replica_name_sim": replica_name_sim,
                "replica_path_sim": f"{target}{replica_name_sim}",
                "perms_sim": "executable_bit_set",
                "hash_sim": _sim_hash(),
                "detection_opportunities": [
                    "hostname_prefixed_filename_in_download_documents",
                    "executable_system_daemon_name_in_nonstandard_location",
                    "shutil_copy_chmod_pattern_non_installer_process",
                    "replica_files_across_multiple_target_paths_simultaneously",
                ],
                "simulation_only": True,
                "executable": False,
                "no_payload_present": True,
                "files_created": False,
            }
            events.append(drop_event)
            with open(_get_artifact_log(), "a") as f:
                f.write(json.dumps(drop_event) + "\n")

    return session_id, hostname_sim, targets, source_payloads, events

def print_simulation(session_id, hostname_sim, targets, source_payloads, events):
    drops = [e for e in events if e["phase"] == "replica_drop_sim"]
    print(f"\n  [SIMULATION]  file_replica_dropper")
    print(f"  [SESSION]     {session_id}")
    print(f"  [HOSTNAME]    {hostname_sim}")
    print(f"  [TARGETS_SIM] {len(targets)}")
    print(f"  [REPLICAS]    {len(drops)} drops simulated")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1036, T1078")
    print(f"  [FILES]       NOT CREATED — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no shutil, no chmod, no file writes")
    print()
    for e in events:
        if e["phase"] == "source_enumeration":
            print(f"  [PHASE 1: SOURCE ENUM]")
            print(f"    source_sim    : {e['source_dir_sim']}")
            print(f"    found_sim     : {e['payloads_found_sim']}")
            print(f"    hostname_sim  : {e['hostname_sim']}")
        elif e["phase"] == "replica_drop_sim":
            print(f"\n  [REPLICA DROP]")
            print(f"    behavior      : {e['behavior_class']}")
            print(f"    target_sim    : {e['target_dir_sim']}")
            print(f"    name_sim      : {e['replica_name_sim'][-40:]}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no file writes, no chmod — telemetry only")

@register_payload(name="file_replica_dropper")
def main():
    session_id, hostname_sim, targets, source_payloads, events = simulate_file_replica_dropper()
    print_simulation(session_id, hostname_sim, targets, source_payloads, events)

if __name__ == "__main__":
    main()
