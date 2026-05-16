from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Stealth Mimic — process name masquerading telemetry simulator
# PURPOSE: Emit defender-observable telemetry for trusted-name payload masquerade patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1036 (Masquerading), T1134 (Access Token Manipulation)
# DETECTION NOTES:
#   - Blue teams should alert on: payloads renamed to match known trusted daemon names
#   - Python scripts with names like "logd", "healthd", "kworker" in non-standard paths
#   - Files in stealth deploy dirs where filename doesn't match file type
#   - chmod +x on files that mimic system daemon names
#   - Hash mismatch between file and known-good version of named binary

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

TRUSTED_NAMES_SIM = [
    "update-engine", "usbmuxd", "healthd", "logd", "servicemanager",
    "systemstats", "crond", "watchdog", "kworker", "journald"
]

FAKE_MUTATED_PAYLOADS_SIM = [
    "stealth_beacon_sim.py", "persist_hook_sim.py",
    "signal_relay_sim.py", "revival_stub_sim.py"
]

FAKE_DEPLOY_DIR_SIM = "~/SHENRON/core/payloads/stealth_sim/"
FAKE_SOURCE_DIR_SIM = "~/SHENRON/core/payloads/mutated_sim/"

MIMIC_BEHAVIOR_CLASSES = [
    "trusted_name_rename_sim",
    "daemon_name_masquerade_sim",
    "system_binary_impersonation_sim",
]

DETECTION_OPPORTUNITIES = [
    "payload_renamed_to_trusted_daemon_name_nonstandard_path",
    "python_script_named_logd_healthd_kworker",
    "filename_mimics_daemon_but_file_type_mismatch",
    "chmod_plus_x_on_daemon_named_file",
    "hash_mismatch_filename_vs_known_good_binary",
]

def _sim_hash():
    return hashlib.sha256(os.urandom(16)).hexdigest()

def simulate_stealth_mimic():
    session_id = str(uuid.uuid4())
    events = []

    payloads = random.sample(FAKE_MUTATED_PAYLOADS_SIM,
                              random.randint(2, len(FAKE_MUTATED_PAYLOADS_SIM)))

    for payload_sim in payloads:
        fake_name = random.choice(TRUSTED_NAMES_SIM)
        behavior = random.choice(MIMIC_BEHAVIOR_CLASSES)
        is_py = payload_sim.endswith(".py")
        dest_name_sim = fake_name + ("_sim.py" if is_py else "_sim")

        mimic_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "stealth_mimic",
            "phase": "payload_mimic_sim",
            "mitre_techniques": ["T1036"],
            "behavior_class": behavior,
            "source_payload_sim": payload_sim,
            "source_path_sim": f"{FAKE_SOURCE_DIR_SIM}{payload_sim}",
            "mimic_name_sim": fake_name,
            "dest_name_sim": dest_name_sim,
            "dest_path_sim": f"{FAKE_DEPLOY_DIR_SIM}{dest_name_sim}",
            "file_type_sim": "python_script",
            "name_implies_type_sim": "native_daemon_binary",
            "type_mismatch_sim": True,
            "perms_sim": "executable_bit_set",
            "hash_sim": _sim_hash(),
            "known_good_hash_sim": _sim_hash(),
            "hash_match_sim": False,
            "detection_opportunities": [
                "payload_renamed_to_trusted_daemon_name_nonstandard_path",
                "python_script_named_logd_healthd_kworker",
                "filename_mimics_daemon_but_file_type_mismatch",
                "chmod_plus_x_on_daemon_named_file",
                "hash_mismatch_filename_vs_known_good_binary",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "files_created": False,
        }
        events.append(mimic_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(mimic_event) + "\n")

    return session_id, events

def print_simulation(session_id, events):
    print(f"\n  [SIMULATION]  stealth_mimic")
    print(f"  [SESSION]     {session_id}")
    print(f"  [MIMICS_SIM]  {len(events)}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1036, T1134")
    print(f"  [FILES]       NOT CREATED — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no shutil, no chmod, no file writes")
    print()
    for e in events:
        print(f"  [MIMIC] {e['source_payload_sim']} → {e['mimic_name_sim']}")
        print(f"    behavior      : {e['behavior_class']}")
        print(f"    dest_sim      : {e['dest_path_sim']}")
        print(f"    type_sim      : {e['file_type_sim']} masquerading as {e['name_implies_type_sim']}")
        print(f"    type_mismatch : {e['type_mismatch_sim']} ← detection opportunity")
        print(f"    hash_match    : {e['hash_match_sim']} ← mismatch = detection opportunity")
        print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no shutil, no chmod, no file writes — telemetry only")

@register_payload(name="stealth_mimic")
def main():
    session_id, events = simulate_stealth_mimic()
    print_simulation(session_id, events)

if __name__ == "__main__":
    main()
