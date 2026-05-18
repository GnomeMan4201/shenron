from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Bio-Replication Layer — device fingerprint spoofing telemetry simulator
# PURPOSE: Emit defender-observable telemetry for device identity spoofing and profile pollution
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1036 (Masquerading), T1027 (Obfuscated Files)
# DETECTION NOTES:
#   - Blue teams should alert on: synthetic device fingerprints logged at regular intervals
#   - IMEI/MAC/hostname values that don't match hardware inventory
#   - Bio-profile log files containing rapidly-changing device identity fields
#   - Repeated UUID generation not correlated with device boot events
#   - Fingerprint emission timing matches sleep(2-5) jitter pattern

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

FAKE_TIMEZONES_SIM = ["UTC", "PST", "EST", "CST", "GMT+3"]

FINGERPRINT_BEHAVIOR_CLASSES = [
    "synthetic_device_fingerprint_emit_sim",
    "imei_mac_hostname_spoof_sim",
    "boot_uuid_pollution_sim",
]

DETECTION_OPPORTUNITIES = [
    "synthetic_device_fingerprint_at_regular_intervals",
    "imei_mac_hostname_not_matching_hardware_inventory",
    "bio_profile_log_rapidly_changing_device_identity",
    "repeated_uuid_generation_not_correlated_boot_events",
    "fingerprint_emission_timing_fixed_jitter_pattern",
]

def _sim_mac():
    return ":".join([f"{random.randint(0,255):02x}" for _ in range(6)])

def _sim_imei():
    return str(random.randint(100000000000000, 999999999999999))

def _sim_entropy_hash():
    return hashlib.sha256(os.urandom(16)).hexdigest()[:16]

def simulate_bio_replication():
    session_id = str(uuid.uuid4())
    events = []

    n_profiles = 5
    for i in range(n_profiles):
        behavior = random.choice(FINGERPRINT_BEHAVIOR_CLASSES)
        interval_sim = round(random.uniform(2.0, 5.0), 2)

        profile_sim = {
            "hostname_sim": f"termux-sim-{random.randint(1000,9999)}",
            "mac_sim": _sim_mac(),
            "imei_sim": _sim_imei(),
            "boot_uuid_sim": str(uuid.uuid4()),
            "entropy_hash_sim": _sim_entropy_hash(),
            "cpu_cycles_sim": random.randint(100000, 9000000),
            "display_usage_sim": f"{random.randint(1,24)}h/day",
            "timezone_sim": random.choice(FAKE_TIMEZONES_SIM),
            "user_taps_sim": random.randint(500, 5000),
            "avg_typing_speed_sim": random.randint(25, 80),
        }

        emit_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "shenron_bio_replication",
            "phase": "fingerprint_emission",
            "mitre_techniques": ["T1036"],
            "behavior_class": behavior,
            "profile_index": i + 1,
            "profile_sim": profile_sim,
            "write_target_sim": "~/SHENRON/logs/bio_replication_sim.log",
            "interval_sim": interval_sim,
            "detection_opportunities": [
                "synthetic_device_fingerprint_at_regular_intervals",
                "imei_mac_hostname_not_matching_hardware_inventory",
                "bio_profile_log_rapidly_changing_device_identity",
                "fingerprint_emission_timing_fixed_jitter_pattern",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "files_created": False,
        }
        events.append(emit_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(emit_event) + "\n")

    return session_id, events

def print_simulation(session_id, events):
    print(f"\n  [SIMULATION]  shenron_bio_replication")
    print(f"  [SESSION]     {session_id}")
    print(f"  [PROFILES]    {len(events)} fingerprints emitted")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1036, T1027")
    print(f"  [FILES]       NOT WRITTEN — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no file writes, no sleep loops")
    print()
    for e in events:
        p = e["profile_sim"]
        print(f"  [PROFILE #{e['profile_index']}] {e['behavior_class']}")
        print(f"    hostname_sim  : {p['hostname_sim']}")
        print(f"    mac_sim       : {p['mac_sim']}")
        print(f"    imei_sim      : {p['imei_sim']}")
        print(f"    boot_uuid_sim : {p['boot_uuid_sim'][:18]}...")
        print(f"    interval_sim  : {e['interval_sim']}s")
        print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no file writes, no sleep — telemetry only")

@register_payload(name="shenron_bio_replication")
def main():
    session_id, events = simulate_bio_replication()
    print_simulation(session_id, events)

if __name__ == "__main__":
    main()
