from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Airlock Quarantine Cloak — synthetic AV quarantine bypass simulator
# PURPOSE: Emit realistic-shaped quarantine evasion telemetry for detection testing
# PRINCIPLE: Represent adversarial shape without adversarial capability
# MITRE: T1564 (Hide Artifacts), T1036 (Masquerading)
# NO FILE WRITES — no real quarantine files created

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

FAKE_AV_ENGINES = [
    "Windows Defender", "ClamAV", "Sophos", "Malwarebytes", "ESET NOD32"
]

FAKE_QUARANTINE_PATHS = [
    "C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine",
    "/var/lib/clamav/quarantine",
    "/opt/sophos/quarantine",
    "~/.config/malwarebytes/quarantine",
]

FAKE_EVASION_TECHNIQUES = [
    "signature_spoof",
    "quarantine_dir_mirror",
    "benign_header_prepend",
    "entropy_reduction_sim",
    "packed_stub_sim",
]

FAKE_QUARANTINE_OUTCOMES = [
    "quarantine attempted — bypass failed (simulated)",
    "quarantine attempted — bypass succeeded (simulated)",
    "av_scan_triggered — evasion maintained (simulated)",
]

def _fake_sig():
    return hashlib.md5(os.urandom(16)).hexdigest()

def simulate_quarantine_cloak():
    session_id = str(uuid.uuid4())
    av_engine = random.choice(FAKE_AV_ENGINES)
    events = []

    # Phase 1: AV engine profiling
    profile_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "sandbox_evasion_sim",
        "phase": "av_profiling",
        "mitre_techniques": ["T1036"],
        "behavior_class": "av_profiling",
        "detection_opportunities": ["av_profiling"],
        "av_engine_sim": av_engine,
        "quarantine_path_sim": random.choice(FAKE_QUARANTINE_PATHS),
        "engine_version_sim": f"{random.randint(1,5)}.{random.randint(0,9)}.{random.randint(100,999)}",
        "safe": True,
        "simulation_only": True,
        "files_created": False,
    }
    events.append(profile_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(profile_event) + "\n")

    # Phase 2: Fake quarantine entries
    n_entries = random.randint(3, 5)
    for i in range(n_entries):
        technique = random.choice(FAKE_EVASION_TECHNIQUES)
        outcome = random.choice(FAKE_QUARANTINE_OUTCOMES)
        entry_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "sandbox_evasion_sim",
            "phase": "quarantine_entry_sim",
            "mitre_techniques": ["T1564"],
            "behavior_class": "quarantine_entry_sim",
            "detection_opportunities": ["quarantine_entry_sim"],
            "entry_num": i + 1,
            "fake_sig_sim": _fake_sig(),
            "evasion_technique_sim": technique,
            "outcome_sim": outcome,
            "bypassed": "succeeded" in outcome,
            "safe": True,
            "simulation_only": True,
            "files_created": False,
        }
        events.append(entry_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(entry_event) + "\n")

    return session_id, av_engine, events

def print_simulation(session_id, av_engine, events):
    bypassed = sum(1 for e in events if e.get("bypassed"))
    print(f"\n  [SIMULATION]  sandbox_evasion_sim")
    print(f"  [SESSION]     {session_id}")
    print(f"  [AV_SIM]      {av_engine}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1564, T1036")
    print(f"  [FILES]       NOT CREATED — synthetic only")
    print()
    for e in events:
        phase = e["phase"]
        if phase == "av_profiling":
            print(f"  [PHASE 1: AV PROFILING]")
            print(f"    engine_sim    : {e['av_engine_sim']}")
            print(f"    version_sim   : {e['engine_version_sim']}")
            print(f"    qpath_sim     : {e['quarantine_path_sim']}")
        elif phase == "quarantine_entry_sim":
            flag = "✓" if e["bypassed"] else "✗"
            print(f"\n  [PHASE 2: QUARANTINE ENTRY #{e['entry_num']} [{flag}]]")
            print(f"    sig_sim       : {e['fake_sig_sim'][:16]}...")
            print(f"    technique_sim : {e['evasion_technique_sim']}")
            print(f"    outcome       : {e['outcome_sim']}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no files created, no quarantine interaction — simulation only")

@register_payload(name="sandbox_evasion_sim")
def main():
    session_id, av_engine, events = simulate_quarantine_cloak()
    print_simulation(session_id, av_engine, events)

if __name__ == "__main__":
    main()
