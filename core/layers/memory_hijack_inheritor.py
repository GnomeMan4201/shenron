from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Memory Hijack Inheritor — synthetic process memory injection simulator
# PURPOSE: Emit realistic-shaped memory injection telemetry for detection testing
# PRINCIPLE: Represent adversarial shape without adversarial capability
# MITRE: T1055 (Process Injection), T1134 (Access Token Manipulation)
# NO MEMORY ACCESS — no /proc writes, no ctypes, no real injection

import os
import json
import uuid
import random
from datetime import datetime, timezone
from pathlib import Path

from core.config import artifact_log_path as _artifact_log_path

def _get_artifact_log():
    p = _artifact_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

FAKE_MEMORY_REGIONS = [
    {"region": "heap",          "offset_sim": "0x00401000", "size_sim": "4096"},
    {"region": "stack",         "offset_sim": "0x7fff0000", "size_sim": "8192"},
    {"region": "mapped_lib",    "offset_sim": "0x7f880000", "size_sim": "2048"},
    {"region": "anonymous",     "offset_sim": "0x00600000", "size_sim": "1024"},
    {"region": "text_segment",  "offset_sim": "0x00100000", "size_sim": "4096"},
]

FAKE_TOKEN_TYPES = [
    "SYSTEM", "LocalService", "NetworkService", "Administrator", "NETWORK"
]

FAKE_INJECTION_PAYLOADS = [
    "shellcode_stub_sim",
    "reflective_dll_sim",
    "position_independent_code_sim",
    "rwx_region_write_sim",
]

FAKE_ANOMALY_EVENTS = [
    "shadow routine monitoring environment — no anomaly",
    "shadow routine monitoring environment — no anomaly",
    "shadow routine monitoring environment — runtime variance detected",
    "counter routine triggered (simulated)",
]

def simulate_memory_hijack():
    session_id = str(uuid.uuid4())
    pid_sim = random.randint(1000, 9999)
    region = random.choice(FAKE_MEMORY_REGIONS)
    events = []

    # Event 1: Memory region probe
    probe_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "memory_hijack_inheritor",
        "phase": "memory_probe",
        "mitre_techniques": ["T1055"],
        "target_pid_sim": pid_sim,
        "proc_mem_path_sim": f"/proc/{pid_sim}/mem",
        "region_sim": region["region"],
        "offset_sim": region["offset_sim"],
        "size_sim": region["size_sim"],
        "safe": True,
        "simulation_only": True,
        "behavior_class": "memory_injection_token_sim",
        "detection_opportunities": ["process_injection_attempt_sim", "token_impersonation_sim", "reflective_injection_sim", "memory_probe_sim"],
        "executable": False,
        "no_payload_present": True,
        "memory_accessed": False,
    }
    events.append(probe_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(probe_event) + "\n")

    # Event 2: Injection attempt
    inject_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "memory_hijack_inheritor",
        "phase": "injection_attempt",
        "mitre_techniques": ["T1055"],
        "target_pid_sim": pid_sim,
        "payload_type_sim": random.choice(FAKE_INJECTION_PAYLOADS),
        "offset_sim": region["offset_sim"],
        "success_sim": random.choice([True, True, False]),
        "safe": True,
        "simulation_only": True,
        "behavior_class": "memory_injection_token_sim",
        "detection_opportunities": ["process_injection_attempt_sim", "token_impersonation_sim", "reflective_injection_sim", "memory_probe_sim"],
        "executable": False,
        "no_payload_present": True,
        "memory_accessed": False,
    }
    events.append(inject_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(inject_event) + "\n")

    # Event 3: Token manipulation attempt
    token_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "memory_hijack_inheritor",
        "phase": "token_manipulation",
        "mitre_techniques": ["T1134"],
        "target_pid_sim": pid_sim,
        "token_type_sim": random.choice(FAKE_TOKEN_TYPES),
        "impersonation_sim": True,
        "safe": True,
        "simulation_only": True,
        "behavior_class": "memory_injection_token_sim",
        "detection_opportunities": ["process_injection_attempt_sim", "token_impersonation_sim", "reflective_injection_sim", "memory_probe_sim"],
        "executable": False,
        "no_payload_present": True,
        "memory_accessed": False,
    }
    events.append(token_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(token_event) + "\n")

    # Event 4: Monitoring loop simulation
    n_cycles = random.randint(2, 3)
    for i in range(n_cycles):
        outcome = FAKE_ANOMALY_EVENTS[min(i, len(FAKE_ANOMALY_EVENTS)-1)]
        monitor_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "memory_hijack_inheritor",
            "phase": "monitoring_cycle",
            "mitre_techniques": ["T1055"],
            "cycle": i + 1,
            "outcome_sim": outcome,
            "anomaly_detected": "detected" in outcome or "triggered" in outcome,
            "safe": True,
            "simulation_only": True,
        "behavior_class": "memory_injection_token_sim",
        "detection_opportunities": ["process_injection_attempt_sim", "token_impersonation_sim", "reflective_injection_sim", "memory_probe_sim"],
        "executable": False,
        "no_payload_present": True,
            "memory_accessed": False,
        }
        events.append(monitor_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(monitor_event) + "\n")

    return session_id, pid_sim, region, events

def print_simulation(session_id, pid_sim, region, events):
    print(f"\n  [SIMULATION]  memory_hijack_inheritor")
    print(f"  [SESSION]     {session_id}")
    print(f"  [TARGET_SIM]  pid={pid_sim}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1055, T1134")
    print(f"  [MEMORY]      NOT ACCESSED — synthetic only")
    print()
    for e in events:
        phase = e["phase"]
        if phase == "memory_probe":
            print(f"  [PHASE 1: MEMORY PROBE]")
            print(f"    proc_path_sim : {e['proc_mem_path_sim']}")
            print(f"    region_sim    : {e['region_sim']}")
            print(f"    offset_sim    : {e['offset_sim']}")
        elif phase == "injection_attempt":
            print(f"\n  [PHASE 2: INJECTION ATTEMPT]")
            print(f"    payload_sim   : {e['payload_type_sim']}")
            print(f"    offset_sim    : {e['offset_sim']}")
            print(f"    success_sim   : {e['success_sim']}")
        elif phase == "token_manipulation":
            print(f"\n  [PHASE 3: TOKEN MANIPULATION]")
            print(f"    token_sim     : {e['token_type_sim']}")
            print(f"    impersonation : {e['impersonation_sim']}")
        elif phase == "monitoring_cycle":
            print(f"\n  [PHASE 4: MONITOR CYCLE #{e['cycle']}]")
            print(f"    outcome       : {e['outcome_sim']}")
            print(f"    anomaly       : {e['anomaly_detected']}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no memory access, no proc writes — simulation only")

@register_payload(name="memory_hijack_inheritor")
def main():
    session_id, pid_sim, region, events = simulate_memory_hijack()
    print_simulation(session_id, pid_sim, region, events)

if __name__ == "__main__":
    main()
