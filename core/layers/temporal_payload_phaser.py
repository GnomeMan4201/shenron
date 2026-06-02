from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Temporal Payload Phaser — synthetic time-gated payload delivery simulator
# PURPOSE: Emit realistic-shaped time-based payload staging telemetry
# PRINCIPLE: Represent adversarial shape without adversarial capability
# MITRE: T1027 (Obfuscated Files), T1140 (Deobfuscate/Decode)
# NO EXECUTION — no real payloads staged, no real timing windows

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

FAKE_PHASE_WINDOWS = [
    {"window": "business_hours",    "start": "09:00", "end": "17:00"},
    {"window": "off_hours",         "start": "22:00", "end": "06:00"},
    {"window": "weekend_only",      "start": "Sat",   "end": "Sun"},
    {"window": "low_traffic",       "start": "03:00", "end": "05:00"},
    {"window": "patch_tuesday",     "start": "Tue",   "end": "Tue"},
]

FAKE_OBFUSCATION_LAYERS = [
    "xor_encoded_sim", "base64_wrapped_sim", "rc4_stub_sim",
    "aes_cbc_sim", "custom_packer_sim"
]

FAKE_DECODE_TRIGGERS = [
    "time_window_match", "env_var_present", "file_marker_found",
    "network_reachable_sim", "registry_key_sim"
]

FAKE_PHASE_OUTCOMES = [
    "phase gate — conditions not met",
    "phase gate — conditions not met",
    "phase gate — conditions met (simulated)",
    "payload deobfuscated — staging complete (simulated)",
]

def simulate_payload_phaser():
    session_id = str(uuid.uuid4())
    window = random.choice(FAKE_PHASE_WINDOWS)
    obfuscation = random.choice(FAKE_OBFUSCATION_LAYERS)
    events = []

    # Phase 1: Obfuscation layer analysis
    obfusc_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "temporal_payload_phaser",
        "phase": "obfuscation_analysis",
        "mitre_techniques": ["T1027"],
        "behavior_class": "obfuscation_analysis",
        "detection_opportunities": ["obfuscation_analysis"],
        "obfuscation_type_sim": obfuscation,
        "layer_count_sim": random.randint(1, 3),
        "entropy_sim": round(random.uniform(0.72, 0.97), 3),
        "safe": True,
        "simulation_only": True,
        "payload_executed": False,
    }
    events.append(obfusc_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(obfusc_event) + "\n")

    # Phase 2: Timing gate evaluation
    n_checks = random.randint(2, 4)
    for i in range(n_checks):
        trigger = random.choice(FAKE_DECODE_TRIGGERS)
        outcome = FAKE_PHASE_OUTCOMES[min(i, len(FAKE_PHASE_OUTCOMES)-1)]
        gate_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "temporal_payload_phaser",
            "phase": "timing_gate",
            "mitre_techniques": ["T1140"],
            "behavior_class": "timing_gate",
            "detection_opportunities": ["timing_gate"],
            "check": i + 1,
            "window_sim": window["window"],
            "trigger_type_sim": trigger,
            "outcome_sim": outcome,
            "gate_passed": "met" in outcome or "complete" in outcome,
            "safe": True,
            "simulation_only": True,
            "payload_executed": False,
        }
        events.append(gate_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(gate_event) + "\n")

    return session_id, window, obfuscation, events

def print_simulation(session_id, window, obfuscation, events):
    passed = sum(1 for e in events if e.get("gate_passed"))
    print(f"\n  [SIMULATION]  temporal_payload_phaser")
    print(f"  [SESSION]     {session_id}")
    print(f"  [WINDOW_SIM]  {window['window']}")
    print(f"  [OBFUSC_SIM]  {obfuscation}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1027, T1140")
    print(f"  [EXECUTION]   NO PAYLOAD EXECUTED — synthetic only")
    print()
    for e in events:
        phase = e["phase"]
        if phase == "obfuscation_analysis":
            print(f"  [PHASE 1: OBFUSCATION ANALYSIS]")
            print(f"    type_sim      : {e['obfuscation_type_sim']}")
            print(f"    layers_sim    : {e['layer_count_sim']}")
            print(f"    entropy_sim   : {e['entropy_sim']}")
        elif phase == "timing_gate":
            flag = "✓" if e["gate_passed"] else "✗"
            print(f"\n  [PHASE 2: TIMING GATE #{e['check']} [{flag}]]")
            print(f"    window_sim    : {e['window_sim']}")
            print(f"    trigger_sim   : {e['trigger_type_sim']}")
            print(f"    outcome       : {e['outcome_sim']}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no payload execution — simulation only")

@register_payload(name="temporal_payload_phaser")
def main():
    session_id, window, obfuscation, events = simulate_payload_phaser()
    print_simulation(session_id, window, obfuscation, events)

if __name__ == "__main__":
    main()
