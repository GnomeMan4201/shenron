from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Evasion Lure Illusion — synthetic lure and decoy deployment simulator
# PURPOSE: Emit realistic-shaped lure deployment telemetry for detection testing
# PRINCIPLE: Represent adversarial shape without adversarial capability
# MITRE: T1036 (Masquerading), T1055 (Process Injection)
# NO FILE WRITES — no real lure files created, no real directories made

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

FAKE_LURE_PATHS = [
    {"path": "~/.hidden/.system32/defrag.dll",    "type": "fake_dll"},
    {"path": "~/bin/.cache/.browser_upgrade",     "type": "fake_updater"},
    {"path": "~/tmp/.stealth_index",              "type": "fake_index"},
    {"path": "~/lib/.phantom_thread.so",          "type": "fake_library"},
    {"path": "~/Downloads/keygen_patch.crack",    "type": "fake_crack"},
    {"path": "/tmp/.cache/svc_helper",            "type": "fake_service"},
    {"path": "~/.config/autostart/updater.sh",   "type": "fake_autostart"},
]

FAKE_SIGNATURES = [
    "Trojan.Dropper.Agent",
    "W32.Mimic.Recon",
    "Win32:FakeRAT-X",
    "Mal/EncPack-AE",
    "Generic.Backdoor.Shadow",
    "PUA:Win32/StealthAgent",
]

FAKE_LURE_OUTCOMES = [
    "lure deployed — awaiting scanner interaction",
    "lure deployed — awaiting scanner interaction",
    "lure triggered — scanner engaged (simulated)",
    "lure response recorded — evasion confirmed (simulated)",
]

def simulate_lure_illusion():
    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: Lure path selection
    lures = random.sample(FAKE_LURE_PATHS, random.randint(3, 5))
    select_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "evasion_lure_illusion",
        "phase": "lure_selection",
        "mitre_techniques": ["T1036"],
        "behavior_class": "lure_selection",
        "detection_opportunities": ["lure_selection"],
        "lures_selected": len(lures),
        "lure_paths_sim": [l["path"] for l in lures],
        "safe": True,
        "simulation_only": True,
        "files_created": False,
    }
    events.append(select_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(select_event) + "\n")

    # Phase 2: Lure deployment simulation
    for i, lure in enumerate(lures):
        sig = random.choice(FAKE_SIGNATURES)
        outcome = FAKE_LURE_OUTCOMES[min(i, len(FAKE_LURE_OUTCOMES)-1)]
        deploy_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "evasion_lure_illusion",
            "phase": "lure_deployment",
            "mitre_techniques": ["T1036", "T1055"],
            "behavior_class": "lure_deployment",
            "detection_opportunities": ["lure_deployment"],
            "lure_path_sim": lure["path"],
            "lure_type": lure["type"],
            "fake_signature_sim": sig,
            "outcome_sim": outcome,
            "triggered": "triggered" in outcome,
            "safe": True,
            "simulation_only": True,
            "files_created": False,
        }
        events.append(deploy_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(deploy_event) + "\n")

    return session_id, lures, events

def print_simulation(session_id, lures, events):
    triggered = sum(1 for e in events if e.get("triggered"))
    print(f"\n  [SIMULATION]  evasion_lure_illusion")
    print(f"  [SESSION]     {session_id}")
    print(f"  [LURES_SIM]   {len(lures)} deployed, {triggered} triggered")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1036, T1055")
    print(f"  [FILES]       NOT CREATED — synthetic only")
    print()
    for e in events:
        phase = e["phase"]
        if phase == "lure_selection":
            print(f"  [PHASE 1: LURE SELECTION]")
            for p in e["lure_paths_sim"]:
                print(f"    {p}")
        elif phase == "lure_deployment":
            flag = "→" if e["triggered"] else " "
            print(f"\n  [PHASE 2: LURE DEPLOY [{flag}]]")
            print(f"    path_sim      : {e['lure_path_sim']}")
            print(f"    type          : {e['lure_type']}")
            print(f"    sig_sim       : {e['fake_signature_sim']}")
            print(f"    outcome       : {e['outcome_sim']}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no files created, no directories made — simulation only")

@register_payload(name="evasion_lure_illusion")
def main():
    session_id, lures, events = simulate_lure_illusion()
    print_simulation(session_id, lures, events)

if __name__ == "__main__":
    main()
