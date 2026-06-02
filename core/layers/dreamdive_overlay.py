from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: DreamDive Overlay — synthetic log distortion and hallucination simulator
# PURPOSE: Emit realistic-shaped fake log injection telemetry for detection testing
# PRINCIPLE: Represent adversarial shape without adversarial capability
# MITRE: T1070.001 (Clear Linux Logs), T1036 (Masquerading)
# NO FILE WRITES — no real log files written, no real events injected

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

FAKE_LOG_EVENTS = [
    {"event": "com.system.shell started activity",          "source": "activity_manager"},
    {"event": "pm install -r update.apk",                   "source": "package_manager"},
    {"event": "GET /sync/analytics HTTP/1.1 200 OK",        "source": "http_access"},
    {"event": "adb shell screencap -p /tmp/fake.png",       "source": "adb_daemon"},
    {"event": "netcat outbound attempt to 203.0.113.66:443","source": "network_monitor"},
    {"event": "unknown su binary detected",                  "source": "security_daemon"},
    {"event": "user granted overlay permission to process",  "source": "permission_manager"},
    {"event": "SecurityException from com.system.malware",  "source": "logcat"},
    {"event": "input tap 488 1299",                         "source": "input_dispatcher"},
    {"event": "magiskd started by sh user",                 "source": "init_daemon"},
]

FAKE_TARGET_LOGS = [
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/kern.log",
    "~/.local/share/xorg/xorg.log",
    "/tmp/app_session.log",
]

FAKE_DISTORTION_METHODS = [
    "prepend_fake_events",
    "interleave_noise",
    "timestamp_collision",
    "source_spoofing",
]

def simulate_dreamdive():
    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: Target log selection
    targets = random.sample(FAKE_TARGET_LOGS, random.randint(2, 3))
    select_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "dreamdive_overlay",
        "phase": "target_selection",
        "mitre_techniques": ["T1070.001"],
        "behavior_class": "target_selection",
        "detection_opportunities": ["target_selection"],
        "targets_selected": len(targets),
        "target_logs_sim": targets,
        "safe": True,
        "simulation_only": True,
        "files_written": False,
    }
    events.append(select_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(select_event) + "\n")

    # Phase 2: Fake event injection simulation
    n_events = random.randint(4, 8)
    fake_logs = random.choices(FAKE_LOG_EVENTS, k=n_events)
    method = random.choice(FAKE_DISTORTION_METHODS)

    inject_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "dreamdive_overlay",
        "phase": "log_injection_sim",
        "mitre_techniques": ["T1036"],
        "behavior_class": "log_injection_sim",
        "detection_opportunities": ["log_injection_sim"],
        "distortion_method_sim": method,
        "events_injected_sim": n_events,
        "target_logs_sim": targets,
        "injected_events_sim": [
            {"timestamp_sim": datetime.now(timezone.utc).isoformat(),
             "event": e["event"],
             "source_sim": e["source"]}
            for e in fake_logs
        ],
        "safe": True,
        "simulation_only": True,
        "files_written": False,
    }
    events.append(inject_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(inject_event) + "\n")

    return session_id, targets, method, fake_logs, events

def print_simulation(session_id, targets, method, fake_logs, events):
    print(f"\n  [SIMULATION]  dreamdive_overlay")
    print(f"  [SESSION]     {session_id}")
    print(f"  [TARGETS_SIM] {len(targets)}")
    print(f"  [METHOD_SIM]  {method}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1070.001, T1036")
    print(f"  [FILES]       NOT WRITTEN — synthetic only")
    print()
    for e in events:
        phase = e["phase"]
        if phase == "target_selection":
            print(f"  [PHASE 1: TARGET SELECTION]")
            for t in e["target_logs_sim"]:
                print(f"    {t}")
        elif phase == "log_injection_sim":
            print(f"\n  [PHASE 2: LOG INJECTION SIM]")
            print(f"    method_sim    : {e['distortion_method_sim']}")
            print(f"    events_sim    : {e['events_injected_sim']}")
            print(f"  [INJECTED EVENTS (simulated)]")
            for ev in e["injected_events_sim"][:5]:
                print(f"    [{ev['source_sim']}] {ev['event'][:60]}")
            if len(e["injected_events_sim"]) > 5:
                print(f"    ... +{len(e['injected_events_sim'])-5} more")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no file writes, no real log injection — simulation only")

@register_payload(name="dreamdive_overlay")
def main():
    session_id, targets, method, fake_logs, events = simulate_dreamdive()
    print_simulation(session_id, targets, method, fake_logs, events)

if __name__ == "__main__":
    main()
