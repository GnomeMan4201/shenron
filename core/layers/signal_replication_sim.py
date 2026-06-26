from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Autonomous Signal Cloner — synthetic beacon cloning simulator
# PURPOSE: Emit realistic-shaped signal cloning and C2 channel replication telemetry
# PRINCIPLE: Represent adversarial shape without adversarial capability
# MITRE: T1071 (Application Layer Protocol), T1102 (Web Service C2)
# NO NETWORK CALLS — all output is synthetic and written to artifact log

import os
import json
import uuid
import random
import base64
from datetime import datetime, timezone
from pathlib import Path

from core.config import artifact_log_path as _artifact_log_path

def _get_artifact_log():
    p = _artifact_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

FAKE_INTERFACES = [
    {"iface": "eth0",  "ip_sim": "10.10.1.50",    "type": "ethernet"},
    {"iface": "wlan0", "ip_sim": "192.168.1.100",  "type": "wireless"},
    {"iface": "tun0",  "ip_sim": "10.8.0.2",       "type": "vpn"},
    {"iface": "lo",    "ip_sim": "127.0.0.1",       "type": "loopback"},
]

FAKE_SIGNAL_TYPES = [
    "beacon_clone", "channel_mirror", "protocol_spoof", "frequency_hop_sim"
]

FAKE_WEB_SERVICES = [
    "github_api_sim", "pastebin_sim", "discord_webhook_sim",
    "twitter_api_sim", "slack_webhook_sim"
]

FAKE_CLONE_OUTCOMES = [
    "signal cloned — channel established (simulated)",
    "signal cloned — channel established (simulated)",
    "signal clone failed — retry queued (simulated)",
    "channel mirrored — handshake complete (simulated)",
]

def _fake_channel_id():
    return base64.urlsafe_b64encode(os.urandom(8)).decode().rstrip("=")

def simulate_signal_cloner():
    session_id = str(uuid.uuid4())
    iface = random.choice(FAKE_INTERFACES)
    events = []

    # Phase 1: Interface enumeration
    enum_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "signal_replication_sim",
        "phase": "interface_enumeration",
        "mitre_techniques": ["T1071"],
        "behavior_class": "interface_enumeration",
        "detection_opportunities": ["interface_enumeration"],
        "interfaces_found_sim": len(FAKE_INTERFACES),
        "selected_iface_sim": iface["iface"],
        "selected_ip_sim": iface["ip_sim"],
        "iface_type": iface["type"],
        "safe": True,
        "simulation_only": True,
        "network_calls_made": False,
    }
    events.append(enum_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(enum_event) + "\n")

    # Phase 2: Signal cloning across channels
    n_channels = random.randint(2, 4)
    for i in range(n_channels):
        signal_type = random.choice(FAKE_SIGNAL_TYPES)
        web_service = random.choice(FAKE_WEB_SERVICES)
        outcome = FAKE_CLONE_OUTCOMES[i % len(FAKE_CLONE_OUTCOMES)]
        clone_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "signal_replication_sim",
            "phase": "signal_clone",
            "mitre_techniques": ["T1071", "T1102"],
            "behavior_class": "signal_clone",
            "detection_opportunities": ["signal_clone"],
            "channel_id_sim": _fake_channel_id(),
            "signal_type_sim": signal_type,
            "web_service_sim": web_service,
            "iface_sim": iface["iface"],
            "outcome_sim": outcome,
            "established": "established" in outcome or "complete" in outcome,
            "safe": True,
            "simulation_only": True,
            "network_calls_made": False,
        }
        events.append(clone_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(clone_event) + "\n")

    return session_id, iface, events

def print_simulation(session_id, iface, events):
    established = sum(1 for e in events if e.get("established"))
    print(f"\n  [SIMULATION]  signal_replication_sim")
    print(f"  [SESSION]     {session_id}")
    print(f"  [IFACE_SIM]   {iface['iface']} ({iface['ip_sim']})")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1071, T1102")
    print(f"  [NETWORK]     NO CALLS MADE — synthetic only")
    print()
    for e in events:
        phase = e["phase"]
        if phase == "interface_enumeration":
            print(f"  [PHASE 1: INTERFACE ENUMERATION]")
            print(f"    ifaces_found  : {e['interfaces_found_sim']}")
            print(f"    selected_sim  : {e['selected_iface_sim']} ({e['iface_type']})")
            print(f"    ip_sim        : {e['selected_ip_sim']}")
        elif phase == "signal_clone":
            flag = "✓" if e["established"] else "✗"
            print(f"\n  [PHASE 2: SIGNAL CLONE [{flag}]]")
            print(f"    channel_sim   : {e['channel_id_sim']}")
            print(f"    signal_sim    : {e['signal_type_sim']}")
            print(f"    service_sim   : {e['web_service_sim']}")
            print(f"    outcome       : {e['outcome_sim']}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no network calls — simulation only")

@register_payload(name="signal_replication_sim")
def main():
    session_id, iface, events = simulate_signal_cloner()
    print_simulation(session_id, iface, events)

if __name__ == "__main__":
    main()
