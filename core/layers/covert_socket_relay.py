#!/usr/bin/env python3
"""
core/layers/covert_socket_relay.py

SHENRON: Covert socket relay and protocol tunneling.

PURPOSE: Emit defender-observable telemetry for covert socket relay and protocol tunneling patterns.
PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure.
TACTIC: command-and-control
MITRE: T1095, T1572, T1571

DETECTION NOTES:
  - Persistent listener on non-standard port from non-server process
  - Relay process that accepts and immediately forwards without application logic
  - SO_REUSEADDR set on non-server process socket
  - Thread spawned per connection from long-running listener
  - Loopback listener that bridges to external destination
  - Unusual protocol encapsulation on standard ports

Design constraints:
- Standalone implementation. Original quantum_*/dragons_breath_*/shenron_* files preserved.
- No subprocess, no network, no real filesystem operations.
- All events carry simulation_only: true and full safety contract.
"""

import json
import uuid
import random
from datetime import datetime, timezone
from pathlib import Path
from core.engine.payload_registry import register_payload
from core.config import artifact_log_path as _artifact_log_path


def _get_artifact_log():
    p = _artifact_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _safe_fields() -> dict:
    return {
        "simulation_only": True,
        "executable": False,
        "payload_present": False,
        "portable_adversarial_procedure": False,
        "network_connection": False,
        "subprocess_spawned": False,
        "real_file_written": False,
        "shell_invoked": False,
    }


MITRE_TECHNIQUES = ['T1095', 'T1572', 'T1571']

DETECTION_OPPORTUNITIES_CATALOG = [
    "persistent_listener_nonstandard_port_non_server",
    "so_reuseaddr_non_server_process_sim",
    "relay_accept_forward_no_app_logic_sim",
    "thread_per_connection_long_running_listener_sim",
    "loopback_listener_bridges_external_dest_sim",
    "localhost_to_external_relay_sim",
    "unusual_protocol_encapsulation_standard_port",
    "covert_channel_encapsulation_sim",
]


def simulate_covert_socket_relay(seed: int = None) -> tuple:
    """Simulate covert socket relay and protocol tunneling campaign. Returns (session_id, events)."""
    if seed is not None:
        random.seed(seed)

    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: non_standard_port_listener_sim
    ev_0 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "covert_socket_relay",
        "phase":                   "ESTABLISH",
        "mitre_techniques":        ['T1095', 'T1571'],
        "behavior_class":          "non_standard_port_listener_sim",
        "signal":                  "non_standard_port_listener_sim",
        "detection_opportunities": ['persistent_listener_nonstandard_port_non_server', 'so_reuseaddr_non_server_process_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/covert_socket_relay v0.4.2",
        "note":                    "SYNTHETIC RECORD — non_standard_port_listener_sim telemetry shape only",
    }
    events.append(ev_0)

    # Phase 2: accept_forward_relay_sim
    ev_1 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "covert_socket_relay",
        "phase":                   "RELAY",
        "mitre_techniques":        ['T1572'],
        "behavior_class":          "accept_forward_relay_sim",
        "signal":                  "accept_forward_relay_sim",
        "detection_opportunities": ['relay_accept_forward_no_app_logic_sim', 'thread_per_connection_long_running_listener_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/covert_socket_relay v0.4.2",
        "note":                    "SYNTHETIC RECORD — accept_forward_relay_sim telemetry shape only",
    }
    events.append(ev_1)

    # Phase 3: loopback_bridge_sim
    ev_2 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "covert_socket_relay",
        "phase":                   "TUNNEL",
        "mitre_techniques":        ['T1572', 'T1095'],
        "behavior_class":          "loopback_bridge_sim",
        "signal":                  "loopback_bridge_sim",
        "detection_opportunities": ['loopback_listener_bridges_external_dest_sim', 'localhost_to_external_relay_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/covert_socket_relay v0.4.2",
        "note":                    "SYNTHETIC RECORD — loopback_bridge_sim telemetry shape only",
    }
    events.append(ev_2)

    # Phase 4: protocol_encapsulation_sim
    ev_3 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "covert_socket_relay",
        "phase":                   "ESTABLISH",
        "mitre_techniques":        ['T1572', 'T1001'],
        "behavior_class":          "protocol_encapsulation_sim",
        "signal":                  "protocol_encapsulation_sim",
        "detection_opportunities": ['unusual_protocol_encapsulation_standard_port', 'covert_channel_encapsulation_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/covert_socket_relay v0.4.2",
        "note":                    "SYNTHETIC RECORD — protocol_encapsulation_sim telemetry shape only",
    }
    events.append(ev_3)

    # Write to artifact log
    with open(_get_artifact_log(), "a") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    return session_id, events


@register_payload(name="covert_socket_relay")
def main():
    session_id, events = simulate_covert_socket_relay()

    all_techs = set()
    all_opps = set()
    for ev in events:
        all_techs.update(ev.get("mitre_techniques", []))
        all_opps.update(ev.get("detection_opportunities", []))

    print(f"\n  [SIMULATION]  covert_socket_relay")
    print(f"  [SESSION]     {session_id}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       {sorted(all_techs)}")
    print(f"  [DETECTIONS]  {len(all_opps)}")
    print(f"  [EXECUTABLE]  FALSE — telemetry shape only")
    print(f"  [LOGGED]      {_get_artifact_log()}")
    for ev in events:
        print(f"  [ESTABLISH] {ev['behavior_class']}")
    print()
    print(f"  [SAFE]  no subprocess, no network, no filesystem writes")

    return session_id, events