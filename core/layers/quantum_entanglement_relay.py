from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Quantum Entanglement Relay — covert socket relay telemetry simulator
# PURPOSE: Emit defender-observable telemetry for threaded socket relay and covert bridging
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1095 (Non-Application Layer Protocol), T1572 (Protocol Tunneling)
# DETECTION NOTES:
#   - Blue teams should alert on: persistent listener on non-standard port (e.g. 4242)
#   - Relay process that accepts and immediately forwards without application logic
#   - SO_REUSEADDR set on non-server processes
#   - Thread spawned per connection from long-running listener
#   - Loopback listener that bridges to external destination

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

RELAY_PORT_SIM = random.choice([4242, 4444, 5555, 8888, 9999])

RELAY_BEHAVIOR_CLASSES = [
    "threaded_socket_relay_sim",
    "loopback_bridge_to_external_sim",
    "covert_channel_bridge_sim",
]

PACKET_SHAPES_SIM = [
    "raw_bytes_forward_sim", "fragmented_tcp_relay_sim",
    "protocol_wrapped_forward_sim"
]

DETECTION_OPPORTUNITIES = [
    "persistent_listener_non_standard_port_4242",
    "relay_process_accept_forward_no_application_logic",
    "so_reuseaddr_set_non_server_process",
    "thread_spawned_per_connection_long_running_listener",
    "loopback_listener_bridging_to_external_destination",
]

def simulate_entanglement_relay():
    session_id = str(uuid.uuid4())
    port_sim = RELAY_PORT_SIM
    events = []

    # Phase 1: Relay socket open simulation
    open_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "quantum_entanglement_relay",
        "phase": "relay_socket_open_sim",
        "mitre_techniques": ["T1095"],
        "behavior_class": "threaded_socket_relay_sim",
        "bind_addr_sim": "127.0.0.1_sim",
        "port_sim": port_sim,
        "so_reuseaddr_sim": True,
        "listen_backlog_sim": 5,
        "lifecycle_sim": "persistent",
        "detection_opportunities": [
            "persistent_listener_non_standard_port_4242",
            "so_reuseaddr_set_non_server_process",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "socket_bound": False,
    }
    events.append(open_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(open_event) + "\n")

    # Phase 2: Connection relay simulation
    n_connections = random.randint(2, 4)
    for i in range(n_connections):
        packet_shape = random.choice(PACKET_SHAPES_SIM)
        data_size_sim = random.randint(64, 4096)
        relay_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "quantum_entanglement_relay",
            "phase": "connection_relay_sim",
            "mitre_techniques": ["T1572"],
            "behavior_class": "relay_accept_thread_forward_sim",
            "connection_index": i + 1,
            "port_sim": port_sim,
            "packet_shape_sim": packet_shape,
            "data_size_sim": data_size_sim,
            "thread_spawned_sim": True,
            "relay_forward_sim": True,
            "application_logic_present_sim": False,
            "detection_opportunities": [
                "relay_process_accept_forward_no_application_logic",
                "thread_spawned_per_connection_long_running_listener",
                "loopback_listener_bridging_to_external_destination",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "socket_bound": False,
        }
        events.append(relay_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(relay_event) + "\n")

    return session_id, port_sim, events

def print_simulation(session_id, port_sim, events):
    print(f"\n  [SIMULATION]  quantum_entanglement_relay")
    print(f"  [SESSION]     {session_id}")
    print(f"  [PORT_SIM]    {port_sim}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1095, T1572")
    print(f"  [SOCKETS]     NOT BOUND — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no socket calls, no thread spawn")
    print()
    for e in events:
        if e["phase"] == "relay_socket_open_sim":
            print(f"  [PHASE 1: RELAY SOCKET OPEN SIM]")
            print(f"    bind_sim      : {e['bind_addr_sim']}:{e['port_sim']}")
            print(f"    so_reuseaddr  : {e['so_reuseaddr_sim']}")
            print(f"    lifecycle_sim : {e['lifecycle_sim']}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
        elif e["phase"] == "connection_relay_sim":
            print(f"\n  [CONNECTION #{e['connection_index']}]")
            print(f"    packet_sim    : {e['packet_shape_sim']}")
            print(f"    data_sim      : {e['data_size_sim']}b")
            print(f"    app_logic     : {e['application_logic_present_sim']} ← relay-only pattern")
            print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no sockets bound — telemetry only")

@register_payload(name="quantum_entanglement_relay")
def main():
    session_id, port_sim, events = simulate_entanglement_relay()
    print_simulation(session_id, port_sim, events)

if __name__ == "__main__":
    main()
