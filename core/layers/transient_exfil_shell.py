from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Transient Exfil Shell — ephemeral outbound tunnel telemetry simulator
# PURPOSE: Emit defender-observable telemetry for transient exfiltration channel patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1041 (Exfiltration Over C2 Channel), T1048 (Exfiltration Over Alternative Protocol)
# DETECTION NOTES:
#   - Blue teams should alert on: ephemeral high-port TCP listeners with single-connection lifecycle
#   - Outbound connections to non-standard ports from non-network processes
#   - Data transfer from process followed immediately by socket close
#   - One-shot connection servers that bind, accept once, then dissolve
#   - Exfil timing correlated with prior staging activity

import os
import json
import uuid
import random
from datetime import datetime, timezone
from pathlib import Path

ARTIFACT_LOG = Path("/home/gnomeman4201/SHENRON/logs/simulation_artifacts.jsonl")

def _get_artifact_log():
    ARTIFACT_LOG.parent.mkdir(parents=True, exist_ok=True)
    return ARTIFACT_LOG

FAKE_EXFIL_PROTOCOLS_SIM = [
    {"proto": "TCP",  "direction": "outbound", "desc": "raw tcp stream"},
    {"proto": "HTTPS","direction": "outbound", "desc": "encrypted http post"},
    {"proto": "DNS",  "direction": "outbound", "desc": "dns txt exfiltration"},
    {"proto": "ICMP", "direction": "outbound", "desc": "icmp payload encoding"},
]

FAKE_DATA_SHAPES_SIM = [
    "binary_blob_sim", "base64_encoded_block_sim",
    "chunked_json_sim", "encrypted_stream_sim"
]

FAKE_EXFIL_OUTCOMES_SIM = [
    "connection_established_data_sent_sim",
    "connection_established_data_sent_sim",
    "connection_timeout_retry_queued_sim",
    "exfil_complete_socket_dissolved_sim",
]

DETECTION_OPPORTUNITIES = [
    "ephemeral_high_port_tcp_listener_single_connection_lifecycle",
    "outbound_connection_non_standard_port_non_network_process",
    "data_transfer_followed_immediately_by_socket_close",
    "one_shot_bind_accept_dissolve_pattern",
    "exfil_timing_correlated_with_prior_staging",
]

def simulate_exfil_shell():
    session_id = str(uuid.uuid4())
    events = []

    proto_sim = random.choice(FAKE_EXFIL_PROTOCOLS_SIM)
    port_sim = random.randint(49152, 65535)
    data_shape_sim = random.choice(FAKE_DATA_SHAPES_SIM)
    data_size_sim = random.randint(128, 4096)

    # Phase 1: Shell spawn simulation
    spawn_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "transient_exfil_shell",
        "phase": "shell_spawn_sim",
        "mitre_techniques": ["T1041"],
        "behavior_class": "transient_listener_spawn_sim",
        "protocol_sim": proto_sim["proto"],
        "direction_sim": proto_sim["direction"],
        "port_sim": port_sim,
        "bind_addr_sim": "0.0.0.0_sim",
        "listen_backlog_sim": 1,
        "lifecycle_sim": "one_shot",
        "log_path_sim": "/home/gnomeman4201/SHENRON/logs/exfil_transients_sim.log",
        "detection_opportunities": [
            "ephemeral_high_port_tcp_listener_single_connection_lifecycle",
            "one_shot_bind_accept_dissolve_pattern",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "socket_bound": False,
    }
    events.append(spawn_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(spawn_event) + "\n")

    # Phase 2: Connection and data transfer simulation
    outcome = random.choice(FAKE_EXFIL_OUTCOMES_SIM)
    transfer_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "transient_exfil_shell",
        "phase": "data_transfer_sim",
        "mitre_techniques": ["T1048"],
        "behavior_class": "one_shot_exfil_transfer_sim",
        "remote_addr_sim": "203.0.113.example.invalid",
        "remote_port_sim": port_sim,
        "data_shape_sim": data_shape_sim,
        "data_size_bytes_sim": data_size_sim,
        "transfer_duration_sim": round(random.uniform(0.8, 2.5), 2),
        "outcome_sim": outcome,
        "socket_closed_after_sim": True,
        "detection_opportunities": [
            "outbound_connection_non_standard_port_non_network_process",
            "data_transfer_followed_immediately_by_socket_close",
            "exfil_timing_correlated_with_prior_staging",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "socket_bound": False,
    }
    events.append(transfer_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(transfer_event) + "\n")

    # Phase 3: Dissolution
    dissolve_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "transient_exfil_shell",
        "phase": "shell_dissolve_sim",
        "mitre_techniques": ["T1041"],
        "behavior_class": "transient_channel_teardown_sim",
        "port_released_sim": port_sim,
        "cleanup_delay_sim": round(random.uniform(2.5, 4.0), 2),
        "log_entry_written_sim": True,
        "log_path_sim": "/home/gnomeman4201/SHENRON/logs/exfil_transients_sim.log",
        "detection_opportunities": [
            "ephemeral_high_port_tcp_listener_single_connection_lifecycle",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "socket_bound": False,
    }
    events.append(dissolve_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(dissolve_event) + "\n")

    return session_id, proto_sim, port_sim, events

def print_simulation(session_id, proto_sim, port_sim, events):
    print(f"\n  [SIMULATION]  transient_exfil_shell")
    print(f"  [SESSION]     {session_id}")
    print(f"  [PROTO_SIM]   {proto_sim['proto']} / {proto_sim['desc']}")
    print(f"  [PORT_SIM]    {port_sim}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1041, T1048")
    print(f"  [SOCKETS]     NOT BOUND — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no socket calls, no real connections")
    print()
    for e in events:
        print(f"  [{e['phase'].upper()}]")
        print(f"    behavior      : {e['behavior_class']}")
        if "port_sim" in e and e["phase"] == "shell_spawn_sim":
            print(f"    port_sim      : {e['port_sim']}")
            print(f"    lifecycle_sim : {e['lifecycle_sim']}")
        if "data_size_bytes_sim" in e:
            print(f"    data_sim      : {e['data_size_bytes_sim']}b {e['data_shape_sim']}")
            print(f"    outcome_sim   : {e['outcome_sim']}")
        if "cleanup_delay_sim" in e:
            print(f"    delay_sim     : {e['cleanup_delay_sim']}s")
        print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no sockets bound — telemetry only")

@register_payload(name="transient_exfil_shell")
def main():
    session_id, proto_sim, port_sim, events = simulate_exfil_shell()
    print_simulation(session_id, proto_sim, port_sim, events)

if __name__ == "__main__":
    main()
