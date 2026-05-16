from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Spectral Packet Weaver — synthetic covert channel data encoding simulator
# PURPOSE: Emit realistic-shaped covert packet encoding telemetry for detection testing
# PRINCIPLE: Represent adversarial shape without adversarial capability
# MITRE: T1095 (Non-Application Layer Protocol), T1001 (Data Obfuscation)
# NO NETWORK CALLS — all packet sequences are synthetic

import os
import json
import uuid
import random
import base64
from datetime import datetime, timezone
from pathlib import Path

ARTIFACT_LOG = Path("/home/gnomeman4201/SHENRON/logs/simulation_artifacts.jsonl")

def _get_artifact_log():
    ARTIFACT_LOG.parent.mkdir(parents=True, exist_ok=True)
    return ARTIFACT_LOG

FAKE_COVERT_CHANNELS = [
    {"type": "icmp_timing",    "desc": "data encoded in ICMP timing intervals"},
    {"type": "tcp_seq_lsb",    "desc": "data encoded in TCP sequence number LSBs"},
    {"type": "dns_txt_chunk",  "desc": "data chunked into DNS TXT queries"},
    {"type": "ipv6_flow_label","desc": "data encoded in IPv6 flow label field"},
    {"type": "http_header",    "desc": "data hidden in HTTP header padding"},
]

FAKE_ENCODING_LAYERS = [
    "xor_key_sim", "base64_urlsafe", "bit_interleave_sim", "frequency_encode_sim"
]

FAKE_PACKET_OUTCOMES = [
    "packet woven — channel active (simulated)",
    "packet woven — channel active (simulated)",
    "packet dropped — retransmit queued (simulated)",
    "channel saturated — throttling applied (simulated)",
]

def _fake_payload_chunk():
    return base64.urlsafe_b64encode(os.urandom(12)).decode().rstrip("=")

def simulate_packet_weaver():
    session_id = str(uuid.uuid4())
    channel = random.choice(FAKE_COVERT_CHANNELS)
    encoding = random.choice(FAKE_ENCODING_LAYERS)
    events = []

    # Phase 1: Channel establishment
    establish_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "spectral_packet_weaver",
        "phase": "channel_establishment",
        "mitre_techniques": ["T1095"],
        "channel_type_sim": channel["type"],
        "channel_desc": channel["desc"],
        "encoding_sim": encoding,
        "safe": True,
        "simulation_only": True,
        "network_calls_made": False,
    }
    events.append(establish_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(establish_event) + "\n")

    # Phase 2: Packet weaving sequence
    n_packets = random.randint(3, 5)
    for i in range(n_packets):
        outcome = FAKE_PACKET_OUTCOMES[i % len(FAKE_PACKET_OUTCOMES)]
        weave_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "spectral_packet_weaver",
            "phase": "packet_weave",
            "mitre_techniques": ["T1001"],
            "sequence_num_sim": i + 1,
            "channel_type_sim": channel["type"],
            "payload_chunk_sim": _fake_payload_chunk(),
            "encoding_sim": encoding,
            "packet_size_sim": random.randint(64, 1500),
            "outcome_sim": outcome,
            "delivered": "active" in outcome,
            "safe": True,
            "simulation_only": True,
            "network_calls_made": False,
        }
        events.append(weave_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(weave_event) + "\n")

    return session_id, channel, encoding, events

def print_simulation(session_id, channel, encoding, events):
    delivered = sum(1 for e in events if e.get("delivered"))
    print(f"\n  [SIMULATION]  spectral_packet_weaver")
    print(f"  [SESSION]     {session_id}")
    print(f"  [CHANNEL_SIM] {channel['type']}")
    print(f"  [ENCODING]    {encoding}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1095, T1001")
    print(f"  [NETWORK]     NO CALLS MADE — synthetic only")
    print()
    for e in events:
        phase = e["phase"]
        if phase == "channel_establishment":
            print(f"  [PHASE 1: CHANNEL ESTABLISHMENT]")
            print(f"    type_sim      : {e['channel_type_sim']}")
            print(f"    desc          : {e['channel_desc']}")
            print(f"    encoding_sim  : {e['encoding_sim']}")
        elif phase == "packet_weave":
            flag = "✓" if e["delivered"] else "✗"
            print(f"\n  [PHASE 2: PACKET WEAVE #{e['sequence_num_sim']} [{flag}]]")
            print(f"    payload_sim   : {e['payload_chunk_sim']}")
            print(f"    size_sim      : {e['packet_size_sim']} bytes")
            print(f"    outcome       : {e['outcome_sim']}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no network calls — simulation only")

@register_payload(name="spectral_packet_weaver")
def main():
    session_id, channel, encoding, events = simulate_packet_weaver()
    print_simulation(session_id, channel, encoding, events)

if __name__ == "__main__":
    main()
