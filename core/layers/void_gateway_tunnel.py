from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Void Gateway Tunnel — protocol tunneling telemetry simulator
# PURPOSE: Emit defender-observable telemetry for protocol tunneling and traffic routing
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1572 (Protocol Tunneling), T1090 (Proxy)
# DETECTION NOTES:
#   - Blue teams should alert on: non-standard protocols carrying encapsulated traffic
#   - Connections to infrastructure that resolve to CDN/cloud but carry non-CDN traffic
#   - DNS queries with unusually high entropy labels (data exfil via DNS)
#   - HTTPS traffic to non-standard ports with mismatched TLS fingerprints
#   - Traffic patterns inconsistent with the declared application protocol

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

FAKE_TUNNEL_PROTOCOLS_SIM = [
    {"outer": "DNS",   "inner": "TCP_sim",  "desc": "dns tunneling carrying tcp payload"},
    {"outer": "HTTPS", "inner": "HTTP_sim", "desc": "https wrapping plaintext http c2"},
    {"outer": "ICMP",  "inner": "data_sim", "desc": "icmp echo payload encoding"},
    {"outer": "WebSocket", "inner": "C2_sim","desc": "websocket carrying c2 protocol"},
]

FAKE_PROXY_TYPES_SIM = [
    "cdn_fronting_sim", "domain_fronting_sim",
    "tor_onion_sim", "vpn_hop_sim", "socks5_chain_sim"
]

FAKE_INFRA_SIM = [
    "cdn.example.invalid", "edge.example.invalid",
    "api.example.invalid", "update.example.invalid"
]

FAKE_TUNNEL_OUTCOMES_SIM = [
    "tunnel_established_traffic_flowing_sim",
    "tunnel_established_traffic_flowing_sim",
    "tunnel_probe_failed_fallback_initiated_sim",
    "tunnel_saturated_secondary_activated_sim",
]

DETECTION_OPPORTUNITIES = [
    "non_standard_protocol_carrying_encapsulated_traffic",
    "dns_queries_with_high_entropy_labels",
    "https_traffic_to_non_standard_port_tls_fingerprint_mismatch",
    "traffic_pattern_inconsistent_with_declared_protocol",
    "cdn_infrastructure_carrying_non_cdn_traffic_shape",
]

def _fake_dns_label():
    return base64.urlsafe_b64encode(os.urandom(8)).decode().rstrip("=").lower()

def simulate_void_tunnel():
    session_id = str(uuid.uuid4())
    tunnel_proto = random.choice(FAKE_TUNNEL_PROTOCOLS_SIM)
    proxy_type = random.choice(FAKE_PROXY_TYPES_SIM)
    infra_sim = random.choice(FAKE_INFRA_SIM)
    events = []

    # Phase 1: Tunnel establishment
    establish_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "void_gateway_tunnel",
        "phase": "tunnel_establishment",
        "mitre_techniques": ["T1572"],
        "behavior_class": "protocol_tunnel_init_sim",
        "outer_protocol_sim": tunnel_proto["outer"],
        "inner_protocol_sim": tunnel_proto["inner"],
        "tunnel_desc": tunnel_proto["desc"],
        "proxy_type_sim": proxy_type,
        "infra_target_sim": infra_sim,
        "detection_opportunities": [
            "non_standard_protocol_carrying_encapsulated_traffic",
            "cdn_infrastructure_carrying_non_cdn_traffic_shape",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "network_calls_made": False,
    }
    events.append(establish_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(establish_event) + "\n")

    # Phase 2: Traffic routing simulation
    n_packets = random.randint(3, 5)
    for i in range(n_packets):
        outcome = FAKE_TUNNEL_OUTCOMES_SIM[i % len(FAKE_TUNNEL_OUTCOMES_SIM)]
        dns_label_sim = _fake_dns_label() if tunnel_proto["outer"] == "DNS" else None
        route_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "void_gateway_tunnel",
            "phase": "traffic_routing",
            "mitre_techniques": ["T1090"],
            "behavior_class": "proxy_hop_traffic_sim",
            "packet_index": i + 1,
            "outer_protocol_sim": tunnel_proto["outer"],
            "proxy_hop_sim": proxy_type,
            "infra_sim": infra_sim,
            "dns_label_sim": dns_label_sim,
            "dns_entropy_sim": round(random.uniform(0.85, 0.97), 3) if dns_label_sim else None,
            "payload_size_sim": random.randint(64, 1400),
            "outcome_sim": outcome,
            "tls_fingerprint_mismatch_sim": random.choice([True, False]),
            "detection_opportunities": [
                "dns_queries_with_high_entropy_labels",
                "traffic_pattern_inconsistent_with_declared_protocol",
                "https_traffic_to_non_standard_port_tls_fingerprint_mismatch",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "network_calls_made": False,
        }
        events.append(route_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(route_event) + "\n")

    return session_id, tunnel_proto, proxy_type, events

def print_simulation(session_id, tunnel_proto, proxy_type, events):
    print(f"\n  [SIMULATION]  void_gateway_tunnel")
    print(f"  [SESSION]     {session_id}")
    print(f"  [TUNNEL_SIM]  {tunnel_proto['outer']} → {tunnel_proto['inner']}")
    print(f"  [PROXY_SIM]   {proxy_type}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1572, T1090")
    print(f"  [NETWORK]     NO CALLS MADE — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no socket calls, no real routing")
    print()
    for e in events:
        if e["phase"] == "tunnel_establishment":
            print(f"  [PHASE 1: TUNNEL ESTABLISHMENT]")
            print(f"    outer_sim     : {e['outer_protocol_sim']}")
            print(f"    inner_sim     : {e['inner_protocol_sim']}")
            print(f"    desc          : {e['tunnel_desc']}")
            print(f"    proxy_sim     : {e['proxy_type_sim']}")
            print(f"    infra_sim     : {e['infra_target_sim']}")
        elif e["phase"] == "traffic_routing":
            print(f"\n  [PHASE 2: ROUTE #{e['packet_index']}]")
            print(f"    behavior      : {e['behavior_class']}")
            if e.get("dns_label_sim"):
                print(f"    dns_label_sim : {e['dns_label_sim']} (entropy={e['dns_entropy_sim']})")
            print(f"    size_sim      : {e['payload_size_sim']}b")
            print(f"    tls_mismatch  : {e['tls_fingerprint_mismatch_sim']}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no network calls — telemetry only")

@register_payload(name="void_gateway_tunnel")
def main():
    session_id, tunnel_proto, proxy_type, events = simulate_void_tunnel()
    print_simulation(session_id, tunnel_proto, proxy_type, events)

if __name__ == "__main__":
    main()
