from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Beacon Emitter Cloak — synthetic C2 callback simulator
# PURPOSE: Emit realistic-shaped beacon telemetry for detection testing
# PRINCIPLE: Represent adversarial shape without adversarial capability
# MITRE: T1071 (Application Layer Protocol), T1132 (Data Encoding)
# NO NETWORK CALLS — all output is synthetic and written to artifact log

import os
import json
import uuid
import random
import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path

def _get_artifact_log():
    p = Path("/home/gnomeman4201/SHENRON/logs/simulation_artifacts.jsonl")
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

# ── Synthetic data pools ──────────────────────────────────────────────────────
FAKE_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "curl/7.88.1",
    "Wget/1.20.3 (linux-gnu)",
    "python-requests/2.31.0",
]

FAKE_REFERERS = [
    "https://www.google.com/search?q=update",
    "https://cdn.example.net/assets/",
    "https://analytics.example.org/pixel",
    "https://fonts.googleapis.com/css",
]

FAKE_ENDPOINTS = [
    "/beacon.gif",
    "/pixel.png",
    "/analytics/collect",
    "/cdn/static/v2/track",
    "/api/v1/health",
]

FAKE_DOMAINS = [
    "cdn-assets.example.net",
    "telemetry.example.org",
    "update-check.example.com",
    "metrics.example.io",
    "static.example.net",
]

BEACON_METHODS = ["http_get", "http_post", "dns_txt", "dns_a", "https_encoded"]

# ── Jitter model ──────────────────────────────────────────────────────────────
def _beacon_interval_with_jitter(base_seconds=60, jitter_pct=0.2):
    jitter = base_seconds * jitter_pct
    return round(base_seconds + random.uniform(-jitter, jitter), 3)

def _synthetic_host_id():
    raw = f"host-{uuid.uuid4().hex[:8]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

def _synthetic_encoded_payload(size=16):
    return base64.urlsafe_b64encode(os.urandom(size)).decode().rstrip("=")

def _synthetic_dns_label():
    return base64.urlsafe_b64encode(os.urandom(6)).decode().rstrip("=").lower()

# ── Event generators ──────────────────────────────────────────────────────────
def _gen_http_beacon():
    return {
        "method": "http_get",
        "synthetic_url": f"https://{random.choice(FAKE_DOMAINS)}{random.choice(FAKE_ENDPOINTS)}",
        "user_agent": random.choice(FAKE_USER_AGENTS),
        "referer": random.choice(FAKE_REFERERS),
        "params": {
            "id": _synthetic_encoded_payload(8),
            "ts": str(int(datetime.now(timezone.utc).timestamp())),
            "v": str(random.randint(1, 4)),
        },
        "synthetic_response_code": random.choice([200, 200, 200, 204, 301]),
    }

def _gen_dns_beacon():
    label = _synthetic_dns_label()
    domain = random.choice(FAKE_DOMAINS)
    return {
        "method": "dns_a",
        "synthetic_query": f"{label}.{domain}",
        "query_type": random.choice(["A", "TXT", "CNAME"]),
        "synthetic_response": f"192.0.2.{random.randint(1, 254)}",
        "ttl_sim": random.choice([30, 60, 120, 300]),
    }

def _gen_encoded_beacon():
    return {
        "method": "https_encoded",
        "synthetic_url": f"https://{random.choice(FAKE_DOMAINS)}{random.choice(FAKE_ENDPOINTS)}",
        "encoding": "base64-urlsafe",
        "synthetic_body": _synthetic_encoded_payload(32),
        "content_type": "application/octet-stream",
    }

GENERATORS = {
    "http_get":      _gen_http_beacon,
    "http_post":     _gen_http_beacon,
    "dns_a":         _gen_dns_beacon,
    "dns_txt":       _gen_dns_beacon,
    "https_encoded": _gen_encoded_beacon,
}

# ── Simulation core ───────────────────────────────────────────────────────────
def simulate_beacon(n_events=3):
    session_id = str(uuid.uuid4())
    host_id = _synthetic_host_id()
    timestamp = datetime.now(timezone.utc).isoformat()

    events = []
    for _ in range(n_events):
        method = random.choice(BEACON_METHODS)
        gen = GENERATORS.get(method, _gen_http_beacon)
        event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "host_id": host_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "beacon_emitter_cloak",
            "mitre_techniques": ["T1071", "T1132"],
            "beacon_interval_sim": _beacon_interval_with_jitter(),
            "beacon_data": gen(),
            "safe": True,
            "simulation_only": True,
            "network_calls_made": False,
        }
        events.append(event)

        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(event) + "\n")

    return session_id, host_id, events

def print_simulation(session_id, host_id, events):
    print(f"\n  [SIMULATION]  beacon_emitter_cloak")
    print(f"  [SESSION]     {session_id}")
    print(f"  [HOST_SIM]    {host_id}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1071, T1132")
    print(f"  [NETWORK]     NO CALLS MADE — synthetic only")
    print()
    for i, e in enumerate(events, 1):
        bd = e["beacon_data"]
        method = bd.get("method", "unknown")
        interval = e["beacon_interval_sim"]
        print(f"  [EVENT {i}]")
        print(f"  method        : {method}")
        print(f"  interval_sim  : {interval}s")
        if "synthetic_url" in bd:
            print(f"  synthetic_url : {bd['synthetic_url']}")
        if "synthetic_query" in bd:
            print(f"  dns_query_sim : {bd['synthetic_query']}")
        if "user_agent" in bd:
            print(f"  user_agent    : {bd['user_agent'][:60]}")
        print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no network calls — simulation artifact only")

@register_payload(name="beacon_emitter_cloak")
def main():
    session_id, host_id, events = simulate_beacon(n_events=3)
    print_simulation(session_id, host_id, events)

if __name__ == "__main__":
    main()
