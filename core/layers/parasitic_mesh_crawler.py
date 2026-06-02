from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Parasitic Mesh Crawler — synthetic LAN mesh propagation simulator
# PURPOSE: Emit realistic-shaped lateral spread and mesh infection telemetry
# PRINCIPLE: Represent adversarial shape without adversarial capability
# MITRE: T1021 (Remote Services), T1570 (Lateral Tool Transfer)
# NO NETWORK CALLS — no ping, no port scans, no real connections, no file drops

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

FAKE_SUBNETS = [
    "10.10.1", "10.10.2", "172.16.0", "192.168.1", "192.168.10"
]

FAKE_SPREAD_VECTORS = [
    {"port": 5555, "method": "ADB",  "desc": "Android Debug Bridge"},
    {"port": 22,   "method": "SSH",  "desc": "Secure Shell"},
    {"port": 80,   "method": "HTTP", "desc": "HTTP service"},
    {"port": 445,  "method": "SMB",  "desc": "SMB file share"},
    {"port": 3389, "method": "RDP",  "desc": "Remote Desktop"},
]

FAKE_HOSTNAMES = [
    "ANDROID-DEV-01", "WORKSTATION-07", "FILESERVER-02",
    "IOT-GATEWAY", "LAPTOP-USER3", "PRINTSERVER"
]

FAKE_SEED_NAMES = [
    "SHENRON_seed", "sys_update", "cache_helper", "net_monitor"
]

FAKE_SPREAD_OUTCOMES = [
    "vector identified — spread attempted (simulated)",
    "vector identified — spread attempted (simulated)",
    "vector blocked — fallback initiated (simulated)",
    "seed deployed — propagation confirmed (simulated)",
]

def _fake_ip(subnet):
    return f"{subnet}.{random.randint(2, 254)}"

def simulate_mesh_crawl():
    session_id = str(uuid.uuid4())
    subnet = random.choice(FAKE_SUBNETS)
    local_ip_sim = _fake_ip(subnet)
    events = []

    # Phase 1: Host sweep simulation
    n_hosts = random.randint(3, 7)
    hosts = []
    used = set()
    for _ in range(n_hosts):
        while True:
            ip = _fake_ip(subnet)
            if ip not in used and ip != local_ip_sim:
                used.add(ip)
                break
        hosts.append({
            "ip": ip,
            "hostname": random.choice(FAKE_HOSTNAMES),
            "latency_sim": round(random.uniform(0.5, 15.0), 2),
        })

    sweep_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "parasitic_mesh_crawler",
        "phase": "host_sweep",
        "mitre_techniques": ["T1021"],
        "behavior_class": "host_sweep",
        "detection_opportunities": ["host_sweep"],
        "subnet_sim": f"{subnet}.0/24",
        "local_ip_sim": local_ip_sim,
        "hosts_found_sim": len(hosts),
        "hosts": hosts,
        "safe": True,
        "simulation_only": True,
        "network_calls_made": False,
        "files_dropped": False,
    }
    events.append(sweep_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(sweep_event) + "\n")

    # Phase 2: Spread attempt per host
    for host in hosts[:3]:
        vectors = random.sample(FAKE_SPREAD_VECTORS, random.randint(1, 3))
        outcome = random.choice(FAKE_SPREAD_OUTCOMES)
        seed_name = random.choice(FAKE_SEED_NAMES)

        spread_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "parasitic_mesh_crawler",
            "phase": "spread_attempt",
            "mitre_techniques": ["T1570"],
            "behavior_class": "spread_attempt",
            "detection_opportunities": ["spread_attempt"],
            "target_ip_sim": host["ip"],
            "target_hostname": host["hostname"],
            "vectors_sim": [v["method"] for v in vectors],
            "seed_name_sim": f"{seed_name}_{host['ip'].replace('.','_')}.txt",
            "outcome_sim": outcome,
            "propagated": "confirmed" in outcome,
            "safe": True,
            "simulation_only": True,
            "network_calls_made": False,
            "files_dropped": False,
        }
        events.append(spread_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(spread_event) + "\n")

    return session_id, subnet, local_ip_sim, hosts, events

def print_simulation(session_id, subnet, local_ip_sim, hosts, events):
    propagated = sum(1 for e in events if e.get("propagated"))
    print(f"\n  [SIMULATION]  parasitic_mesh_crawler")
    print(f"  [SESSION]     {session_id}")
    print(f"  [SUBNET_SIM]  {subnet}.0/24")
    print(f"  [LOCAL_SIM]   {local_ip_sim}")
    print(f"  [HOSTS_SIM]   {len(hosts)} found, {propagated} seeded")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1021, T1570")
    print(f"  [NETWORK]     NO CALLS MADE — synthetic only")
    print(f"  [FILES]       NOT DROPPED — synthetic only")
    print()
    for e in events:
        phase = e["phase"]
        if phase == "host_sweep":
            print(f"  [PHASE 1: HOST SWEEP]")
            for h in e["hosts"][:4]:
                print(f"    {h['ip']:<18} {h['hostname']:<20} {h['latency_sim']}ms")
            if len(e["hosts"]) > 4:
                print(f"    ... +{len(e['hosts'])-4} more")
        elif phase == "spread_attempt":
            flag = "✓" if e["propagated"] else " "
            print(f"\n  [PHASE 2: SPREAD ATTEMPT [{flag}]]")
            print(f"    target_sim    : {e['target_ip_sim']} ({e['target_hostname']})")
            print(f"    vectors_sim   : {', '.join(e['vectors_sim'])}")
            print(f"    seed_sim      : {e['seed_name_sim']}")
            print(f"    outcome       : {e['outcome_sim']}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no network calls, no file drops — simulation only")

@register_payload(name="parasitic_mesh_crawler")
def main():
    session_id, subnet, local_ip_sim, hosts, events = simulate_mesh_crawl()
    print_simulation(session_id, subnet, local_ip_sim, hosts, events)

if __name__ == "__main__":
    main()
