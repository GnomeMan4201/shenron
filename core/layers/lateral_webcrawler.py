from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Lateral Webcrawler — synthetic lateral movement simulator
# PURPOSE: Emit realistic-shaped lateral movement telemetry for detection testing
# PRINCIPLE: Represent adversarial shape without adversarial capability
# MITRE: T1021 (Remote Services), T1046 (Network Service Discovery), T1135 (Network Share Discovery)
# NO NETWORK CALLS — all output is synthetic and written to artifact log

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

# ── Synthetic data pools ──────────────────────────────────────────────────────
FAKE_SUBNETS = [
    "10.10.1", "10.10.2", "172.16.0", "172.16.1", "192.168.1", "192.168.10"
]

FAKE_SERVICES = [
    {"port": 445,  "service": "SMB",   "banner": "Windows SMB"},
    {"port": 22,   "service": "SSH",   "banner": "OpenSSH_8.9"},
    {"port": 80,   "service": "HTTP",  "banner": "Apache/2.4.52"},
    {"port": 443,  "service": "HTTPS", "banner": "nginx/1.18.0"},
    {"port": 3389, "service": "RDP",   "banner": "Microsoft RDP"},
    {"port": 5985, "service": "WinRM", "banner": "Microsoft WinRM"},
    {"port": 8080, "service": "HTTP",  "banner": "Tomcat/9.0.65"},
    {"port": 2049, "service": "NFS",   "banner": "NFS v4"},
]

FAKE_SHARES = [
    "ADMIN$", "C$", "IPC$", "SYSVOL", "NETLOGON",
    "shared", "backup", "files", "data", "users"
]

FAKE_HOSTNAMES = [
    "WORKSTATION-01", "FILESERVER-02", "DC-PRIMARY", "WEBSERVER-03",
    "DEVBOX-04", "DBSERVER-01", "PRINTSERVER", "BACKUPHOST"
]

FAKE_PATHS = [
    "/admin/", "/login/", "/dashboard/", "/api/v1/",
    "/wp-admin/", "/phpmyadmin/", "/.git/", "/backup/"
]

# ── Synthetic event generators ────────────────────────────────────────────────
def _fake_ip(subnet):
    return f"{subnet}.{random.randint(2, 254)}"

def _gen_host_discovery(subnet):
    n_hosts = random.randint(3, 8)
    hosts = []
    used = set()
    for _ in range(n_hosts):
        while True:
            ip = _fake_ip(subnet)
            if ip not in used:
                used.add(ip)
                break
        hosts.append({
            "ip": ip,
            "hostname": random.choice(FAKE_HOSTNAMES),
            "latency_ms": round(random.uniform(0.4, 12.0), 2),
            "status": "up",
        })
    return hosts

def _gen_port_scan(host_ip):
    n_open = random.randint(1, 4)
    open_ports = random.sample(FAKE_SERVICES, min(n_open, len(FAKE_SERVICES)))
    return [
        {
            "port": svc["port"],
            "service": svc["service"],
            "banner_sim": svc["banner"],
            "state": "open",
        }
        for svc in open_ports
    ]

def _gen_share_discovery(host_ip):
    n_shares = random.randint(2, 5)
    shares = random.sample(FAKE_SHARES, min(n_shares, len(FAKE_SHARES)))
    return [
        {
            "share": s,
            "path": f"\\\\{host_ip}\\{s}",
            "access": random.choice(["READ", "READ/WRITE", "NO ACCESS"]),
        }
        for s in shares
    ]

def _gen_web_crawl(host_ip, port=80):
    n_paths = random.randint(2, 5)
    paths = random.sample(FAKE_PATHS, min(n_paths, len(FAKE_PATHS)))
    return [
        {
            "synthetic_url": f"http://{host_ip}:{port}{p}",
            "status_code_sim": random.choice([200, 200, 301, 401, 403, 404]),
            "links_found_sim": random.randint(0, 12),
        }
        for p in paths
    ]

# ── Simulation core ───────────────────────────────────────────────────────────
def simulate_lateral_movement(n_hops=2):
    session_id = str(uuid.uuid4())
    subnet = random.choice(FAKE_SUBNETS)
    timestamp = datetime.now(timezone.utc).isoformat()
    all_events = []

    # Phase 1: Host discovery
    hosts = _gen_host_discovery(subnet)
    discovery_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "lateral_webcrawler",
        "phase": "host_discovery",
        "mitre_techniques": ["T1046"],
        "synthetic_subnet": f"{subnet}.0/24",
        "hosts_found_sim": len(hosts),
        "hosts": hosts,
        "safe": True,
        "simulation_only": True,
        "network_calls_made": False,
    }
    all_events.append(discovery_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(discovery_event) + "\n")

    # Phase 2: Per-host port scan + share/web discovery
    for hop, host in enumerate(hosts[:n_hops]):
        ip = host["ip"]

        ports = _gen_port_scan(ip)
        port_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "lateral_webcrawler",
            "phase": "port_scan",
            "mitre_techniques": ["T1046"],
            "target_ip_sim": ip,
            "hop": hop + 1,
            "open_ports": ports,
            "safe": True,
            "simulation_only": True,
            "network_calls_made": False,
        }
        all_events.append(port_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(port_event) + "\n")

        # SMB share discovery if port 445 open
        if any(p["port"] == 445 for p in ports):
            shares = _gen_share_discovery(ip)
            share_event = {
                "artifact_id": str(uuid.uuid4()),
                "session_id": session_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "layer": "lateral_webcrawler",
                "phase": "share_discovery",
                "mitre_techniques": ["T1135"],
                "target_ip_sim": ip,
                "hop": hop + 1,
                "shares": shares,
                "safe": True,
                "simulation_only": True,
                "network_calls_made": False,
            }
            all_events.append(share_event)
            with open(_get_artifact_log(), "a") as f:
                f.write(json.dumps(share_event) + "\n")

        # Web crawl if HTTP/HTTPS open
        http_ports = [p["port"] for p in ports if p["service"] in ("HTTP", "HTTPS")]
        if http_ports:
            crawl = _gen_web_crawl(ip, http_ports[0])
            crawl_event = {
                "artifact_id": str(uuid.uuid4()),
                "session_id": session_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "layer": "lateral_webcrawler",
                "phase": "web_crawl",
                "mitre_techniques": ["T1021"],
                "target_ip_sim": ip,
                "hop": hop + 1,
                "paths_crawled": crawl,
                "safe": True,
                "simulation_only": True,
                "network_calls_made": False,
            }
            all_events.append(crawl_event)
            with open(_get_artifact_log(), "a") as f:
                f.write(json.dumps(crawl_event) + "\n")

    return session_id, subnet, hosts, all_events

def print_simulation(session_id, subnet, hosts, events):
    print(f"\n  [SIMULATION]  lateral_webcrawler")
    print(f"  [SESSION]     {session_id}")
    print(f"  [SUBNET_SIM]  {subnet}.0/24")
    print(f"  [HOSTS_FOUND] {len(hosts)}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1021, T1046, T1135")
    print(f"  [NETWORK]     NO CALLS MADE — synthetic only")
    print()
    for e in events:
        phase = e["phase"]
        if phase == "host_discovery":
            print(f"  [PHASE 1: HOST DISCOVERY]")
            for h in e["hosts"][:3]:
                print(f"    {h['ip']:<18} {h['hostname']:<20} latency={h['latency_ms']}ms")
            if len(e["hosts"]) > 3:
                print(f"    ... +{len(e['hosts'])-3} more hosts")
        elif phase == "port_scan":
            print(f"\n  [PHASE 2: PORT SCAN] hop={e['hop']} target={e['target_ip_sim']}")
            for p in e["open_ports"]:
                print(f"    {p['port']:<6} {p['service']:<8} {p['banner_sim']}")
        elif phase == "share_discovery":
            print(f"\n  [PHASE 3: SHARE DISCOVERY] target={e['target_ip_sim']}")
            for s in e["shares"]:
                print(f"    {s['path']:<35} {s['access']}")
        elif phase == "web_crawl":
            print(f"\n  [PHASE 4: WEB CRAWL] target={e['target_ip_sim']}")
            for p in e["paths_crawled"]:
                print(f"    {p['status_code_sim']}  {p['synthetic_url']}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no network calls — simulation artifact only")

@register_payload(name="lateral_webcrawler")
def main():
    session_id, subnet, hosts, events = simulate_lateral_movement(n_hops=2)
    print_simulation(session_id, subnet, hosts, events)

if __name__ == "__main__":
    main()
