#!/usr/bin/env python3
# parasitic_mesh_crawler.py - SHENRON Layer 5: LAN/Mesh Infection & Spread

import os
import subprocess
import socket
import fcntl
import struct
from datetime import datetime

LOG_PATH = os.path.expanduser("~/SHENRON/logs/mesh_spread.log")
PAYLOAD_DROP_DIR = "/sdcard/SHENRON_DROP/"
os.makedirs(PAYLOAD_DROP_DIR, exist_ok=True)

def get_iface_ip():
    try:
        result = subprocess.check_output("ip route get 8.8.8.8 | awk '{print $7}'", shell=True).decode().strip()
        return result
    except Exception:
        return "192.168.0.100"  # fallback

def generate_ips(ip_base):
    for i in range(1, 255):
        yield f"{ip_base}.{i}"

def log_event(entry):
    with open(LOG_PATH, "a") as f:
        f.write(f"[{datetime.now()}] {entry}\n")

def check_host(ip):
    try:
        output = subprocess.check_output(["ping", "-c", "1", "-W", "1", ip], stderr=subprocess.DEVNULL).decode()
        return "1 received" in output or "bytes from" in output
    except:
        return False

def port_open(ip, port):
    try:
        s = socket.socket()
        s.settimeout(0.5)
        s.connect((ip, port))
        s.close()
        return True
    except:
        return False

def attempt_spread(ip):
    log_event(f"[+] Host up: {ip}")
    methods = []
    if port_open(ip, 5555):
        methods.append("ADB")
    if port_open(ip, 22):
        methods.append("SSH")
    if port_open(ip, 80):
        methods.append("HTTP")

    if methods:
        log_event(f"    ‚Ü≥ Infectable via: {methods}")
        # Example drop
        drop_path = f"{PAYLOAD_DROP_DIR}/SHENRON_seed_{ip.replace('.', '_')}.txt"
        with open(drop_path, "w") as f:
            f.write(f"SHENRON seed deployed to {ip}\n")
        log_event(f"    ‚Ü≥ Dropped seed: {drop_path}")
    else:
        log_event(f"    ‚Ü≥ No open vector")

def main():
    local_ip = get_iface_ip()
    base_ip = ".".join(local_ip.split(".")[:3])
    print(f"[*] Crawling local net: {base_ip}.x")
    for ip in generate_ips(base_ip):
        if ip == local_ip:
            continue
        if check_host(ip):
            attempt_spread(ip)

    print("[‚úì] Mesh propagation attempt complete.")
    log_event("=== Mesh scan finished ===\n")

if __name__ == "__main__":
    main()

rU˙ø3DfÓ\àlMè‘S°EÉπ∞u»ì™£#÷`k#MORPHED

Ï— :ùe¸:3πnà¬@F˚πF#MORPHED

®
©±≤–›¿~W*|¯˜#MORPHED
