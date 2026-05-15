#!/usr/bin/env python3
# SHENRON: Mutation History — tracks layer load events, mutation types and stealth scores
from core.engine.payload_registry import register_payload
import os
import json
from datetime import datetime

LOG_FILE = os.path.expanduser("~/SHENRON/logs/mutation_history.json")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

def log_mutation(payload_name, mutation_type, stealth_score, notes=""):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "payload": payload_name,
        "mutation": mutation_type,
        "stealth_score": stealth_score,
        "notes": notes
    }

    try:
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'w') as f:
                json.dump([entry], f, indent=2)
        else:
            with open(LOG_FILE, 'r') as f:
                data = json.load(f)
            data.append(entry)
            with open(LOG_FILE, 'w') as f:
                json.dump(data, f, indent=2)
        print(f"[+] Mutation logged for: {payload_name}")
    except Exception as e:
        print(f"[!] Failed to write mutation log: {e}")

def show_history():
    if not os.path.exists(LOG_FILE):
        print("[!] No mutation history found.")
        return
    with open(LOG_FILE, 'r') as f:
        data = json.load(f)
        for entry in data[-20:]:
            print(f"- {entry['timestamp']} | {entry['payload']} | {entry['mutation']} | Stealth: {entry['stealth_score']}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        show_history()
    elif len(sys.argv) >= 4:
        log_mutation(sys.argv[1], sys.argv[2], sys.argv[3], " ".join(sys.argv[4:]))
    else:
        print("[*] Usage:\n  mutation_history.py <payload> <mutation> <stealth> [notes]\n  mutation_history.py            (show history)")
