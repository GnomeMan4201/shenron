#!/usr/bin/env python3
# SHENRON: Mutation History — operational logging infrastructure
# ROLE: Core audit log module — records every layer load and execution event
# MECHANISM: Appends structured JSON entries to ~/SHENRON/logs/mutation_history.json
# NOTE: This module IS the mutation audit trail. It is not a simulator.
#       It is called by layer_loader.py on every load and by payload_registry.run() on execution.
#       Do not convert to a stub — it is active operational infrastructure.
#       Similar role to polymorph_chain_stats (dashboard) and dark_signature_morpher (mutation engine).
from core.engine.payload_registry import register_payload
import os
import json
from datetime import datetime, timezone

LOG_FILE = os.path.expanduser("~/SHENRON/logs/mutation_history.jsonl")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

def log_mutation(payload_name, mutation_type, stealth_score, notes=""):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": payload_name,
        "mutation": mutation_type,
        "stealth_score": stealth_score,
        "notes": notes
    }

    try:
        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps(entry) + "\n")
        print(f"[+] Mutation logged for: {payload_name}")
    except Exception as e:
        print(f"[!] Failed to write mutation log: {e}")

def show_history():
    if not os.path.exists(LOG_FILE):
        print("[!] No mutation history found.")
        return
    with open(LOG_FILE, 'r') as f:
        lines = [l.strip() for l in f if l.strip()]
    data = [json.loads(l) for l in lines[-20:]]
    for entry in data:
        print(f"- {entry['timestamp']} | {entry['payload']} | {entry['mutation']} | Stealth: {entry['stealth_score']}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        show_history()
    elif len(sys.argv) >= 4:
        log_mutation(sys.argv[1], sys.argv[2], sys.argv[3], " ".join(sys.argv[4:]))
    else:
        print("[*] Usage:\n  mutation_history.py <payload> <mutation> <stealth> [notes]\n  mutation_history.py            (show history)")
