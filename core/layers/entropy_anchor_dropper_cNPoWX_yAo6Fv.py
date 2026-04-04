from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Entropy Anchor Dropper â€” Timing and Pattern Camouflage Engine

import os
import time
import random
import hashlib
from datetime import datetime

ANCHOR_LOG = os.path.expanduser("~/SHENRON/logs/entropy_anchor.log")

def generate_entropy():
    junk = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=512))
    digest = hashlib.sha256(junk.encode()).hexdigest()
    with open(ANCHOR_LOG, "a") as f:
        f.write(f"[~] Junk hash: {digest}\n")
    return digest

def create_noise_files():
    noise_dir = os.path.expanduser("~/SHENRON/.noise")
    os.makedirs(noise_dir, exist_ok=True)
    for i in range(3):
        fname = f"noise_{random.randint(1000,9999)}.tmp"
        fpath = os.path.join(noise_dir, fname)
        with open(fpath, "w") as f:
            f.write(generate_entropy())
        time.sleep(random.uniform(0.5, 2.0))
        os.remove(fpath)
        with open(ANCHOR_LOG, "a") as f:
            f.write(f"[+] Temp noise dropped and deleted: {fname}\n")
        print(f"[âœ“] Noise temp file created and removed: {fname}")

def delay_and_decoy():
    s = random.randint(5, 15)
    print(f"[~] Pausing for {s} seconds (entropy timing)")
    time.sleep(s)

def anchor_session():
    print("[*] Entropy Anchor engaged. Obfuscating runtime artifacts...")
    for _ in range(2):
        generate_entropy()
        delay_and_decoy()
        create_noise_files()
    print("[âœ“] Entropy anchor complete.")

if __name__ == "__main__":
    anchor_session()

¬˜¶¨¡(§Ì+’%>·J¢Í"Tðh#MORPHED

-¶¼Õ·F“¡ÓÈž»E¼±‹(eíö™Ã×žBÏ[öx2YA”ÿÃ’‹7A+Å#MORPHED
