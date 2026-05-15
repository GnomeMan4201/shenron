from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON Layer: Dark Signature Morpher
# ROLE: Core mutation engine — generates all layer variants in core/layers/
# MECHANISM: Appends random entropy bytes + #MORPHED marker to each base layer,
#            saves with a random 6-char suffix, logs SHA256 of each output.
# NOTE: This module IS the variant generator. It has zero variants itself by design.
#       All 4354 variants across 50 canonical layers were produced by this module.
#       Run only in controlled lab context against intended target directory.

import os
import hashlib
import base64
import random
import string
from datetime import datetime

MORPH_LOG = os.path.expanduser("~/SHENRON/logs/signature_morphs.log")
TARGETS_DIR = os.path.expanduser("~/SHENRON/core/layers/")

def random_suffix(length=6):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def morph_file(filepath):
    try:
        with open(filepath, "rb") as f:
            content = f.read()

        # Add junk entropy
        junk = os.urandom(random.randint(10, 50))
        new_content = content + b"\n" + junk + b"#MORPHED\n"

        # Save as morphed file
        suffix = random_suffix()
        new_name = os.path.splitext(filepath)[0] + f"_{suffix}.py"
        with open(new_name, "wb") as f:
            f.write(new_content)

        sha256 = hashlib.sha256(new_content).hexdigest()
        with open(MORPH_LOG, "a") as log:
            log.write(f"[{datetime.now()}] Morphed: {filepath} -> {new_name} [SHA256={sha256}]\n")

        print(f"[+] Morphed: {filepath} -> {new_name}")
    except Exception as e:
        print(f"[!] Failed to morph {filepath}: {e}")

@register_payload(name="dark_signature_morpher")
def main():
    print("[*] Morphing all SHENRON payload fingerprints...")
    for file in os.listdir(TARGETS_DIR):
        if file.endswith(".py") and "morph" not in file:
            morph_file(os.path.join(TARGETS_DIR, file))
    print("[✓] All signatures morphed.")

if __name__ == "__main__":
    main()
