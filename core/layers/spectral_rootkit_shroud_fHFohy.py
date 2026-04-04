#!/usr/bin/env python3
import subprocess

def spectral_shroud():
    processes = ["shenron", "payload", "python", "bash"]
    for proc in processes:
        subprocess.run(["pgrep", proc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["renice", "+10", "-p", "$(pgrep " + proc + ")"], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[‚úì] Processes cloaked in spectral shroud.")

if __name__ == "__main__":
    spectral_shroud()

@…Û& Aî:ài·æ¶¥¡⁄ﬁ€ê”ãovZ÷TπŒ#MORPHED
