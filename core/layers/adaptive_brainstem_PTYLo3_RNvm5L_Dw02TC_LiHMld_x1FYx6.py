from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# adaptive_brainstem.py - SHENRON Layer 6: Context-Aware Neural Reflex Controller

import os
import subprocess
import time
from datetime import datetime

LOG_PATH = os.path.expanduser("~/SHENRON/logs/brainstem_decisions.log")
STATE_PATH = os.path.expanduser("~/.shenron_brain_state")

LAYER_PATHS = {
    "deadzone": "~/SHENRON/core/layers/deadzone_payload.py",
    "skinwalker": "~/SHENRON/core/layers/payload_skinwalker.py",
    "symbiote": "~/SHENRON/core/layers/symbiote_payload.py",
    "vampire": "~/SHENRON/core/layers/manifest_vampire.py",
    "crawler": "~/SHENRON/core/layers/parasitic_mesh_crawler.py",
    "replicator": "~/SHENRON/core/layers/cognitive_replicator.py",
    "sandbox": "~/SHENRON/core/layers/self_sealing_nano_sandbox.py"
}

def log(msg):
    with open(LOG_PATH, "a") as f:
        f.write(f"[{datetime.now()}] {msg}\n")

def run_layer(name):
    path = os.path.expanduser(LAYER_PATHS.get(name, ""))
    if path and os.path.exists(path):
        log(f"β†’ Executing: {name}")
        subprocess.Popen(["python", path])
        time.sleep(1)  # Let it breathe
    else:
        log(f"Γ— Missing or unknown layer: {name}")

def load_state():
    if not os.path.exists(STATE_PATH):
        return {}
    with open(STATE_PATH) as f:
        lines = f.readlines()
    return dict(line.strip().split("=") for line in lines if "=" in line)

def save_state(state):
    with open(STATE_PATH, "w") as f:
        for k, v in state.items():
            f.write(f"{k}={v}\n")

@register_payload(name="adaptive_brainstem_PTYLo3_RNvm5L_Dw02TC_LiHMld_x1FYx6")
def main():
    state = load_state()
    round_count = int(state.get("round", 0))

    log(f"=== Decision Cycle {round_count} ===")

    if round_count == 0:
        run_layer("deadzone")
        run_layer("skinwalker")
        run_layer("crawler")
    elif round_count == 1:
        run_layer("vampire")
        run_layer("symbiote")
        run_layer("replicator")
    else:
        run_layer("sandbox")
        run_layer("crawler")  # re-crawl once stabilized

    round_count += 1
    state["round"] = str(round_count)
    save_state(state)

    log(f"β“ Cycle {round_count} complete.\n")

if __name__ == "__main__":
    main()

C¦r8ϋ‡«ΌÒπ§Δίdª!νΛ
(ψτ#MORPHED

Ά)ΘWψcΕ/g$}[,%© k#MORPHED

ΠI`$–{HMγΰ‹@ΥsϊeΊθΰ‹΅–ΰeB#MORPHED

n΄ΫΚ@Ε{;ζ¥Òήθ N.5 ΔEΠ^«gVΑ-‰‚(ϋJΪ5#MORPHED

§?Kn”>
οl6CήCqΓχªkA«"“ώ#MORPHED
