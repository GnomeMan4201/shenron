#!/usr/bin/env python3
# SHENRON: LLM Shroud Writer — synthetic obfuscation pattern simulator
# PURPOSE: Generate inert adversarial-shaped artifacts for detector and policy testing
# PRINCIPLE: Represent adversarial shape without adversarial capability
# STATUS: defensive simulation only — no executable content produced

import os
import re
import uuid
import json
import random
import string
from datetime import datetime
from pathlib import Path
from core.config import artifact_log_path as _artifact_log_path

def _get_artifact_log():
    p = _artifact_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p



# ── Output paths ──────────────────────────────────────────────────────────────
ARTIFACT_LOG = _get_artifact_log()

# ── Input validation ──────────────────────────────────────────────────────────
BLOCKLIST = [
    (r'[;&|`$(){}]',                                          "shell metacharacters"),
    (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',             "IP address"),
    (r'https?://',                                             "URL"),
    (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',     "email address"),
    (r'(?i)(password|passwd|secret|token|apikey|api_key|credential)', "credential pattern"),
    (r'(?i)(\bexec|eval|subprocess|os\.system|popen|shell)', "execution pattern"),
    (r'(?i)\b(exploit|shellcode|payload|reverse.shell|bind.shell)\b', "exploit pattern"),
]

def validate_input(text: str) -> tuple[bool, str]:
    """Reject any input that contains real adversarial material."""
    for pattern, label in BLOCKLIST:
        if re.search(pattern, text):
            return False, f"rejected: input contains {label}"
    if len(text) > 512:
        return False, "rejected: input exceeds safe length limit (512 chars)"
    return True, "ok"

# ── Synthetic pattern generators ──────────────────────────────────────────────
def _fake_b64_chunk(length: int = 32) -> str:
    """Generate a string that looks like base64 but encodes nothing real."""
    chars = string.ascii_letters + string.digits + "+/"
    raw = ''.join(random.choices(chars, k=length))
    pad = (4 - len(raw) % 4) % 4
    return raw + ("=" * pad)

def _fake_hex_chunk(length: int = 16) -> str:
    """Generate a hex-shaped string with no real content."""
    return ''.join(random.choices('0123456789abcdef', k=length * 2))

def _fake_entropy_score() -> float:
    return round(random.uniform(0.71, 0.97), 3)

def _fake_layer_label() -> str:
    prefixes = ["wrap", "shroud", "veil", "mask", "fold", "layer"]
    encodings = ["b64", "hex", "rot", "xor-sim", "lzw-sim", "pack-sim"]
    return f"{random.choice(prefixes)}_{random.choice(encodings)}"

SYNTHETIC_COMMENTS = [
    "# obfuscation layer — pattern only, no function",
    "# synthetic wrapper — inert simulation artifact",
    "# shape: LLM-style obfuscation mimicry",
    "# detector test artifact — safe to analyze",
    "# no executable content below this line",
]

def generate_shroud_artifact(label: str = "test", depth: int = 3) -> dict:
    """
    Generate a synthetic multi-layer obfuscation artifact.
    All content is structurally shaped but semantically inert.
    """
    artifact_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    layers = []

    for i in range(1, depth + 1):
        layer_label = _fake_layer_label()
        if i % 2 == 0:
            content = _fake_hex_chunk(random.randint(12, 24))
        else:
            content = _fake_b64_chunk(random.randint(24, 48))

        layers.append({
            "layer": i,
            "label": layer_label,
            "content": content,
            "entropy_sim": _fake_entropy_score(),
            "comment": random.choice(SYNTHETIC_COMMENTS),
        })

    artifact = {
        "artifact_id": artifact_id,
        "timestamp": timestamp,
        "label": label,
        "depth": depth,
        "layers": layers,
        "overall_entropy_sim": _fake_entropy_score(),
        "safe": True,
        "simulation_only": True,
        "executable": False,
    }
    return artifact

def emit_artifact(artifact: dict) -> None:
    """Write artifact to JSONL log for detector consumption."""
    with open(ARTIFACT_LOG, "a") as f:
        f.write(json.dumps(artifact) + "\n")

def print_artifact(artifact: dict) -> None:
    """Human-readable simulation output."""
    print(f"\n  [SIMULATION]  llm_shroud_writer")
    print(f"  [ARTIFACT_ID] {artifact['artifact_id']}")
    print(f"  [TIMESTAMP]   {artifact['timestamp']}")
    print(f"  [LABEL]       {artifact['label']}")
    print(f"  [DEPTH]       {artifact['depth']} layers")
    print(f"  [ENTROPY_SIM] {artifact['overall_entropy_sim']}")
    print()
    for layer in artifact["layers"]:
        print(f"  [LAYER {layer['layer']}]    {layer['label']}")
        print(f"  [SYNTHETIC]   {layer['content']}")
        print(f"  [ENTROPY_SIM] {layer['entropy_sim']}")
        print(f"  {layer['comment']}")
        print()
    print(f"  [SAFE]        no executable content — simulation artifact only")
    print(f"  [LOGGED]      {ARTIFACT_LOG}")

# ── Public API ────────────────────────────────────────────────────────────────
def simulate(label: str = "test", depth: int = 3) -> dict | None:
    """
    Main simulation entry point.
    Validates input, generates artifact, logs it, returns it.
    """
    ok, reason = validate_input(label)
    if not ok:
        print(f"  [BLOCKED] {reason}")
        return None

    depth = max(1, min(depth, 6))  # clamp depth 1-6
    artifact = generate_shroud_artifact(label=label, depth=depth)
    emit_artifact(artifact)
    print_artifact(artifact)
    return artifact

def run_detector_test(n: int = 5) -> None:
    """
    Generate a batch of synthetic artifacts for detector pipeline testing.
    """
    labels = [
        "obfuscation_test",
        "layer_depth_test",
        "entropy_variance_test",
        "pattern_shape_test",
        "detector_baseline",
    ]
    print(f"\n  [BATCH TEST] Generating {n} synthetic artifacts for detector testing\n")
    for i in range(n):
        label = labels[i % len(labels)]
        depth = random.randint(2, 5)
        simulate(label=label, depth=depth)

def main():
    print("\n  [*] llm_shroud_writer: synthetic obfuscation simulator")
    print("  [*] PURPOSE: detector and policy testing only")
    print("  [*] No executable content will be produced\n")
    simulate(label="baseline_test", depth=3)

if __name__ == "__main__":
    main()