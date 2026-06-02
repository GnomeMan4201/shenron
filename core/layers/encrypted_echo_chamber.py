from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Encrypted Echo Chamber — synthetic secure comms channel simulator
# PURPOSE: Emit defender-observable telemetry for encrypted internal C2 channel patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1573 (Encrypted Channel), T1132 (Data Encoding)
# NO REAL ENCRYPTION — all keys, ciphertext, and channel state are synthetic strings
# NO FILE WRITES outside artifact log — no real key files, no real message files

import os
import uuid
import json
import random
import string
from datetime import datetime, timezone
from pathlib import Path

from core.config import artifact_log_path as _artifact_log_path

def _get_artifact_log():
    p = _artifact_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

# ── Synthetic data pools ──────────────────────────────────────────────────────
CHANNEL_TYPES = ["fernet_sim", "aes256_gcm_sim", "chacha20_sim", "xor_layered_sim"]

FAKE_CHANNEL_TARGETS = [
    "internal_relay_node_sim",
    "mesh_peer_alpha_sim",
    "c2_proxy_endpoint_sim",
    "dead_drop_listener_sim",
]

FAKE_MESSAGE_TEMPLATES = [
    "All layers operational and synchronized.",
    "Beacon interval adjusted to {interval}s.",
    "Lateral node {node} confirmed reachable.",
    "Payload staging complete at zone {zone}.",
    "Awaiting exfil window — {window}s delay.",
]

def _fake_key_sim(length=32):
    """Synthetic key-shaped string — not a real cryptographic key."""
    return ''.join(random.choices(string.ascii_letters + string.digits + '+/=', k=length))

def _fake_ciphertext_sim(length=64):
    """Synthetic ciphertext-shaped string — not real encrypted data."""
    return ''.join(random.choices(string.ascii_letters + string.digits + '+/=', k=length))

def _fake_message():
    template = random.choice(FAKE_MESSAGE_TEMPLATES)
    return template.format(
        interval=random.randint(30, 300),
        node=f"192.0.2.{random.randint(1,254)}",
        zone=random.randint(1, 9),
        window=random.randint(60, 600),
    )

def simulate_echo_chamber(n_messages=3):
    session_id = str(uuid.uuid4())
    channel_type = random.choice(CHANNEL_TYPES)
    target = random.choice(FAKE_CHANNEL_TARGETS)
    events = []

    # Phase 1: Key establishment simulation
    key_event = {
        "artifact_id":           str(uuid.uuid4()),
        "session_id":            session_id,
        "timestamp":             datetime.now(timezone.utc).isoformat(),
        "layer":                 "encrypted_echo_chamber",
        "phase":                 "key_establishment_sim",
        "mitre_techniques":      ["T1573", "T1132"],
        "behavior_class":        "symmetric_key_gen_sim",
        "channel_type_sim":      channel_type,
        "key_path_sim":          "~/SHENRON/configs/echo_chamber.key_sim",
        "key_material_sim":      _fake_key_sim(44),
        "detection_opportunities": [
            "key_file_written_to_config_path_non_crypto_process",
            "symmetric_key_gen_outside_tls_handshake",
        ],
        "simulation_only":       True,
        "executable":            False,
        "no_payload_present":    True,
        "files_written":         False,
    }
    events.append(key_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(key_event) + "\n")

    # Phase 2: Message encryption and channel send simulation
    for i in range(n_messages):
        plaintext_sim = _fake_message()
        msg_event = {
            "artifact_id":           str(uuid.uuid4()),
            "session_id":            session_id,
            "timestamp":             datetime.now(timezone.utc).isoformat(),
            "layer":                 "encrypted_echo_chamber",
            "phase":                 "channel_send_sim",
            "mitre_techniques":      ["T1573", "T1132"],
            "behavior_class":        "encrypted_channel_message_sim",
            "channel_type_sim":      channel_type,
            "target_sim":            target,
            "message_length_sim":    len(plaintext_sim),
            "ciphertext_sim":        _fake_ciphertext_sim(random.randint(48, 88)),
            "message_path_sim":      "~/SHENRON/data/echo_message.enc_sim",
            "detection_opportunities": [
                "encrypted_message_written_to_nonstandard_path",
                "repeated_fixed_length_ciphertext_single_process",
                "internal_channel_traffic_non_network_daemon",
            ],
            "simulation_only":       True,
            "executable":            False,
            "no_payload_present":    True,
            "files_written":         False,
            "network_calls_made":    False,
        }
        events.append(msg_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(msg_event) + "\n")

    return session_id, channel_type, target, events

def print_simulation(session_id, channel_type, target, events):
    print(f"\n  [SIMULATION]  encrypted_echo_chamber")
    print(f"  [SESSION]     {session_id}")
    print(f"  [CHANNEL_SIM] {channel_type}")
    print(f"  [TARGET_SIM]  {target}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1573, T1132")
    print(f"  [FILES]       NOT WRITTEN — synthetic only")
    print(f"  [CRYPTO]      NOT USED — key and ciphertext are inert strings")
    print()
    for e in events:
        if e["phase"] == "key_establishment_sim":
            print(f"  [PHASE 1: KEY ESTABLISHMENT]")
            print(f"    channel_sim   : {e['channel_type_sim']}")
            print(f"    key_path_sim  : {e['key_path_sim']}")
            print(f"    key_sim       : {e['key_material_sim'][:24]}...")
            print(f"    detection     : {e['detection_opportunities'][0]}")
        else:
            print(f"\n  [CHANNEL SEND]")
            print(f"    target_sim    : {e['target_sim']}")
            print(f"    msg_len_sim   : {e['message_length_sim']} bytes")
            print(f"    cipher_sim    : {e['ciphertext_sim'][:24]}...")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no real crypto, no file writes — simulation artifact only")

@register_payload(name="encrypted_echo_chamber")
def main():
    session_id, channel_type, target, events = simulate_echo_chamber(n_messages=3)
    print_simulation(session_id, channel_type, target, events)

if __name__ == "__main__":
    main()
