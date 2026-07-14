#!/usr/bin/env python3
"""
core/layers/payload_hash_shuffler.py

SHENRON: Payload hash randomization and polymorphic evasion.

PURPOSE: Emit defender-observable telemetry for payload hash randomization and polymorphic evasion patterns.
PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure.
TACTIC: defense-evasion
MITRE: T1027, T1027.001, T1001

DETECTION NOTES:
  - Multiple files with salted-hash names created in rapid succession
  - High-entropy filename pattern with no corresponding source file
  - Hash-renamed binaries in temp or hidden directories
  - File creation burst with identical size but different hashes
  - Staging directory containing only hash-named files

Design constraints:
- Standalone implementation. Original quantum_*/dragons_breath_*/shenron_* files preserved.
- No subprocess, no network, no real filesystem operations.
- All events carry simulation_only: true and full safety contract.
"""

import json
import uuid
import random
from datetime import datetime, timezone
from pathlib import Path
from core.engine.payload_registry import register_payload
from core.config import artifact_log_path as _artifact_log_path


def _get_artifact_log():
    p = _artifact_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _safe_fields() -> dict:
    return {
        "simulation_only": True,
        "executable": False,
        "payload_present": False,
        "portable_adversarial_procedure": False,
        "network_connection": False,
        "subprocess_spawned": False,
        "real_file_written": False,
        "shell_invoked": False,
    }


MITRE_TECHNIQUES = ['T1027', 'T1027.001', 'T1001']

DETECTION_OPPORTUNITIES_CATALOG = [
    "salted_hash_named_files_rapid_succession",
    "high_entropy_filename_no_source_sim",
    "hash_renamed_binaries_temp_hidden_dir",
    "staging_dir_hash_files_only_sim",
    "file_burst_same_size_different_hash",
    "polymorphic_payload_generation_sim",
    "hash_chain_rekey_evasion_sim",
    "payload_rekey_before_drop_sim",
]


def simulate_payload_hash_shuffler(seed: int = None) -> tuple:
    """Simulate payload hash randomization and polymorphic evasion campaign. Returns (session_id, events)."""
    if seed is not None:
        random.seed(seed)

    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: hash_rename_burst_sim
    ev_0 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "payload_hash_shuffler",
        "phase":                   "STAGE",
        "mitre_techniques":        ['T1027', 'T1027.001'],
        "behavior_class":          "hash_rename_burst_sim",
        "signal":                  "hash_rename_burst_sim",
        "detection_opportunities": ['salted_hash_named_files_rapid_succession', 'high_entropy_filename_no_source_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/payload_hash_shuffler v0.4.2",
        "note":                    "SYNTHETIC RECORD — hash_rename_burst_sim telemetry shape only",
    }
    events.append(ev_0)

    # Phase 2: temp_dir_hash_staging_sim
    ev_1 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "payload_hash_shuffler",
        "phase":                   "SHUFFLE",
        "mitre_techniques":        ['T1027'],
        "behavior_class":          "temp_dir_hash_staging_sim",
        "signal":                  "temp_dir_hash_staging_sim",
        "detection_opportunities": ['hash_renamed_binaries_temp_hidden_dir', 'staging_dir_hash_files_only_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/payload_hash_shuffler v0.4.2",
        "note":                    "SYNTHETIC RECORD — temp_dir_hash_staging_sim telemetry shape only",
    }
    events.append(ev_1)

    # Phase 3: identical_size_hash_diff_sim
    ev_2 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "payload_hash_shuffler",
        "phase":                   "DEPLOY",
        "mitre_techniques":        ['T1027.001', 'T1001'],
        "behavior_class":          "identical_size_hash_diff_sim",
        "signal":                  "identical_size_hash_diff_sim",
        "detection_opportunities": ['file_burst_same_size_different_hash', 'polymorphic_payload_generation_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/payload_hash_shuffler v0.4.2",
        "note":                    "SYNTHETIC RECORD — identical_size_hash_diff_sim telemetry shape only",
    }
    events.append(ev_2)

    # Phase 4: hash_chain_rekey_sim
    ev_3 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "payload_hash_shuffler",
        "phase":                   "STAGE",
        "mitre_techniques":        ['T1027'],
        "behavior_class":          "hash_chain_rekey_sim",
        "signal":                  "hash_chain_rekey_sim",
        "detection_opportunities": ['hash_chain_rekey_evasion_sim', 'payload_rekey_before_drop_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/payload_hash_shuffler v0.4.2",
        "note":                    "SYNTHETIC RECORD — hash_chain_rekey_sim telemetry shape only",
    }
    events.append(ev_3)

    # Write to artifact log
    with open(_get_artifact_log(), "a") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    return session_id, events


@register_payload(name="payload_hash_shuffler")
def main():
    session_id, events = simulate_payload_hash_shuffler()

    all_techs = set()
    all_opps = set()
    for ev in events:
        all_techs.update(ev.get("mitre_techniques", []))
        all_opps.update(ev.get("detection_opportunities", []))

    print(f"\n  [SIMULATION]  payload_hash_shuffler")
    print(f"  [SESSION]     {session_id}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       {sorted(all_techs)}")
    print(f"  [DETECTIONS]  {len(all_opps)}")
    print(f"  [EXECUTABLE]  FALSE — telemetry shape only")
    print(f"  [LOGGED]      {_get_artifact_log()}")
    for ev in events:
        print(f"  [STAGE] {ev['behavior_class']}")
    print()
    print(f"  [SAFE]  no subprocess, no network, no filesystem writes")

    return session_id, events