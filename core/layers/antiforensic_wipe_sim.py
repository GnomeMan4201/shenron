#!/usr/bin/env python3
"""
core/layers/antiforensic_wipe_sim.py

SHENRON: Anti-forensics scorched-earth cleanup.

PURPOSE: Emit defender-observable telemetry for anti-forensics scorched-earth cleanup patterns.
PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure.
TACTIC: defense-evasion
MITRE: T1070, T1485, T1070.001, T1070.003

DETECTION NOTES:
  - Mass file deletion across multiple directories in single time window
  - Log directory wipe by non-log-rotation process
  - Shell history file truncated or deleted
  - Temp directory bulk deletion outside scheduled cleanup
  - Artifact staging directory removed after short existence
  - Security event log cleared

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


MITRE_TECHNIQUES = ['T1070', 'T1485', 'T1070.001', 'T1070.003']

DETECTION_OPPORTUNITIES_CATALOG = [
    "mass_file_deletion_multiple_dirs_single_window",
    "log_dir_wipe_non_rotation_process_sim",
    "shell_history_truncated_deleted_sim",
    "bash_history_zsh_history_removed_sim",
    "temp_dir_bulk_deletion_outside_schedule_sim",
    "staging_dir_removed_short_existence_sim",
    "security_event_log_cleared_sim",
    "windows_event_log_1102_pattern_sim",
]


def simulate_antiforensic_wipe_sim(seed: int = None) -> tuple:
    """Simulate anti-forensics scorched-earth cleanup campaign. Returns (session_id, events)."""
    if seed is not None:
        random.seed(seed)

    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: mass_delete_multi_dir_sim
    ev_0 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "antiforensic_wipe_sim",
        "phase":                   "ASSESS",
        "mitre_techniques":        ['T1070', 'T1485'],
        "behavior_class":          "mass_delete_multi_dir_sim",
        "signal":                  "mass_delete_multi_dir_sim",
        "detection_opportunities": ['mass_file_deletion_multiple_dirs_single_window', 'log_dir_wipe_non_rotation_process_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/antiforensic_wipe_sim v0.4.2",
        "note":                    "SYNTHETIC RECORD — mass_delete_multi_dir_sim telemetry shape only",
    }
    events.append(ev_0)

    # Phase 2: shell_history_wipe_sim
    ev_1 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "antiforensic_wipe_sim",
        "phase":                   "WIPE",
        "mitre_techniques":        ['T1070.003'],
        "behavior_class":          "shell_history_wipe_sim",
        "signal":                  "shell_history_wipe_sim",
        "detection_opportunities": ['shell_history_truncated_deleted_sim', 'bash_history_zsh_history_removed_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/antiforensic_wipe_sim v0.4.2",
        "note":                    "SYNTHETIC RECORD — shell_history_wipe_sim telemetry shape only",
    }
    events.append(ev_1)

    # Phase 3: temp_bulk_delete_sim
    ev_2 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "antiforensic_wipe_sim",
        "phase":                   "VERIFY",
        "mitre_techniques":        ['T1070'],
        "behavior_class":          "temp_bulk_delete_sim",
        "signal":                  "temp_bulk_delete_sim",
        "detection_opportunities": ['temp_dir_bulk_deletion_outside_schedule_sim', 'staging_dir_removed_short_existence_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/antiforensic_wipe_sim v0.4.2",
        "note":                    "SYNTHETIC RECORD — temp_bulk_delete_sim telemetry shape only",
    }
    events.append(ev_2)

    # Phase 4: event_log_clear_sim
    ev_3 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "antiforensic_wipe_sim",
        "phase":                   "ASSESS",
        "mitre_techniques":        ['T1070.001'],
        "behavior_class":          "event_log_clear_sim",
        "signal":                  "event_log_clear_sim",
        "detection_opportunities": ['security_event_log_cleared_sim', 'windows_event_log_1102_pattern_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/antiforensic_wipe_sim v0.4.2",
        "note":                    "SYNTHETIC RECORD — event_log_clear_sim telemetry shape only",
    }
    events.append(ev_3)

    # Write to artifact log
    with open(_get_artifact_log(), "a") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    return session_id, events


@register_payload(name="antiforensic_wipe_sim")
def main():
    session_id, events = simulate_antiforensic_wipe_sim()

    all_techs = set()
    all_opps = set()
    for ev in events:
        all_techs.update(ev.get("mitre_techniques", []))
        all_opps.update(ev.get("detection_opportunities", []))

    print(f"\n  [SIMULATION]  antiforensic_wipe_sim")
    print(f"  [SESSION]     {session_id}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       {sorted(all_techs)}")
    print(f"  [DETECTIONS]  {len(all_opps)}")
    print(f"  [EXECUTABLE]  FALSE — telemetry shape only")
    print(f"  [LOGGED]      {_get_artifact_log()}")
    for ev in events:
        print(f"  [ASSESS] {ev['behavior_class']}")
    print()
    print(f"  [SAFE]  no subprocess, no network, no filesystem writes")

    return session_id, events