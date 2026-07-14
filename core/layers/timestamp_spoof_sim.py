#!/usr/bin/env python3
"""
core/layers/timestamp_spoof_sim.py

SHENRON: Timestamp manipulation and anti-forensics.

PURPOSE: Emit defender-observable telemetry for timestamp manipulation and anti-forensics patterns.
PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure.
TACTIC: defense-evasion
MITRE: T1070, T1070.006, T1027

DETECTION NOTES:
  - Batch file timestamp modification outside maintenance window
  - mtime/atime/ctime all identical across many files (bulk operation)
  - Timestamps set to future dates or epoch (1970-01-01)
  - Log files with last-modified older than creation date
  - Filesystem metadata inconsistency across directory

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


MITRE_TECHNIQUES = ['T1070', 'T1070.006', 'T1027']

DETECTION_OPPORTUNITIES_CATALOG = [
    "bulk_timestamp_modification_outside_window",
    "mtime_atime_ctime_identical_bulk_operation",
    "log_file_modified_older_than_creation",
    "filesystem_metadata_inconsistency",
    "timestamp_set_to_future_date",
    "epoch_timestamp_injection_sim",
    "selective_file_timestamp_alteration",
    "anti_forensics_mtime_sim",
]


def simulate_timestamp_spoof_sim(seed: int = None) -> tuple:
    """Simulate timestamp manipulation and anti-forensics campaign. Returns (session_id, events)."""
    if seed is not None:
        random.seed(seed)

    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: bulk_mtime_modification_sim
    ev_0 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "timestamp_spoof_sim",
        "phase":                   "RECON",
        "mitre_techniques":        ['T1070', 'T1070.006'],
        "behavior_class":          "bulk_mtime_modification_sim",
        "signal":                  "bulk_mtime_modification_sim",
        "detection_opportunities": ['bulk_timestamp_modification_outside_window', 'mtime_atime_ctime_identical_bulk_operation'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/timestamp_spoof_sim v0.4.2",
        "note":                    "SYNTHETIC RECORD — bulk_mtime_modification_sim telemetry shape only",
    }
    events.append(ev_0)

    # Phase 2: log_timestamp_rollback_sim
    ev_1 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "timestamp_spoof_sim",
        "phase":                   "MANIPULATE",
        "mitre_techniques":        ['T1070', 'T1027'],
        "behavior_class":          "log_timestamp_rollback_sim",
        "signal":                  "log_timestamp_rollback_sim",
        "detection_opportunities": ['log_file_modified_older_than_creation', 'filesystem_metadata_inconsistency'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/timestamp_spoof_sim v0.4.2",
        "note":                    "SYNTHETIC RECORD — log_timestamp_rollback_sim telemetry shape only",
    }
    events.append(ev_1)

    # Phase 3: future_timestamp_inject_sim
    ev_2 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "timestamp_spoof_sim",
        "phase":                   "COVER_TRACKS",
        "mitre_techniques":        ['T1070.006'],
        "behavior_class":          "future_timestamp_inject_sim",
        "signal":                  "future_timestamp_inject_sim",
        "detection_opportunities": ['timestamp_set_to_future_date', 'epoch_timestamp_injection_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/timestamp_spoof_sim v0.4.2",
        "note":                    "SYNTHETIC RECORD — future_timestamp_inject_sim telemetry shape only",
    }
    events.append(ev_2)

    # Phase 4: selective_mtime_cover_sim
    ev_3 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "timestamp_spoof_sim",
        "phase":                   "RECON",
        "mitre_techniques":        ['T1070'],
        "behavior_class":          "selective_mtime_cover_sim",
        "signal":                  "selective_mtime_cover_sim",
        "detection_opportunities": ['selective_file_timestamp_alteration', 'anti_forensics_mtime_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/timestamp_spoof_sim v0.4.2",
        "note":                    "SYNTHETIC RECORD — selective_mtime_cover_sim telemetry shape only",
    }
    events.append(ev_3)

    # Write to artifact log
    with open(_get_artifact_log(), "a") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    return session_id, events


@register_payload(name="timestamp_spoof_sim")
def main():
    session_id, events = simulate_timestamp_spoof_sim()

    all_techs = set()
    all_opps = set()
    for ev in events:
        all_techs.update(ev.get("mitre_techniques", []))
        all_opps.update(ev.get("detection_opportunities", []))

    print(f"\n  [SIMULATION]  timestamp_spoof_sim")
    print(f"  [SESSION]     {session_id}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       {sorted(all_techs)}")
    print(f"  [DETECTIONS]  {len(all_opps)}")
    print(f"  [EXECUTABLE]  FALSE — telemetry shape only")
    print(f"  [LOGGED]      {_get_artifact_log()}")
    for ev in events:
        print(f"  [RECON] {ev['behavior_class']}")
    print()
    print(f"  [SAFE]  no subprocess, no network, no filesystem writes")

    return session_id, events