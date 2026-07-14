#!/usr/bin/env python3
"""
core/layers/process_masquerade_sim.py

SHENRON: Process name masquerading and fake process.

PURPOSE: Emit defender-observable telemetry for process name masquerading and fake process patterns.
PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure.
TACTIC: defense-evasion
MITRE: T1036, T1036.005, T1027

DETECTION NOTES:
  - Process name matches system process but path is non-standard
  - argv[0] does not match actual binary path
  - System process name spawned from unexpected parent
  - Multiple processes with identical names and similar PIDs
  - Process with system name running from user home directory

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


MITRE_TECHNIQUES = ['T1036', 'T1036.005', 'T1027']

DETECTION_OPPORTUNITIES_CATALOG = [
    "process_name_matches_system_nonstandard_path",
    "argv0_mismatch_binary_path_sim",
    "system_process_unexpected_parent_sim",
    "process_reparenting_sim",
    "multiple_identical_names_similar_pids",
    "pid_range_outside_normal_sim",
    "system_process_running_from_user_home",
    "masquerade_path_anomaly_sim",
]


def simulate_process_masquerade_sim(seed: int = None) -> tuple:
    """Simulate process name masquerading and fake process campaign. Returns (session_id, events)."""
    if seed is not None:
        random.seed(seed)

    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: system_name_spoof_sim
    ev_0 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "process_masquerade_sim",
        "phase":                   "EXECUTE",
        "mitre_techniques":        ['T1036', 'T1036.005'],
        "behavior_class":          "system_name_spoof_sim",
        "signal":                  "system_name_spoof_sim",
        "detection_opportunities": ['process_name_matches_system_nonstandard_path', 'argv0_mismatch_binary_path_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/process_masquerade_sim v0.4.2",
        "note":                    "SYNTHETIC RECORD — system_name_spoof_sim telemetry shape only",
    }
    events.append(ev_0)

    # Phase 2: parent_process_spoof_sim
    ev_1 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "process_masquerade_sim",
        "phase":                   "MASQUERADE",
        "mitre_techniques":        ['T1036'],
        "behavior_class":          "parent_process_spoof_sim",
        "signal":                  "parent_process_spoof_sim",
        "detection_opportunities": ['system_process_unexpected_parent_sim', 'process_reparenting_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/process_masquerade_sim v0.4.2",
        "note":                    "SYNTHETIC RECORD — parent_process_spoof_sim telemetry shape only",
    }
    events.append(ev_1)

    # Phase 3: pid_range_anomaly_sim
    ev_2 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "process_masquerade_sim",
        "phase":                   "PERSIST",
        "mitre_techniques":        ['T1036', 'T1027'],
        "behavior_class":          "pid_range_anomaly_sim",
        "signal":                  "pid_range_anomaly_sim",
        "detection_opportunities": ['multiple_identical_names_similar_pids', 'pid_range_outside_normal_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/process_masquerade_sim v0.4.2",
        "note":                    "SYNTHETIC RECORD — pid_range_anomaly_sim telemetry shape only",
    }
    events.append(ev_2)

    # Phase 4: homedir_system_name_sim
    ev_3 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "process_masquerade_sim",
        "phase":                   "EXECUTE",
        "mitre_techniques":        ['T1036.005'],
        "behavior_class":          "homedir_system_name_sim",
        "signal":                  "homedir_system_name_sim",
        "detection_opportunities": ['system_process_running_from_user_home', 'masquerade_path_anomaly_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/process_masquerade_sim v0.4.2",
        "note":                    "SYNTHETIC RECORD — homedir_system_name_sim telemetry shape only",
    }
    events.append(ev_3)

    # Write to artifact log
    with open(_get_artifact_log(), "a") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    return session_id, events


@register_payload(name="process_masquerade_sim")
def main():
    session_id, events = simulate_process_masquerade_sim()

    all_techs = set()
    all_opps = set()
    for ev in events:
        all_techs.update(ev.get("mitre_techniques", []))
        all_opps.update(ev.get("detection_opportunities", []))

    print(f"\n  [SIMULATION]  process_masquerade_sim")
    print(f"  [SESSION]     {session_id}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       {sorted(all_techs)}")
    print(f"  [DETECTIONS]  {len(all_opps)}")
    print(f"  [EXECUTABLE]  FALSE — telemetry shape only")
    print(f"  [LOGGED]      {_get_artifact_log()}")
    for ev in events:
        print(f"  [EXECUTE] {ev['behavior_class']}")
    print()
    print(f"  [SAFE]  no subprocess, no network, no filesystem writes")

    return session_id, events