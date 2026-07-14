#!/usr/bin/env python3
"""
core/layers/entropy_injection_sim.py

SHENRON: Entropy injection and log noise generation.

PURPOSE: Emit defender-observable telemetry for entropy injection and log noise generation patterns.
PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure.
TACTIC: defense-evasion
MITRE: T1027, T1001, T1070

DETECTION NOTES:
  - Log files with artificially high entropy content from non-logging process
  - Burst writes to log files outside normal logging cadence
  - Synthetic entropy patterns that don't match real system entropy sources
  - Processes generating high-entropy output at regular intervals
  - Log entries with unusually high Shannon entropy in value fields

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


MITRE_TECHNIQUES = ['T1027', 'T1001', 'T1070']

DETECTION_OPPORTUNITIES_CATALOG = [
    "log_files_high_entropy_non_logging_process",
    "burst_write_log_outside_cadence_sim",
    "synthetic_entropy_mismatch_real_sources_sim",
    "entropy_pattern_does_not_match_system_sim",
    "high_entropy_output_regular_intervals_sim",
    "timing_fingerprint_entropy_burst_sim",
    "log_entry_high_shannon_entropy_value_fields",
    "field_level_entropy_anomaly_sim",
]


def simulate_entropy_injection_sim(seed: int = None) -> tuple:
    """Simulate entropy injection and log noise generation campaign. Returns (session_id, events)."""
    if seed is not None:
        random.seed(seed)

    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: high_entropy_log_inject_sim
    ev_0 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "entropy_injection_sim",
        "phase":                   "INJECT",
        "mitre_techniques":        ['T1027', 'T1001'],
        "behavior_class":          "high_entropy_log_inject_sim",
        "signal":                  "high_entropy_log_inject_sim",
        "detection_opportunities": ['log_files_high_entropy_non_logging_process', 'burst_write_log_outside_cadence_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/entropy_injection_sim v0.4.2",
        "note":                    "SYNTHETIC RECORD — high_entropy_log_inject_sim telemetry shape only",
    }
    events.append(ev_0)

    # Phase 2: entropy_pattern_spoof_sim
    ev_1 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "entropy_injection_sim",
        "phase":                   "SUSTAIN",
        "mitre_techniques":        ['T1027'],
        "behavior_class":          "entropy_pattern_spoof_sim",
        "signal":                  "entropy_pattern_spoof_sim",
        "detection_opportunities": ['synthetic_entropy_mismatch_real_sources_sim', 'entropy_pattern_does_not_match_system_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/entropy_injection_sim v0.4.2",
        "note":                    "SYNTHETIC RECORD — entropy_pattern_spoof_sim telemetry shape only",
    }
    events.append(ev_1)

    # Phase 3: timed_entropy_burst_sim
    ev_2 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "entropy_injection_sim",
        "phase":                   "COVER",
        "mitre_techniques":        ['T1001'],
        "behavior_class":          "timed_entropy_burst_sim",
        "signal":                  "timed_entropy_burst_sim",
        "detection_opportunities": ['high_entropy_output_regular_intervals_sim', 'timing_fingerprint_entropy_burst_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/entropy_injection_sim v0.4.2",
        "note":                    "SYNTHETIC RECORD — timed_entropy_burst_sim telemetry shape only",
    }
    events.append(ev_2)

    # Phase 4: shannon_entropy_anomaly_sim
    ev_3 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "entropy_injection_sim",
        "phase":                   "INJECT",
        "mitre_techniques":        ['T1027', 'T1070'],
        "behavior_class":          "shannon_entropy_anomaly_sim",
        "signal":                  "shannon_entropy_anomaly_sim",
        "detection_opportunities": ['log_entry_high_shannon_entropy_value_fields', 'field_level_entropy_anomaly_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/entropy_injection_sim v0.4.2",
        "note":                    "SYNTHETIC RECORD — shannon_entropy_anomaly_sim telemetry shape only",
    }
    events.append(ev_3)

    # Write to artifact log
    with open(_get_artifact_log(), "a") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    return session_id, events


@register_payload(name="entropy_injection_sim")
def main():
    session_id, events = simulate_entropy_injection_sim()

    all_techs = set()
    all_opps = set()
    for ev in events:
        all_techs.update(ev.get("mitre_techniques", []))
        all_opps.update(ev.get("detection_opportunities", []))

    print(f"\n  [SIMULATION]  entropy_injection_sim")
    print(f"  [SESSION]     {session_id}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       {sorted(all_techs)}")
    print(f"  [DETECTIONS]  {len(all_opps)}")
    print(f"  [EXECUTABLE]  FALSE — telemetry shape only")
    print(f"  [LOGGED]      {_get_artifact_log()}")
    for ev in events:
        print(f"  [INJECT] {ev['behavior_class']}")
    print()
    print(f"  [SAFE]  no subprocess, no network, no filesystem writes")

    return session_id, events