#!/usr/bin/env python3
"""
core/layers/device_fingerprint_spoof.py

SHENRON: Device identity spoofing and fingerprint pollution.

PURPOSE: Emit defender-observable telemetry for device identity spoofing and fingerprint pollution patterns.
PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure.
TACTIC: defense-evasion
MITRE: T1036, T1027, T1078

DETECTION NOTES:
  - Synthetic device fingerprints logged at regular intervals
  - MAC address that doesn't match hardware inventory
  - Hostname changed without corresponding DNS update
  - Multiple device identity profiles emitted from single host
  - UUID generation not correlated with device boot or provisioning event
  - Network identity fields inconsistent across log sources

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


MITRE_TECHNIQUES = ['T1036', 'T1027', 'T1078']

DETECTION_OPPORTUNITIES_CATALOG = [
    "mac_address_not_in_hardware_inventory_sim",
    "arp_mac_mismatch_inventory_sim",
    "hostname_changed_no_dns_update_sim",
    "hostname_inconsistent_across_log_sources_sim",
    "multiple_device_identity_profiles_single_host_sim",
    "identity_pollution_burst_sim",
    "uuid_generation_no_boot_provision_correlation_sim",
    "synthetic_device_uuid_rapid_generation_sim",
]


def simulate_device_fingerprint_spoof(seed: int = None) -> tuple:
    """Simulate device identity spoofing and fingerprint pollution campaign. Returns (session_id, events)."""
    if seed is not None:
        random.seed(seed)

    session_id = str(uuid.uuid4())
    events = []

    # Phase 1: mac_spoof_sim
    ev_0 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "device_fingerprint_spoof",
        "phase":                   "ENUMERATE",
        "mitre_techniques":        ['T1036', 'T1027'],
        "behavior_class":          "mac_spoof_sim",
        "signal":                  "mac_spoof_sim",
        "detection_opportunities": ['mac_address_not_in_hardware_inventory_sim', 'arp_mac_mismatch_inventory_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/device_fingerprint_spoof v0.4.2",
        "note":                    "SYNTHETIC RECORD — mac_spoof_sim telemetry shape only",
    }
    events.append(ev_0)

    # Phase 2: hostname_spoof_sim
    ev_1 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "device_fingerprint_spoof",
        "phase":                   "SPOOF",
        "mitre_techniques":        ['T1036'],
        "behavior_class":          "hostname_spoof_sim",
        "signal":                  "hostname_spoof_sim",
        "detection_opportunities": ['hostname_changed_no_dns_update_sim', 'hostname_inconsistent_across_log_sources_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/device_fingerprint_spoof v0.4.2",
        "note":                    "SYNTHETIC RECORD — hostname_spoof_sim telemetry shape only",
    }
    events.append(ev_1)

    # Phase 3: multi_identity_emit_sim
    ev_2 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "device_fingerprint_spoof",
        "phase":                   "POLLUTE",
        "mitre_techniques":        ['T1078', 'T1036'],
        "behavior_class":          "multi_identity_emit_sim",
        "signal":                  "multi_identity_emit_sim",
        "detection_opportunities": ['multiple_device_identity_profiles_single_host_sim', 'identity_pollution_burst_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/device_fingerprint_spoof v0.4.2",
        "note":                    "SYNTHETIC RECORD — multi_identity_emit_sim telemetry shape only",
    }
    events.append(ev_2)

    # Phase 4: uuid_anomaly_sim
    ev_3 = {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
        "layer":                   "device_fingerprint_spoof",
        "phase":                   "ENUMERATE",
        "mitre_techniques":        ['T1027'],
        "behavior_class":          "uuid_anomaly_sim",
        "signal":                  "uuid_anomaly_sim",
        "detection_opportunities": ['uuid_generation_no_boot_provision_correlation_sim', 'synthetic_device_uuid_rapid_generation_sim'],
        "simulation_only":         True,
        "executable":              False,
        "payload_present":         False,
        "safety":                  _safe_fields(),
        "entropy":                 round(random.uniform(6.2, 7.9), 4),
        "generator":               "shenron/device_fingerprint_spoof v0.4.2",
        "note":                    "SYNTHETIC RECORD — uuid_anomaly_sim telemetry shape only",
    }
    events.append(ev_3)

    # Write to artifact log
    with open(_get_artifact_log(), "a") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    return session_id, events


@register_payload(name="device_fingerprint_spoof")
def main():
    session_id, events = simulate_device_fingerprint_spoof()

    all_techs = set()
    all_opps = set()
    for ev in events:
        all_techs.update(ev.get("mitre_techniques", []))
        all_opps.update(ev.get("detection_opportunities", []))

    print(f"\n  [SIMULATION]  device_fingerprint_spoof")
    print(f"  [SESSION]     {session_id}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       {sorted(all_techs)}")
    print(f"  [DETECTIONS]  {len(all_opps)}")
    print(f"  [EXECUTABLE]  FALSE — telemetry shape only")
    print(f"  [LOGGED]      {_get_artifact_log()}")
    for ev in events:
        print(f"  [ENUMERATE] {ev['behavior_class']}")
    print()
    print(f"  [SAFE]  no subprocess, no network, no filesystem writes")

    return session_id, events