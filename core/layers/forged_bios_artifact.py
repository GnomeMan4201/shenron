from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Forged BIOS Artifact — firmware tamper telemetry simulator
# PURPOSE: Emit defender-observable telemetry for BIOS/UEFI tamper indicator patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1542 (Pre-OS Boot), T1036 (Masquerading)
# DETECTION NOTES:
#   - Blue teams should alert on: BIOS log entries indicating flash protection override
#   - UEFI shell disabled entries not correlated with admin action
#   - TPM recovery key rewrite events not matching provisioning workflow
#   - firmware_override.conf or BootGuard_debug.tmp in unexpected paths
#   - ACPI S3 fallback entries outside maintenance windows
#   - Tamper log files with anomalous timestamps vs actual firmware event logs

import os
import json
import uuid
import random
from datetime import datetime, timezone
from pathlib import Path

ARTIFACT_LOG = Path("/home/gnomeman4201/SHENRON/logs/simulation_artifacts.jsonl")

def _get_artifact_log():
    ARTIFACT_LOG.parent.mkdir(parents=True, exist_ok=True)
    return ARTIFACT_LOG

FAKE_BIOS_EVENTS_SIM = [
    {"event": "flash_protection_override_sim",     "severity": "critical", "desc": "Flash protection overridden via admin override key"},
    {"event": "bootloader_injection_stage1_sim",   "severity": "critical", "desc": "Bootloader injected: GRUB_MIRAGE patch stage 1"},
    {"event": "uefi_shell_disabled_post_sim",      "severity": "high",     "desc": "UEFI Shell disabled via POST trigger"},
    {"event": "acpi_s3_fallback_forced_sim",       "severity": "high",     "desc": "ACPI S3 fallback forced — tamper recovery activated"},
    {"event": "tpm_recovery_key_rewrite_sim",      "severity": "critical", "desc": "TPM recovery keys rewritten to null proxy path"},
]

FAKE_UEFI_ARTIFACTS_SIM = [
    {"filename": "firmware_override_sim.conf",    "type": "config",   "tamper_state": True},
    {"filename": "BootGuard_debug_sim.tmp",        "type": "debug_log","tamper_state": True},
    {"filename": "s3_shadow_bypass_sim.ini",       "type": "config",   "tamper_state": True},
    {"filename": "uefi_tamper_record_sim.log",     "type": "log",      "tamper_state": True},
]

DETECTION_OPPORTUNITIES = [
    "bios_log_flash_protection_override_not_correlated_admin_action",
    "uefi_shell_disabled_outside_provisioning_workflow",
    "tpm_recovery_key_rewrite_not_matching_provisioning",
    "firmware_override_conf_bootguard_tmp_unexpected_path",
    "acpi_s3_fallback_outside_maintenance_window",
    "tamper_log_timestamp_vs_actual_firmware_event_log_mismatch",
]

def simulate_bios_artifact():
    session_id = str(uuid.uuid4())
    events = []
    timestamp_sim = datetime.now(timezone.utc).isoformat()

    # Phase 1: BIOS log forgery simulation
    selected_bios_events = random.sample(FAKE_BIOS_EVENTS_SIM,
                                          random.randint(3, len(FAKE_BIOS_EVENTS_SIM)))
    bios_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "forged_bios_artifact",
        "phase": "bios_log_forge_sim",
        "mitre_techniques": ["T1542"],
        "behavior_class": "bios_tamper_log_write_sim",
        "target_log_sim": "~/SHENRON/logs/fake_bios_sim.log",
        "events_forged_sim": len(selected_bios_events),
        "bios_events_sim": [
            {
                "timestamp_sim": timestamp_sim,
                "event_sim": e["event"],
                "severity_sim": e["severity"],
                "desc_sim": e["desc"],
            }
            for e in selected_bios_events
        ],
        "detection_opportunities": [
            "bios_log_flash_protection_override_not_correlated_admin_action",
            "tpm_recovery_key_rewrite_not_matching_provisioning",
            "tamper_log_timestamp_vs_actual_firmware_event_log_mismatch",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "files_created": False,
    }
    events.append(bios_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(bios_event) + "\n")

    # Phase 2: UEFI trace artifact simulation
    selected_uefi = random.sample(FAKE_UEFI_ARTIFACTS_SIM,
                                   random.randint(2, len(FAKE_UEFI_ARTIFACTS_SIM)))
    for artifact in selected_uefi:
        uefi_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "forged_bios_artifact",
            "phase": "uefi_trace_plant_sim",
            "mitre_techniques": ["T1036"],
            "behavior_class": "uefi_artifact_plant_sim",
            "artifact_filename_sim": artifact["filename"],
            "artifact_type_sim": artifact["type"],
            "target_dir_sim": "~/SHENRON/core/uefi_logs_sim/",
            "full_path_sim": f"~/SHENRON/core/uefi_logs_sim/{artifact['filename']}",
            "tamper_state_sim": artifact["tamper_state"],
            "content_fields_sim": ["timestamp_sim", "tamper_state", "status_anomalous"],
            "detection_opportunities": [
                "firmware_override_conf_bootguard_tmp_unexpected_path",
                "uefi_shell_disabled_outside_provisioning_workflow",
                "acpi_s3_fallback_outside_maintenance_window",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "files_created": False,
        }
        events.append(uefi_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(uefi_event) + "\n")

    return session_id, selected_bios_events, selected_uefi, events

def print_simulation(session_id, bios_events, uefi_artifacts, events):
    print(f"\n  [SIMULATION]  forged_bios_artifact")
    print(f"  [SESSION]     {session_id}")
    print(f"  [BIOS_SIM]    {len(bios_events)} events forged")
    print(f"  [UEFI_SIM]    {len(uefi_artifacts)} artifacts planted")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1542, T1036")
    print(f"  [FILES]       NOT WRITTEN — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no file writes, no firmware interaction")
    print()
    for e in events:
        if e["phase"] == "bios_log_forge_sim":
            print(f"  [PHASE 1: BIOS LOG FORGE SIM]")
            print(f"    target_sim    : {e['target_log_sim']}")
            print(f"    events_sim    : {e['events_forged_sim']}")
            for be in e["bios_events_sim"]:
                print(f"    [{be['severity_sim'].upper()}] {be['desc_sim']}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
        elif e["phase"] == "uefi_trace_plant_sim":
            print(f"\n  [UEFI ARTIFACT] {e['artifact_filename_sim']}")
            print(f"    type_sim      : {e['artifact_type_sim']}")
            print(f"    path_sim      : {e['full_path_sim']}")
            print(f"    tamper_sim    : {e['tamper_state_sim']}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no file writes, no firmware interaction — telemetry only")

@register_payload(name="forged_bios_artifact")
def main():
    session_id, bios_events, uefi_artifacts, events = simulate_bios_artifact()
    print_simulation(session_id, bios_events, uefi_artifacts, events)

if __name__ == "__main__":
    main()
