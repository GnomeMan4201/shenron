#!/usr/bin/env python3
# SHENRON Layer: Phantom Thread Fabricator
# CATEGORY: evasion
# MITRE: T1055.003, T1036, T1070
# TACTIC: defense-evasion
# FIDELITY: medium
# NO subprocess, NO socket, NO os.system, NO eval, NO exec, NO threading, NO real file writes.

import hashlib
import random
from datetime import datetime, timezone
from core.engine.payload_registry import register_payload

MITRE_TECHNIQUES = ["T1055.003", "T1036", "T1070"]

SAFETY = {
    "simulation_only":                True,
    "executable":                     False,
    "payload_present":                False,
    "portable_adversarial_procedure": False,
    "network_connection":             False,
    "subprocess_spawned":             False,
    "real_file_written":              False,
    "shell_invoked":                  False,
}


@register_payload(name="thread_injection_sim")
def main():
    ts = datetime.now(timezone.utc).isoformat()
    rng = random.Random(ts)
    events = []

    # Phase 1: Thread inventory
    events.append({
        "timestamp":               ts,
        "layer":                   "thread_injection_sim",
        "phase":                   "thread_inventory_sim",
        "mitre_techniques":        MITRE_TECHNIQUES,
        "behavior_class":          "thread_count_spike_sim",
        "mechanism_type":          "anti_forensic_noise_sim",
        "thread_count_sim":        rng.randint(8, 20),
        "parent_type_sim":         "non_daemon_process",
        "detection_opportunities": [
            "thread_count_spike_single_process",
            "daemon_named_threads_non_daemon_parent",
        ],
        "safety":             SAFETY,
        "simulation_only":    True,
        "executable":         False,
        "no_payload_present": True,
    })

    # Phase 2: IO chatter cycles
    num_cycles = rng.randint(3, 6)
    for i in range(num_cycles):
        tmp_name = hashlib.md5((ts + "io" + str(i)).encode()).hexdigest()[:8]
        events.append({
            "timestamp":               ts,
            "layer":                   "thread_injection_sim",
            "phase":                   "io_chatter_sim",
            "mitre_techniques":        MITRE_TECHNIQUES,
            "behavior_class":          "io_chatter_burst_sim",
            "mechanism_type":          "anti_forensic_noise_sim",
            "cycle":                   i + 1,
            "tmp_artifact_sim":        f"/tmp/io_{tmp_name}",
            "bytes_written_sim":       rng.randint(256, 1024),
            "lifecycle_ms_sim":        rng.randint(10, 400),
            "detection_opportunities": [
                "temp_file_create_delete_high_frequency_non_system_process",
                "io_burst_no_application_activity",
            ],
            "safety":             SAFETY,
            "simulation_only":    True,
            "executable":         False,
            "no_payload_present": True,
        })

    # Phase 3: Log rotation noise
    events.append({
        "timestamp":               ts,
        "layer":                   "thread_injection_sim",
        "phase":                   "log_rotation_sim",
        "mitre_techniques":        MITRE_TECHNIQUES,
        "behavior_class":          "log_rotation_spoof_sim",
        "mechanism_type":          "anti_forensic_noise_sim",
        "log_target_sim":          f"/tmp/shenron_phantom_syslog_{rng.randint(1000,9999)}.log",
        "rotation_trigger_sim":    "synthetic_kernel_event",
        "correlated_logmanager":   False,
        "detection_opportunities": [
            "log_rotation_uncorrelated_log_manager",
            "short_lived_threads_no_work_product",
        ],
        "safety":             SAFETY,
        "simulation_only":    True,
        "executable":         False,
        "no_payload_present": True,
    })

    print(f"  [SHENRON]     thread_injection_sim")
    print(f"  [TECHNIQUE]   {', '.join(MITRE_TECHNIQUES)}")
    print(f"  [BEHAVIOR]    anti_forensic_noise_sim — {num_cycles} IO cycles + thread inventory + log rotation")
    print(f"  [EVENTS]      {len(events)} synthetic telemetry records")
    print(f"  [SAFE]        simulation_only: true — no threads spawned, no file writes, no subprocess")
    return events
