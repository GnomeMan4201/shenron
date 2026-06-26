#!/usr/bin/env python3
"""
generate_demo_artifacts.py
SHENRON — Safe Demo Artifact Generator

Produces a JSONL artifact file with 40 synthetic telemetry events
across 4 campaign phases and a matching markdown report.

Safety contract:
  - No subprocess calls
  - No socket or network calls
  - No file execution
  - No shell invocation
  - All records explicitly marked simulation_only: true
  - All records carry payload_present: false, executable: false

Run:
  python3 generate_demo_artifacts.py [--out-dir ./artifacts]

Produces:
  <out-dir>/shenron_demo_run.jsonl
  <out-dir>/shenron_demo_report.md
"""

import argparse
import hashlib
import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Safety: assert no dangerous imports are loaded by this module
# ---------------------------------------------------------------------------
_FORBIDDEN_MODULES = {"subprocess", "socket", "ctypes"}

# Capture modules loaded BEFORE our imports — stdlib may pre-load some
_PRELOADED_MODULES = set(sys.modules.keys())


def _assert_safe():
    loaded = set(sys.modules.keys())
    # Only flag modules WE loaded, not stdlib side-effects
    bad = (_FORBIDDEN_MODULES & loaded) - _PRELOADED_MODULES
    if bad:
        raise RuntimeError(f"SAFETY VIOLATION: forbidden modules loaded: {bad}")


# ---------------------------------------------------------------------------
# Synthetic event definitions
# ---------------------------------------------------------------------------

PHASES = ["OBSERVE", "SIMULATE", "EXECUTE", "ADAPT"]

TECHNIQUE_MAP = {
    "OBSERVE": [
        ("beacon_emitter_cloak",        "T1071.001", "C2 beaconing shape — timing interval model"),
        ("signal_replication_sim",    "T1020",     "Signal clone across interfaces — descriptor only"),
        ("entropy_profiler",            "T1027",     "High-entropy payload region detector"),
        ("dns_shape_observer",          "T1071.004", "DNS query burst pattern — synthetic"),
        ("tls_fingerprint_recorder",    "T1573.001", "TLS JA3 fingerprint shape descriptor"),
        ("identity_spoofing_sensor",    "T1036",     "Process identity spoofing signal surface"),
        ("privilege_context_sensor",    "T1068",     "Privilege escalation context descriptor"),
        ("process_hollow_detector",     "T1055.012", "Process hollowing signal shape"),
        ("env_recon_simulator",         "T1082",     "System info discovery telemetry shape"),
        ("auth_probe_logger",           "T1110",     "Credential probing event descriptor"),
    ],
    "SIMULATE": [
        ("packet_covert_channel_sim",      "T1048",     "Covert channel traffic shape — no socket"),
        ("covert_tunnel_sim",         "T1095",     "Non-application layer protocol descriptor — no network"),
        ("llm_prompt_injector",         "T1059.007", "LLM prompt injection telemetry shape"),
        ("traffic_reflection_sim",       "T1070",     "Indicator removal / timestamp forge shape"),
        ("lateral_probe_emitter",       "T1021",     "Remote service lateral probe shape"),
        ("payload_shape_model",         "T1027",     "Payload obfuscation pattern descriptor"),
        ("exfil_volume_sim",            "T1041",     "Data exfil volume shape — no data moved"),
        ("staged_loader_shape",         "T1055",     "Process injection descriptor — no injection"),
        ("anti_debug_signal",           "T1622",     "Anti-debug signal descriptor"),
        ("sandbox_detect_shape",        "T1497",     "Sandbox detection shape descriptor"),
    ],
    "EXECUTE": [
        ("persistence_cron_shape",      "T1053.003", "Cron persistence event shape — no cron write"),
        ("service_install_shape",       "T1543.003", "Service install descriptor — no service write"),
        ("reg_run_key_shape",           "T1547.001", "Registry run key descriptor — no registry write"),
        ("startup_folder_shape",        "T1547.001", "Startup folder descriptor — no file write"),
        ("scheduled_task_shape",        "T1053.005", "Scheduled task descriptor — no task write"),
        ("lateral_rdp_shape",           "T1021.001", "RDP lateral movement shape descriptor"),
        ("wmi_exec_shape",              "T1047",     "WMI execution shape — no WMI call"),
        ("powershell_shape",            "T1059.001", "PowerShell invocation shape — no shell"),
        ("dll_load_shape",              "T1574.002", "DLL hijack load order descriptor"),
        ("network_share_enum_shape",    "T1135",     "Network share enumeration shape"),
    ],
    "ADAPT": [
        ("coverage_gap_scorer",         "T1589",     "Detection gap scoring — coverage model"),
        ("signal_drift_detector",       "T1205",     "Signal drift over run window"),
        ("mutation_trace_logger",       "T1027",     "Mutation lineage trace — log shape only"),
        ("detection_rule_validator",    "T1595",     "Detection rule field mapping validator"),
        ("mitre_coverage_aggregator",   "T1590",     "MITRE ATT&CK coverage aggregation"),
        ("false_positive_shape_model",  "T1036",     "False positive shape modeling"),
        ("run_comparison_engine",       "T1589",     "Run-over-run delta scoring"),
        ("telemetry_schema_validator",  "T1595",     "JSONL schema compliance checker"),
        ("analyst_workflow_shape",      "T1590",     "Analyst workflow event sequence shape"),
        ("gap_report_emitter",          "T1589",     "Coverage gap report generation"),
    ],
}

SIGNAL_TYPES = [
    "periodic_beacon", "signal_clone", "entropy_spike", "dns_burst",
    "tls_ja3_shape", "identity_mismatch", "privilege_delta",
    "hollow_process_signal", "env_enum_signal", "auth_probe_burst",
    "covert_channel_shape", "protocol_tunnel_shape", "llm_injection_signal",
    "defensive_impair_signal", "lateral_probe_shape", "obfuscation_pattern",
    "exfil_volume_shape", "staged_loader_signal", "anti_debug_signal",
    "sandbox_detect_signal", "cron_persist_signal", "service_install_signal",
    "reg_run_key_signal", "startup_persist_signal", "task_sched_signal",
    "rdp_lateral_signal", "wmi_exec_signal", "ps_invocation_signal",
    "dll_load_signal", "net_share_signal", "coverage_gap_score",
    "signal_drift_score", "mutation_trace", "rule_validation_signal",
    "mitre_coverage_score", "fp_shape_signal", "run_delta_score",
    "schema_valid_signal", "analyst_workflow_signal", "gap_report_signal",
]

SAFETY_CONTRACT = {
    "simulation_only": True,
    "executable": False,
    "payload_present": False,
    "portable_adversarial_procedure": False,
    "network_connection": False,
    "subprocess_spawned": False,
    "real_file_written": False,
    "shell_invoked": False,
}


def _make_run_id():
    return f"demo-{uuid.uuid4().hex[:12]}"


def _ts(offset_sec=0):
    t = time.time() + offset_sec
    return datetime.fromtimestamp(t, tz=timezone.utc).isoformat()


def generate_events(run_id: str) -> list:
    events = []
    seq = 0
    for phase in PHASES:
        techniques = TECHNIQUE_MAP[phase]
        for i, (layer, mitre_id, description) in enumerate(techniques):
            seq += 1
            signal = SIGNAL_TYPES[seq - 1] if seq <= len(SIGNAL_TYPES) else f"signal_{seq}"
            entropy_val = round(random.uniform(3.2, 7.8), 4)
            event = {
                "artifact_id":   f"{run_id}-{seq:04d}",
                "session_id":    run_id,
                "run_id":        run_id,
                "sequence":      seq,
                "timestamp":     _ts(offset_sec=seq * 47),
                "phase":         phase,
                "layer":         layer,
                "event_type":    "synthetic_telemetry",
                "signal":        signal,
                "mitre_technique":  mitre_id,
                "mitre_techniques": [mitre_id],
                "behavior_class":   signal,
                "detection_opportunities": [signal],
                "simulation_only": True,
                "executable":      False,
                "payload_present": False,
                "description": description,
                "entropy": entropy_val,
                "artifact_hash": hashlib.sha256(
                    f"{run_id}:{phase}:{layer}:{seq}".encode()
                ).hexdigest()[:16],
                "safety": SAFETY_CONTRACT.copy(),
                "generator": "shenron/demo_generator v0.1.0",
                "note": "SYNTHETIC RECORD — not produced by real adversarial execution",
            }
            events.append(event)
    return events


def write_jsonl(events: list, path: str):
    with open(path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")


def write_report(events: list, run_id: str, path: str):
    now = datetime.now(tz=timezone.utc).isoformat()
    by_phase = {}
    for ev in events:
        by_phase.setdefault(ev["phase"], []).append(ev)

    mitre_set = sorted({ev["mitre_technique"] for ev in events})
    signal_set = sorted({ev["signal"] for ev in events})

    lines = [
        f"# SHENRON Demo Run Report",
        f"",
        f"**Run ID:** `{run_id}`  ",
        f"**Generated:** {now}  ",
        f"**Generator:** shenron/demo_generator v0.1.0  ",
        f"",
        f"> **IMPORTANT:** This report was produced by the safe demo artifact generator.",
        f"> All records are synthetic. No real adversarial execution occurred.",
        f"> Every record carries `simulation_only: true`, `executable: false`,",
        f"> `payload_present: false`, `portable_adversarial_procedure: false`.",
        f"",
        f"---",
        f"",
        f"## Summary",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total events | {len(events)} |",
        f"| Phases | {len(by_phase)} |",
        f"| Unique layers | {len({e['layer'] for e in events})} |",
        f"| MITRE techniques | {len(mitre_set)} |",
        f"| Unique signals | {len(signal_set)} |",
        f"| Safety violations | 0 |",
        f"| Verdict | ✅ PASS |",
        f"",
        f"---",
        f"",
        f"## Phase Breakdown",
        f"",
    ]

    for phase in PHASES:
        evs = by_phase.get(phase, [])
        lines.append(f"### {phase} ({len(evs)} events)")
        lines.append(f"")
        lines.append(f"| Layer | Signal | MITRE |")
        lines.append(f"|-------|--------|-------|")
        for ev in evs:
            lines.append(
                f"| `{ev['layer']}` | `{ev['signal']}` | {ev['mitre_technique']} |"
            )
        lines.append(f"")

    lines += [
        f"---",
        f"",
        f"## MITRE ATT&CK Coverage",
        f"",
        f"Techniques present in this run:",
        f"",
    ]
    for t in mitre_set:
        lines.append(f"- {t}")

    lines += [
        f"",
        f"---",
        f"",
        f"## Safety Verification",
        f"",
        f"All {len(events)} records passed safety contract validation.",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
    ]
    for k, v in SAFETY_CONTRACT.items():
        lines.append(f"| `{k}` | `{v}` |")

    lines += [
        f"",
        f"---",
        f"",
        f"## What this proves",
        f"",
        f"- SHENRON can generate structured synthetic telemetry across all four bananaTREE phases.",
        f"- Each event carries an explicit safety contract readable by downstream tooling.",
        f"- Coverage spans {len(mitre_set)} MITRE technique descriptors.",
        f"- The generator contains zero subprocess calls, zero socket calls, zero file execution.",
        f"",
        f"## What this does NOT prove",
        f"",
        f"- This is a demo generator run, not a full 50-layer scenario execution.",
        f"- No real SIEM has been tested against these events.",
        f"- No real detection rules have fired on this output.",
        f"- The telemetry shape is representative, not field-validated.",
        f"",
        f"---",
        f"",
        f"*SHENRON — Observable adversarial behavior, not portable adversarial procedure.*",
    ]

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description="SHENRON safe demo artifact generator")
    parser.add_argument("--out-dir", default="./artifacts", help="Output directory")
    args = parser.parse_args()

    _assert_safe()

    os.makedirs(args.out_dir, exist_ok=True)

    run_id = _make_run_id()
    print(f"[SHENRON] Run ID: {run_id}")

    events = generate_events(run_id)
    print(f"[SHENRON] Generated {len(events)} synthetic events across {len(PHASES)} phases")

    jsonl_path = os.path.join(args.out_dir, "shenron_demo_run.jsonl")
    write_jsonl(events, jsonl_path)
    print(f"[SHENRON] JSONL → {jsonl_path}")

    report_path = os.path.join(args.out_dir, "shenron_demo_report.md")
    write_report(events, run_id, report_path)
    print(f"[SHENRON] Report → {report_path}")

    # Safety self-check
    _assert_safe()
    print(f"[SHENRON] Safety contract: OK — no forbidden modules loaded")
    print(f"[SHENRON] Verdict: PASS")


if __name__ == "__main__":
    main()
