"""
core/ingest/journald_normalizer.py

Normalize journald log output into SHENRON-compatible JSONL.

Reads journald JSON output (journalctl --output=json) and maps events
to SHENRON's telemetry schema, classifying them into behavior_class and
detection_opportunities that match what simulation layers emit.

This breaks the circularity: SHENRON assumptions can be validated against
data the framework did not generate.

Usage:
    journalctl -n 5000 --output=json | python3 -m core.ingest.journald_normalizer
    journalctl -n 5000 --output=json > /tmp/journal.json
    python3 -m core.ingest.journald_normalizer --input /tmp/journal.json \
        --output ~/SHENRON/logs/journald_normalized.jsonl

Safety:
    Read-only. No writes outside output path. No subprocess calls.
    No network. Purely transforms log data.
"""

import json
import sys
import uuid
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

NORMALIZER_VERSION = "0.1.0"
LAYER_TAG = "journald_external"

# ── Behavior classifiers ───────────────────────────────────────────────────────
# Each classifier is a function that takes a journald event dict and returns
# (behavior_class, detection_opportunities, mitre_techniques, phase) or None.

def _classify_kernel_bpf(e: dict) -> Optional[tuple]:
    """BPF-related kernel events."""
    msg = e.get("MESSAGE", "")
    if not isinstance(msg, str):
        return None
    msg_lower = msg.lower()
    if "bpf" not in msg_lower:
        return None
    if e.get("_SYSTEMD_UNIT", "") != "kernel" and e.get("SYSLOG_IDENTIFIER", "") != "kernel":
        return None

    if "prog" in msg_lower or "map" in msg_lower:
        return (
            "bpf_prog_event",
            ["unexpected_bpf_prog_type", "map_enumeration_discrepancy"],
            ["T1014", "T1562.001"],
            "bpf_load",
        )
    return (
        "bpf_kernel_event",
        ["bpf_probe_write_user_usage"],
        ["T1014"],
        "memory_tamper",
    )


def _classify_process_spawn(e: dict) -> Optional[tuple]:
    """Process spawn / exec events."""
    msg = e.get("MESSAGE", "")
    if not isinstance(msg, str):
        return None
    comm = e.get("_COMM", "")
    exe = e.get("_EXE", "")

    # Interpreter spawns
    interpreters = {"python3", "python", "bash", "sh", "perl", "ruby", "node"}
    if comm in interpreters or any(i in exe for i in interpreters):
        return (
            "interpreter_spawn_sim",
            ["interpreter_spawn_no_script_arg_sim", "shell_spawn_sim"],
            ["T1059", "T1059.007"],
            "execution",
        )

    # Script execution
    if exe.endswith(".sh") or exe.endswith(".py"):
        return (
            "script_execution_sim",
            ["script_execution_sim", "shell_spawn_sim"],
            ["T1059"],
            "execution",
        )

    return None


def _classify_network(e: dict) -> Optional[tuple]:
    """Network connection events from NetworkManager/wpa_supplicant."""
    unit = e.get("_SYSTEMD_UNIT", "")
    identifier = e.get("SYSLOG_IDENTIFIER", "")
    msg = e.get("MESSAGE", "")
    if not isinstance(msg, str):
        return None
    msg_lower = msg.lower()

    if "networkmanager" in unit.lower() or "networkmanager" in identifier.lower():
        if "connect" in msg_lower or "activat" in msg_lower:
            return (
                "network_connection_sim",
                ["outbound_connection_non_standard_port_non_network_process"],
                ["T1071"],
                "c2_callback",
            )

    if "wpa_supplicant" in unit.lower() or "wpa_supplicant" in identifier.lower():
        return (
            "wifi_auth_event",
            ["protocol_tunnel_init_sim"],
            ["T1071"],
            "c2_callback",
        )

    return None


def _classify_auth(e: dict) -> Optional[tuple]:
    """Authentication / privilege events."""
    msg = e.get("MESSAGE", "")
    if not isinstance(msg, str):
        return None
    msg_lower = msg.lower()
    identifier = e.get("SYSLOG_IDENTIFIER", "")

    if "sudo" in identifier.lower() or "sudo" in msg_lower:
        return (
            "privilege_escalation_sim",
            ["cap_escalation", "cap_bpf_privilege_escalation"],
            ["T1548"],
            "privilege_acquisition",
        )

    if "pam" in identifier.lower() or "pam" in msg_lower:
        if "session open" in msg_lower or "session close" in msg_lower:
            return (
                "session_event",
                ["token_impersonation_sim"],
                ["T1078"],
                "identity",
            )

    if "polkit" in identifier.lower():
        return (
            "polkit_event",
            ["token_impersonation_sim"],
            ["T1078", "T1548"],
            "privilege_acquisition",
        )

    return None


def _classify_systemd_unit(e: dict) -> Optional[tuple]:
    """Systemd service start/stop events."""
    msg = e.get("MESSAGE", "")
    if not isinstance(msg, str):
        return None
    msg_lower = msg.lower()
    unit = e.get("_SYSTEMD_UNIT", "")
    identifier = e.get("SYSLOG_IDENTIFIER", "")

    if "systemd" not in unit.lower() and "systemd" not in identifier.lower():
        return None

    if "started" in msg_lower or "starting" in msg_lower:
        return (
            "service_start_sim",
            ["background_launch_pattern_in_rc_file", "staging"],
            ["T1543"],
            "persistence",
        )

    if "failed" in msg_lower or "error" in msg_lower:
        return (
            "service_failure_sim",
            ["log_marker"],
            ["T1543"],
            "persistence",
        )

    return None


def _classify_kernel_generic(e: dict) -> Optional[tuple]:
    """Generic kernel events worth capturing."""
    identifier = e.get("SYSLOG_IDENTIFIER", "")
    unit = e.get("_SYSTEMD_UNIT", "")
    msg = e.get("MESSAGE", "")
    if not isinstance(msg, str):
        return None

    if unit != "kernel" and identifier != "kernel":
        return None

    msg_lower = msg.lower()

    if "oom" in msg_lower or "killed process" in msg_lower:
        return (
            "oom_event",
            ["dormant_process_revival_sim"],
            ["T1055"],
            "execution",
        )

    if "usb" in msg_lower or "device" in msg_lower:
        return (
            "device_event",
            ["source_enumeration"],
            ["T1082"],
            "recon",
        )

    if "net" in msg_lower or "eth" in msg_lower or "wlan" in msg_lower:
        return (
            "kernel_network_event",
            ["non_standard_protocol_carrying_encapsulated_traffic"],
            ["T1095"],
            "c2_callback",
        )

    return None


# Ordered classifier list — first match wins
CLASSIFIERS = [
    _classify_kernel_bpf,
    _classify_auth,
    _classify_process_spawn,
    _classify_network,
    _classify_systemd_unit,
    _classify_kernel_generic,
]


# ── Normalizer ─────────────────────────────────────────────────────────────────

def _parse_timestamp(e: dict) -> str:
    """Extract ISO8601 timestamp from journald event."""
    ts_us = e.get("__REALTIME_TIMESTAMP")
    if ts_us:
        try:
            ts = datetime.fromtimestamp(int(ts_us) / 1_000_000, tz=timezone.utc)
            return ts.isoformat()
        except (ValueError, OSError):
            pass
    return datetime.now(timezone.utc).isoformat()


def _build_shenron_event(
    e: dict,
    run_id: str,
    behavior_class: str,
    detection_opportunities: list,
    mitre_techniques: list,
    phase: str,
) -> dict:
    """Build a SHENRON-schema event from a classified journald event."""
    msg = e.get("MESSAGE", "")
    if isinstance(msg, bytes):
        msg = msg.decode("utf-8", errors="replace")

    return {
        "artifact_id":             str(uuid.uuid4()),
        "run_id":                  run_id,
        "session_id":              run_id,
        "layer":                   LAYER_TAG,
        "source":                  "external_journald",
        "phase":                   phase,
        "behavior_class":          behavior_class,
        "detection_opportunities": detection_opportunities,
        "mitre_techniques":        mitre_techniques,
        "simulation_only":         False,
        "executable":              False,
        "timestamp":               _parse_timestamp(e),
        "detail": {
            "message":    msg[:500],
            "unit":       e.get("_SYSTEMD_UNIT", ""),
            "identifier": e.get("SYSLOG_IDENTIFIER", ""),
            "comm":       e.get("_COMM", ""),
            "exe":        e.get("_EXE", ""),
            "pid":        e.get("_PID", ""),
            "priority":   e.get("PRIORITY", ""),
        },
    }


def normalize_stream(input_stream, run_id: str) -> list[dict]:
    """
    Read journald JSON lines from input_stream, classify and normalize.
    Returns list of SHENRON-schema events.
    """
    events = []
    skipped = 0
    classified = 0

    for line in input_stream:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue

        # Try each classifier
        result = None
        for classifier in CLASSIFIERS:
            result = classifier(e)
            if result:
                break

        if not result:
            skipped += 1
            continue

        behavior_class, detection_opportunities, mitre_techniques, phase = result
        event = _build_shenron_event(
            e, run_id, behavior_class, detection_opportunities,
            mitre_techniques, phase,
        )
        events.append(event)
        classified += 1

    return events, classified, skipped


def normalize_file(input_path: str, output_path: str) -> dict:
    """
    Normalize a journald JSON file to SHENRON JSONL.
    Returns summary stats.
    """
    run_id = str(uuid.uuid4())
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    with open(input_path, "r", errors="replace") as f:
        events, classified, skipped = normalize_stream(f, run_id)

    with open(out, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    return {
        "run_id":     run_id,
        "input":      input_path,
        "output":     output_path,
        "classified": classified,
        "skipped":    skipped,
        "total":      classified + skipped,
        "layer":      LAYER_TAG,
    }


def normalize_stdin(output_path: str) -> dict:
    """Normalize journald JSON from stdin to SHENRON JSONL."""
    run_id = str(uuid.uuid4())
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    events, classified, skipped = normalize_stream(sys.stdin, run_id)

    with open(out, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    return {
        "run_id":     run_id,
        "input":      "stdin",
        "output":     output_path,
        "classified": classified,
        "skipped":    skipped,
        "total":      classified + skipped,
        "layer":      LAYER_TAG,
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="Normalize journald JSON output to SHENRON-compatible JSONL"
    )
    p.add_argument("--input", type=str, default=None,
                   help="input journald JSON file (default: stdin)")
    p.add_argument("--output", type=str,
                   default=str(Path.home() / "SHENRON" / "logs" / "journald_normalized.jsonl"),
                   help="output SHENRON JSONL path")
    p.add_argument("--stats", action="store_true",
                   help="print classification stats only, don't write output")
    args = p.parse_args()

    if args.input:
        result = normalize_file(args.input, args.output)
    else:
        result = normalize_stdin(args.output)

    print(f"\n  journald → SHENRON normalizer v{NORMALIZER_VERSION}")
    print(f"  input      : {result['input']}")
    print(f"  output     : {result['output']}")
    print(f"  total      : {result['total']}")
    print(f"  classified : {result['classified']}")
    print(f"  skipped    : {result['skipped']}")
    print(f"  run_id     : {result['run_id']}")
    print()

    if result["classified"] == 0:
        print("  [!] No events classified — check journald output format")
        sys.exit(1)


if __name__ == "__main__":
    main()
