"""
core/noise/benign_generator.py

SHENRON Benign Event Generator.

Produces realistic, volume-appropriate benign system telemetry in SHENRON
JSONL schema. Used to create realistic noise for L3 detection evaluation.

Event categories modeled:
  - authentication: SSH login/logout, sudo, PAM sessions, failed auth
  - network: DHCP renewal, DNS resolution, NTP sync, TLS handshake
  - system: Cron execution, systemd unit start/stop, logrotate, journald
  - storage: Package manager activity, file integrity checks, tmp cleanup
  - process: Browser activity, editor sessions, compiler runs, git operations
  - hardware: USB attach/detach, thermal events, battery status

Design constraints:
- New file only. Zero modifications to existing core files.
- All events carry simulation_only: true and full safety contract.
- Output is valid SHENRON JSONL schema.
- Deterministic given a seed.
- No subprocess, no network, no real file writes outside output path.
"""

import json
import uuid
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Optional


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


AUTH_EVENTS = [
    {"layer": "auth_monitor", "behavior_class": "ssh_login_authorized",
     "signal": "authorized_ssh_login", "category": "authentication",
     "description": "Authorized SSH login via key authentication",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "auth_monitor", "behavior_class": "ssh_logout",
     "signal": "normal_session_close", "category": "authentication",
     "description": "SSH session closed — normal logout",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "auth_monitor", "behavior_class": "sudo_authorized_command",
     "signal": "authorized_sudo", "category": "authentication",
     "description": "Authorized sudo command by known user",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "auth_monitor", "behavior_class": "pam_session_open",
     "signal": "pam_session_normal", "category": "authentication",
     "description": "PAM session opened for local user",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "auth_monitor", "behavior_class": "failed_ssh_password",
     "signal": "single_failed_auth", "category": "authentication",
     "description": "Single failed SSH password attempt — likely mistyped",
     "detection_opportunities": [], "mitre_techniques": []},
]

NETWORK_EVENTS = [
    {"layer": "network_monitor", "behavior_class": "dhcp_lease_renewal",
     "signal": "dhcp_renew", "category": "network",
     "description": "DHCP lease renewal on primary interface",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "network_monitor", "behavior_class": "dns_resolution_normal",
     "signal": "dns_query_normal", "category": "network",
     "description": "Routine DNS A record query for known domain",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "network_monitor", "behavior_class": "ntp_sync",
     "signal": "ntp_clock_sync", "category": "network",
     "description": "NTP clock synchronization with pool.ntp.org",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "network_monitor", "behavior_class": "tls_handshake_normal",
     "signal": "tls_connection_normal", "category": "network",
     "description": "Normal TLS 1.3 handshake to known CDN endpoint",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "network_monitor", "behavior_class": "http_package_repo_fetch",
     "signal": "apt_http_fetch", "category": "network",
     "description": "HTTP fetch from apt package repository",
     "detection_opportunities": [], "mitre_techniques": []},
]

SYSTEM_EVENTS = [
    {"layer": "system_monitor", "behavior_class": "cron_job_execution",
     "signal": "cron_heartbeat", "category": "system",
     "description": "Scheduled cron job execution — daily maintenance task",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "system_monitor", "behavior_class": "systemd_unit_start",
     "signal": "unit_start_normal", "category": "system",
     "description": "systemd unit started — print spooler or similar service",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "system_monitor", "behavior_class": "logrotate_cycle",
     "signal": "log_rotation_normal", "category": "system",
     "description": "Routine log rotation — no anomaly",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "system_monitor", "behavior_class": "journald_flush",
     "signal": "journal_flush_normal", "category": "system",
     "description": "journald flushing runtime journal to persistent storage",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "system_monitor", "behavior_class": "systemd_unit_stop",
     "signal": "unit_stop_normal", "category": "system",
     "description": "systemd unit stopped cleanly — expected shutdown",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "system_monitor", "behavior_class": "tmp_cleanup",
     "signal": "tmpfiles_cleanup", "category": "system",
     "description": "systemd-tmpfiles cleaning stale /tmp entries",
     "detection_opportunities": [], "mitre_techniques": []},
]

STORAGE_EVENTS = [
    {"layer": "storage_monitor", "behavior_class": "apt_package_update",
     "signal": "package_update_normal", "category": "storage",
     "description": "apt package list update — unattended-upgrades",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "storage_monitor", "behavior_class": "file_integrity_check",
     "signal": "integrity_scan_normal", "category": "storage",
     "description": "Scheduled file integrity check — no anomalies detected",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "storage_monitor", "behavior_class": "disk_health_check",
     "signal": "smartd_normal", "category": "storage",
     "description": "SMART disk health check — all values nominal",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "storage_monitor", "behavior_class": "backup_job_normal",
     "signal": "backup_cycle_complete", "category": "storage",
     "description": "Scheduled backup job completed successfully",
     "detection_opportunities": [], "mitre_techniques": []},
]

PROCESS_EVENTS = [
    {"layer": "process_monitor", "behavior_class": "browser_session_normal",
     "signal": "browser_activity_normal", "category": "process",
     "description": "Browser process active — user web browsing session",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "process_monitor", "behavior_class": "editor_session",
     "signal": "editor_activity_normal", "category": "process",
     "description": "Text editor session — user editing source files",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "process_monitor", "behavior_class": "compiler_run",
     "signal": "build_activity_normal", "category": "process",
     "description": "Compiler invocation — normal software build",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "process_monitor", "behavior_class": "git_operation",
     "signal": "git_activity_normal", "category": "process",
     "description": "git fetch/pull from remote — normal VCS activity",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "process_monitor", "behavior_class": "terminal_session",
     "signal": "terminal_activity_normal", "category": "process",
     "description": "Terminal emulator session — user command line activity",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "process_monitor", "behavior_class": "python_script_normal",
     "signal": "interpreter_activity_normal", "category": "process",
     "description": "Python script execution — user development activity",
     "detection_opportunities": [], "mitre_techniques": []},
]

HARDWARE_EVENTS = [
    {"layer": "hardware_monitor", "behavior_class": "usb_device_attach",
     "signal": "usb_attach_known_device", "category": "hardware",
     "description": "USB device attached — known trusted device",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "hardware_monitor", "behavior_class": "thermal_normal",
     "signal": "thermal_reading_normal", "category": "hardware",
     "description": "CPU thermal reading — within normal operating range",
     "detection_opportunities": [], "mitre_techniques": []},
    {"layer": "hardware_monitor", "behavior_class": "battery_status",
     "signal": "battery_normal", "category": "hardware",
     "description": "Battery status report — charging normally",
     "detection_opportunities": [], "mitre_techniques": []},
]

ALL_TEMPLATES = (
    AUTH_EVENTS + NETWORK_EVENTS + SYSTEM_EVENTS +
    STORAGE_EVENTS + PROCESS_EVENTS + HARDWARE_EVENTS
)

CATEGORY_WEIGHTS = {
    "authentication": 0.15,
    "network": 0.25,
    "system": 0.30,
    "storage": 0.10,
    "process": 0.15,
    "hardware": 0.05,
}


def _build_event(template: dict, run_id: str, timestamp: datetime,
                 rng: random.Random) -> dict:
    return {
        "artifact_id": str(uuid.UUID(int=rng.getrandbits(128))),
        "run_id": run_id,
        "session_id": run_id,
        "layer": template["layer"],
        "phase": "BENIGN",
        "behavior_class": template["behavior_class"],
        "detection_opportunities": list(template["detection_opportunities"]),
        "mitre_techniques": list(template["mitre_techniques"]),
        "signal": template["signal"],
        "description": template["description"],
        "category": template["category"],
        "entropy": round(rng.uniform(2.0, 4.5), 4),
        "timestamp": timestamp.isoformat(),
        "simulation_only": True,
        "executable": False,
        "payload_present": False,
        "benign": True,
        "safety": _safe_fields(),
        "generator": "shenron/benign_generator v0.1.0",
        "note": "BENIGN SYNTHETIC RECORD — normal system activity simulation",
    }


def _sample_template(rng: random.Random,
                     category_weights: Dict[str, float] = None) -> dict:
    weights = category_weights or CATEGORY_WEIGHTS
    categories = list(weights.keys())
    cat_weights = [weights[c] for c in categories]
    chosen = rng.choices(categories, weights=cat_weights, k=1)[0]
    pool = [t for t in ALL_TEMPLATES if t["category"] == chosen]
    return rng.choice(pool)


def generate_benign_events(
    n: int,
    seed: int = 42,
    run_id: Optional[str] = None,
    base_timestamp: Optional[datetime] = None,
    interval_seconds: int = 47,
    jitter_seconds: int = 30,
    category_weights: Optional[Dict[str, float]] = None,
) -> List[dict]:
    """Generate n realistic benign system events in SHENRON JSONL schema."""
    rng = random.Random(seed)
    run_id = run_id or str(uuid.UUID(int=rng.getrandbits(128)))
    ts = base_timestamp or datetime.now(timezone.utc)
    events = []
    for i in range(n):
        template = _sample_template(rng, category_weights)
        jitter = rng.randint(-jitter_seconds, jitter_seconds)
        ts += timedelta(seconds=interval_seconds + jitter)
        events.append(_build_event(template, run_id, ts, rng))
    return events


def generate_mixed_artifact(
    campaign_events: List[dict],
    noise_ratio: float = 0.4,
    seed: int = 42,
    interleave: bool = True,
) -> List[dict]:
    """Mix adversarial campaign events with benign noise events."""
    rng = random.Random(seed)
    n_campaign = len(campaign_events)
    n_noise = max(1, int(n_campaign * noise_ratio / (1 - noise_ratio)))

    if campaign_events:
        timestamps = [e.get("timestamp", "") for e in campaign_events if e.get("timestamp")]
        try:
            base_ts = datetime.fromisoformat(min(timestamps))
        except Exception:
            base_ts = datetime.now(timezone.utc)
    else:
        base_ts = datetime.now(timezone.utc)

    noise_events = generate_benign_events(
        n=n_noise, seed=seed, base_timestamp=base_ts,
        interval_seconds=30, jitter_seconds=20,
    )
    mixed = list(campaign_events) + noise_events
    if interleave:
        rng.shuffle(mixed)
    return mixed


def write_benign_artifact(
    n: int,
    output_path: str,
    seed: int = 42,
    verbose: bool = True,
) -> dict:
    """Generate benign events and write to JSONL file. Returns summary stats."""
    events = generate_benign_events(n=n, seed=seed)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    by_category: Dict[str, int] = {}
    for ev in events:
        cat = ev.get("category", "unknown")
        by_category[cat] = by_category.get(cat, 0) + 1

    summary = {
        "output_path": str(output_path),
        "events_written": len(events),
        "seed": seed,
        "by_category": by_category,
    }
    if verbose:
        print(f"\n  [NOISE-GEN] Output  : {output_path}")
        print(f"  [NOISE-GEN] Events  : {len(events)}")
        for cat, count in sorted(by_category.items()):
            print(f"  [NOISE-GEN]   {cat:<20} {count}")
        print()
    return summary
