from core.engine.payload_registry import register_payload
#!/usr/bin/env python3
# SHENRON: Registry Mutator Cloak — defense impairment via registry manipulation simulator
# PURPOSE: Emit defender-observable telemetry for defense impairment patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1112 (Modify Registry),
#        T1484 (Domain or Tenant Policy Modification), T1484.001 (Group Policy Modification),
#        T1222 (File and Directory Permissions Modification),
#        T1222.001 (Windows File and Directory Permissions Modification),
#        T1562 (Impair Defenses), T1562.001 (Disable or Modify Tools),
#        T1562.004 (Disable or Modify System Firewall),
#        T1070 (Indicator Removal), T1070.001 (Clear Windows Event Logs)
# DETECTION NOTES:
#   - Alert on: registry writes to security-relevant keys by non-system processes
#   - Defender/AV registry keys modified (DisableAntiSpyware, DisableRealtimeMonitoring)
#   - Event log clearing (wevtutil cl) or log service stops
#   - GPO modification by non-GPO-management processes
#   - UAC registry bypass patterns (fodhelper, computerdefaults)
#   - Firewall rule addition allowing inbound on unusual ports
# NO SUBPROCESS CALLS — all registry patterns are synthetic
# NO ACTUAL REGISTRY WRITES — simulation only

import json
import uuid
import random
from datetime import datetime, timezone
from pathlib import Path
from core.config import artifact_log_path as _artifact_log_path


def _get_artifact_log():
    p = _artifact_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


FAKE_DEFENDER_KEYS = [
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring",
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableBehaviorMonitoring",
    r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection",
]
FAKE_UAC_BYPASS_KEYS = [
    r"HKCU\Software\Classes\ms-settings\Shell\Open\command",
    r"HKCU\Software\Classes\mscfile\Shell\Open\command",
    r"HKCU\Environment\windir",
]
FAKE_PERSISTENCE_KEYS = [
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
]
FAKE_LOG_CHANNELS = [
    "System", "Security", "Application",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Sysmon/Operational",
]
FAKE_GPO_PATHS = [
    r"\\domain-sim\SYSVOL\domain-sim\Policies\{GUID-SIM}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf",
    r"\\domain-sim\SYSVOL\domain-sim\Policies\{GUID-SIM}\User\Scripts\Logon\logon_sim.ps1",
]
FAKE_PROCESSES = [
    "powershell.exe", "cmd.exe", "wscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe"
]


def _log_event(event: dict):
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(event) + "\n")


def _base_event(session_id, mitre, behavior, opps, phase):
    return {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "layer":                   "registry_mutator_cloak",
        "phase":                   phase,
        "mitre_techniques":        mitre,
        "behavior_class":          behavior,
        "detection_opportunities": opps,
        "simulation_only":         True,
        "executable":              False,
        "no_payload_present":      True,
        "network_calls_made":      False,
        "subprocess_spawned":      False,
        "registry_writes_made":    False,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
    }


def _phase_defender_disable(session_id):
    key = random.choice(FAKE_DEFENDER_KEYS)
    proc = random.choice(FAKE_PROCESSES)
    method = random.choice(["reg add", "Set-MpPreference", "WMI StdRegProv", "Group Policy"])

    event = _base_event(session_id,
        mitre=["T1112", "T1562", "T1562.001"],
        behavior="defender_disable_via_registry_sim",
        opps=[
            "defender_registry_key_write_by_non_system_sim",
            "antispyware_disable_policy_set_sim",
            "realtime_monitoring_disable_sim",
            "tamper_protection_modification_attempt_sim",
        ],
        phase="defender_disable")
    event.update({
        "source_process_sim":  proc,
        "method_sim":          method,
        "registry_key_sim":    key,
        "value_set_sim":       "DWORD:1",
        "effect_sim":          "Windows Defender real-time protection disabled",
        "detection_note": (
            f"'{proc}' writing to Defender policy key via '{method}'. "
            f"Key: '{key}' set to 1. "
            f"Alert: any non-SYSTEM write to Defender policy keys, especially "
            f"DisableRealtimeMonitoring or TamperProtection."
        ),
    })
    _log_event(event)
    return event


def _phase_event_log_clear(session_id):
    channels = random.sample(FAKE_LOG_CHANNELS, 3)
    proc = random.choice(FAKE_PROCESSES)
    method = random.choice(["wevtutil cl", "Clear-EventLog", "WMI Win32_NTEventlogFile.ClearEventLog"])

    event = _base_event(session_id,
        mitre=["T1070", "T1070.001"],
        behavior="event_log_clear_sim",
        opps=[
            "wevtutil_clear_log_commandline_sim",
            "security_log_clear_event_1102_sim",
            "multiple_log_channels_cleared_sequentially_sim",
            "log_service_stop_then_file_deletion_sim",
        ],
        phase="event_log_clear")
    event.update({
        "source_process_sim":    proc,
        "method_sim":            method,
        "channels_cleared_sim":  channels,
        "windows_event_sim":     "Event ID 1102 (Security log cleared) + 104 (System log cleared)",
        "sequence_sim":          [f"{method} {ch}" for ch in channels],
        "detection_note": (
            f"'{proc}' clearing {len(channels)} event log channels via '{method}'. "
            f"Security log clear generates Event ID 1102 — monitor this regardless. "
            f"Sequential multi-channel clear in <60s is high-confidence indicator."
        ),
    })
    _log_event(event)
    return event


def _phase_uac_bypass(session_id):
    key = random.choice(FAKE_UAC_BYPASS_KEYS)
    proc = random.choice(FAKE_PROCESSES)
    bypass_method = random.choice([
        "fodhelper.exe COM object hijack",
        "computerdefaults.exe registry hijack",
        "windir environment variable tamper",
        "sdclt.exe /KickOffElev registry hijack",
    ])

    event = _base_event(session_id,
        mitre=["T1112", "T1548", "T1548.002"],
        behavior="uac_bypass_registry_sim",
        opps=[
            "hkcu_classes_ms_settings_write_sim",
            "auto_elevate_binary_registry_hijack_sim",
            "uac_bypass_pattern_registry_key_creation_sim",
            "high_integrity_process_spawn_without_uac_prompt_sim",
        ],
        phase="uac_bypass")
    event.update({
        "source_process_sim":  proc,
        "method_sim":          bypass_method,
        "registry_key_sim":    key,
        "payload_in_key_sim":  r"cmd.exe /c payload_sim.exe",
        "result_sim":          "elevated process spawned without UAC prompt",
        "detection_note": (
            f"UAC bypass via '{bypass_method}'. "
            f"Registry key '{key}' written by '{proc}'. "
            f"Alert: HKCU\\Classes\\ms-settings or mscfile write by non-installer, "
            f"followed by auto-elevating binary execution."
        ),
    })
    _log_event(event)
    return event


def _phase_gpo_modification(session_id):
    gpo_path = random.choice(FAKE_GPO_PATHS)
    proc = random.choice(FAKE_PROCESSES)
    modification = random.choice([
        "Added logon script pointing to attacker-controlled UNC path",
        "Modified password policy — minimum length set to 1",
        "Added scheduled task via GPO for persistence",
        "Disabled AppLocker via GPO Computer Configuration",
    ])

    event = _base_event(session_id,
        mitre=["T1484", "T1484.001"],
        behavior="gpo_policy_modification_sim",
        opps=[
            "sysvol_gpo_file_write_by_non_gpmc_process_sim",
            "gpo_logon_script_addition_sim",
            "password_policy_weakening_sim",
            "applocker_disable_via_gpo_sim",
        ],
        phase="gpo_modification")
    event.update({
        "source_process_sim":    proc,
        "gpo_path_sim":          gpo_path,
        "modification_sim":      modification,
        "scope_sim":             f"{random.randint(50,5000)} affected machines [SIM]",
        "detection_note": (
            f"GPO modification by '{proc}' — '{modification}'. "
            f"SYSVOL path: '{gpo_path}'. "
            f"Alert: non-GPMC process writing to SYSVOL\\Policies, "
            f"GPO version counter increment without corresponding GPMC activity."
        ),
    })
    _log_event(event)
    return event


def _phase_firewall_tamper(session_id):
    proc = random.choice(FAKE_PROCESSES)
    port = random.choice([4444, 8080, 1337, 31337, 9001, 443])
    method = random.choice([
        "netsh advfirewall firewall add rule",
        "New-NetFirewallRule PowerShell",
        "registry write to HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters",
    ])

    event = _base_event(session_id,
        mitre=["T1562", "T1562.004"],
        behavior="firewall_rule_modification_sim",
        opps=[
            "inbound_firewall_rule_add_unusual_port_sim",
            "netsh_firewall_allow_rule_non_admin_tool_sim",
            "windows_firewall_registry_key_modification_sim",
            "firewall_profile_disable_sim",
        ],
        phase="firewall_tamper")
    event.update({
        "source_process_sim":  proc,
        "method_sim":          method,
        "port_opened_sim":     port,
        "direction_sim":       "Inbound",
        "action_sim":          "Allow",
        "rule_name_sim":       random.choice(["Windows Update", "Adobe Service", "svchost"]),
        "detection_note": (
            f"Firewall rule added by '{proc}' via '{method}'. "
            f"Port {port} inbound allowed — rule named '{random.choice(['Windows Update','Adobe Service'])}'. "
            f"Alert: firewall rule addition by non-administrative tools, "
            f"especially rules with legitimate-sounding names on unusual ports."
        ),
    })
    _log_event(event)
    return event


@register_payload("registry_mutator_cloak")
def main():
    session_id = str(uuid.uuid4())
    phases = [
        ("defender_disable", _phase_defender_disable),
        ("event_log_clear",  _phase_event_log_clear),
        ("uac_bypass",       _phase_uac_bypass),
        ("gpo_modification", _phase_gpo_modification),
        ("firewall_tamper",  _phase_firewall_tamper),
    ]

    print(f"\n  [SIMULATION]  registry_mutator_cloak")
    print(f"  [SESSION]     {session_id}")
    print(f"  [EVENTS]      {len(phases)}")
    print(f"  [MITRE]       T1112, T1484, T1484.001, T1222, T1562.001, T1562.004, T1070.001")
    print(f"  [SUBPROCESS]  NOT CALLED — synthetic only")
    print(f"  [NETWORK]     NO CALLS MADE — synthetic only")
    print(f"  [REGISTRY]    NO ACTUAL WRITES — simulation only")
    print()

    events = []
    for phase_name, phase_fn in phases:
        event = phase_fn(session_id)
        events.append(event)
        print(f"  [PHASE: {phase_name}]")
        print(f"    behavior      : {event['behavior_class']}")
        print(f"    mitre         : {', '.join(event['mitre_techniques'])}")
        print(f"    detection     : {event['detection_opportunities'][0]}")
        print(f"    note          : {event.get('detection_note','')[:80]}")
        print()

    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no subprocess calls, no network, no registry writes — simulation only")
    return events
