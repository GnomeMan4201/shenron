from core.engine.payload_registry import register_payload
#!/usr/bin/env python3
# SHENRON: Boot Persistence Anchor — boot/logon script and service persistence simulator
# PURPOSE: Emit defender-observable telemetry for persistence patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1037 (Boot or Logon Initialization Scripts),
#        T1037.001 (Logon Script Windows), T1037.004 (RC Scripts),
#        T1037.005 (Startup Items),
#        T1543 (Create or Modify System Process),
#        T1543.001 (Launch Agent), T1543.002 (Systemd Service),
#        T1543.003 (Windows Service),
#        T1547 (Boot or Logon Autostart Execution),
#        T1547.001 (Registry Run Keys / Startup Folder),
#        T1547.006 (Kernel Modules and Extensions),
#        T1574 (Hijack Execution Flow), T1574.006 (Dynamic Linker Hijacking)
# DETECTION NOTES:
#   - Alert on: new service creation by non-installer processes
#   - Systemd unit file creation in /etc/systemd/system/ by non-package-manager
#   - LaunchAgent/LaunchDaemon plist creation outside /System/Library
#   - rc.local modification or new rc.d scripts
#   - Startup folder files added by non-installer processes
#   - LD_PRELOAD or /etc/ld.so.preload modification
#   - Registry Run key writes by non-installer processes
#   - Kernel module load (insmod/modprobe) for unusual modules
# NO SUBPROCESS CALLS — all persistence patterns are synthetic
# NO ACTUAL SERVICE/FILE CREATION — simulation only

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


FAKE_SERVICE_NAMES = [
    "WindowsUpdateSvc_SIM", "AdobeFlashHelper_SIM",
    "svchost_monitor_SIM", "NetDiagSvc_SIM"
]
FAKE_SERVICE_BINARIES = [
    r"C:\Windows\Temp\svc_sim.exe",
    r"C:\ProgramData\sim_service\sim.exe",
    r"C:\Users\Public\Documents\svc_sim.exe",
]
FAKE_SYSTEMD_UNITS = [
    "/etc/systemd/system/sim-beacon.service",
    "/etc/systemd/system/network-monitor-sim.service",
    "/lib/systemd/system/sim-updater.service",
]
FAKE_LAUNCH_AGENTS = [
    "~/Library/LaunchAgents/com.sim.beacon.plist",
    "~/Library/LaunchAgents/com.adobe.sim.plist",
    "/Library/LaunchDaemons/com.sim.daemon.plist",
]
FAKE_RC_SCRIPTS = [
    "/etc/rc.local",
    "/etc/rc.d/rc.sim_beacon",
    "/etc/init.d/sim-persist",
]
FAKE_RUN_KEYS = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SIM_Update",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SIM_Svc",
    r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
]
FAKE_STARTUP_PATHS = [
    r"C:\Users\sim_user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\sim.lnk",
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\sim_update.bat",
]
FAKE_PROCESSES = [
    "powershell.exe", "cmd.exe", "bash", "python3",
    "wscript.exe", "mshta.exe"
]


def _log_event(event: dict):
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(event) + "\n")


def _base_event(session_id, mitre, behavior, opps, phase):
    return {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "layer":                   "boot_persistence_anchor",
        "phase":                   phase,
        "mitre_techniques":        mitre,
        "behavior_class":          behavior,
        "detection_opportunities": opps,
        "simulation_only":         True,
        "executable":              False,
        "no_payload_present":      True,
        "network_calls_made":      False,
        "subprocess_spawned":      False,
        "file_writes_made":        False,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
    }


def _phase_windows_service(session_id):
    svc_name   = random.choice(FAKE_SERVICE_NAMES)
    svc_binary = random.choice(FAKE_SERVICE_BINARIES)
    proc       = random.choice(FAKE_PROCESSES)
    start_type = random.choice(["AUTO_START", "DEMAND_START"])

    event = _base_event(session_id,
        mitre=["T1543", "T1543.003"],
        behavior="windows_service_create_persist_sim",
        opps=[
            "service_create_non_installer_process_sim",
            "service_binary_in_temp_or_user_path_sim",
            "service_description_mimics_legitimate_sim",
            "event_id_7045_new_service_installed_sim",
        ],
        phase="windows_service")
    event.update({
        "source_process_sim":   proc,
        "service_name_sim":     svc_name,
        "service_binary_sim":   svc_binary,
        "start_type_sim":       start_type,
        "run_as_sim":           "LocalSystem",
        "sc_command_sim":       f"sc create {svc_name} binPath= \"{svc_binary}\" start= auto",
        "windows_event_sim":    "Event ID 7045 (New Service Installed) in System log",
        "detection_note": (
            f"Windows service '{svc_name}' created by '{proc}'. "
            f"Binary at '{svc_binary}' — non-standard path. "
            f"Alert: Event ID 7045 from non-installer processes, "
            f"service binaries in Temp/User/ProgramData paths."
        ),
    })
    _log_event(event)
    return event


def _phase_systemd_service(session_id):
    unit_path = random.choice(FAKE_SYSTEMD_UNITS)
    proc      = random.choice(["bash", "python3", "wget | bash"])
    payload   = f"/tmp/.sim_{uuid.uuid4().hex[:8]}"

    unit_content = f"""[Unit]
Description=System Network Monitor [SIM]
After=network.target

[Service]
Type=simple
ExecStart={payload}
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target"""

    event = _base_event(session_id,
        mitre=["T1543", "T1543.002"],
        behavior="systemd_service_persist_sim",
        opps=[
            "systemd_unit_file_write_non_package_manager_sim",
            "service_execstart_tmp_or_hidden_path_sim",
            "systemctl_enable_new_unit_sim",
            "unit_file_description_mimics_legitimate_sim",
        ],
        phase="systemd_service")
    event.update({
        "source_process_sim":   proc,
        "unit_path_sim":        unit_path,
        "exec_start_sim":       payload,
        "unit_content_sim":     unit_content,
        "enable_command_sim":   f"systemctl enable {unit_path.split('/')[-1]}",
        "start_command_sim":    f"systemctl start {unit_path.split('/')[-1]}",
        "detection_note": (
            f"Systemd unit '{unit_path}' written by '{proc}'. "
            f"ExecStart points to '{payload}' — temp/hidden path. "
            f"Alert: /etc/systemd/system writes by non-apt/dpkg/rpm, "
            f"unit files with ExecStart in /tmp, /dev/shm, or hidden paths."
        ),
    })
    _log_event(event)
    return event


def _phase_launch_agent(session_id):
    plist_path = random.choice(FAKE_LAUNCH_AGENTS)
    proc       = random.choice(FAKE_PROCESSES)
    payload    = f"/tmp/.sim_{uuid.uuid4().hex[:8]}"
    label      = random.choice(["com.apple.sim.update", "com.adobe.sim.helper"])

    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">
<plist version="1.0"><dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array><string>{payload}</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>"""

    event = _base_event(session_id,
        mitre=["T1543", "T1543.001", "T1037.005"],
        behavior="launch_agent_persist_sim",
        opps=[
            "plist_write_library_launchagents_non_installer_sim",
            "runatload_true_with_tmp_payload_sim",
            "keepalive_true_persistence_pattern_sim",
            "launchctl_load_new_plist_sim",
        ],
        phase="launch_agent")
    event.update({
        "source_process_sim":   proc,
        "plist_path_sim":       plist_path,
        "label_sim":            label,
        "payload_sim":          payload,
        "plist_content_sim":    plist_content,
        "load_command_sim":     f"launchctl load -w {plist_path}",
        "detection_note": (
            f"LaunchAgent plist '{plist_path}' created by '{proc}'. "
            f"Label: '{label}' (mimics legitimate Apple/Adobe). RunAtLoad=true. "
            f"Alert: ~/Library/LaunchAgents writes by non-installer processes, "
            f"RunAtLoad with ProgramArguments pointing to tmp/hidden paths."
        ),
    })
    _log_event(event)
    return event


def _phase_rc_script(session_id):
    rc_path = random.choice(FAKE_RC_SCRIPTS)
    proc    = random.choice(["bash", "sh", "python3"])
    payload = f"/tmp/.sim_{uuid.uuid4().hex[:8]} &"

    event = _base_event(session_id,
        mitre=["T1037", "T1037.004"],
        behavior="rc_script_persist_sim",
        opps=[
            "rc_local_modification_by_non_package_manager_sim",
            "rc_d_script_creation_unusual_name_sim",
            "background_launch_pattern_in_rc_file_sim",
            "rc_file_modified_by_non_shell_process_sim",
        ],
        phase="rc_script")
    event.update({
        "source_process_sim":   proc,
        "rc_path_sim":          rc_path,
        "appended_line_sim":    payload,
        "execution_trigger_sim": "system boot (runs as root)",
        "detection_note": (
            f"RC script persistence via write to '{rc_path}' by '{proc}'. "
            f"Appended: '{payload}'. Executes as root on boot. "
            f"Alert: /etc/rc.local modifications, new files in /etc/rc.d/, "
            f"appended lines with & (background) or network fetches."
        ),
    })
    _log_event(event)
    return event


def _phase_ld_preload(session_id):
    proc    = random.choice(["bash", "python3", "gcc"])
    lib_path = random.choice([
        "/tmp/.sim_preload.so",
        "/lib/x86_64-linux-gnu/.sim.so",
        f"/usr/local/lib/sim_{uuid.uuid4().hex[:6]}.so",
    ])

    event = _base_event(session_id,
        mitre=["T1574", "T1574.006"],
        behavior="ld_preload_hijack_sim",
        opps=[
            "ld_so_preload_modification_sim",
            "shared_library_write_system_path_sim",
            "ld_preload_env_variable_set_for_persistence_sim",
            "library_function_hook_credential_harvest_sim",
        ],
        phase="ld_preload")
    event.update({
        "source_process_sim":    proc,
        "preload_file_sim":      "/etc/ld.so.preload",
        "library_path_sim":      lib_path,
        "hook_targets_sim":      ["read()", "write()", "connect()", "open()"],
        "effect_sim":            "All processes load attacker library — credential/key harvest",
        "env_method_sim":        f"export LD_PRELOAD={lib_path}",
        "detection_note": (
            f"LD_PRELOAD hijack via write to /etc/ld.so.preload by '{proc}'. "
            f"Library: '{lib_path}' hooks into all process syscalls. "
            f"Alert: /etc/ld.so.preload modification (rare legitimate use), "
            f"new .so files in system library paths by non-package-manager."
        ),
    })
    _log_event(event)
    return event


def _phase_startup_folder(session_id):
    startup_path = random.choice(FAKE_STARTUP_PATHS)
    run_key      = random.choice(FAKE_RUN_KEYS)
    proc         = random.choice(FAKE_PROCESSES)
    payload      = r"C:\Windows\Temp\sim_payload.exe"

    event = _base_event(session_id,
        mitre=["T1547", "T1547.001", "T1037.001"],
        behavior="startup_folder_run_key_persist_sim",
        opps=[
            "startup_folder_file_creation_non_installer_sim",
            "run_key_write_to_temp_binary_path_sim",
            "lnk_file_in_startup_folder_sim",
            "userinit_registry_key_modification_sim",
        ],
        phase="startup_folder")
    event.update({
        "source_process_sim":   proc,
        "startup_path_sim":     startup_path,
        "run_key_sim":          run_key,
        "payload_sim":          payload,
        "lnk_target_sim":       payload,
        "run_key_value_sim":    payload,
        "detection_note": (
            f"Startup persistence via '{startup_path}' and registry key '{run_key}' "
            f"by '{proc}'. Both methods used simultaneously — belt-and-suspenders. "
            f"Alert: Startup folder file creation by non-installer, "
            f"Run key pointing to Temp/User directory binaries."
        ),
    })
    _log_event(event)
    return event


@register_payload("boot_persistence_anchor")
def main():
    session_id = str(uuid.uuid4())
    phases = [
        ("windows_service",  _phase_windows_service),
        ("systemd_service",  _phase_systemd_service),
        ("launch_agent",     _phase_launch_agent),
        ("rc_script",        _phase_rc_script),
        ("ld_preload",       _phase_ld_preload),
        ("startup_folder",   _phase_startup_folder),
    ]

    print(f"\n  [SIMULATION]  boot_persistence_anchor")
    print(f"  [SESSION]     {session_id}")
    print(f"  [EVENTS]      {len(phases)}")
    print(f"  [MITRE]       T1037.x, T1543.x, T1547.001, T1574.006")
    print(f"  [SUBPROCESS]  NOT CALLED — synthetic only")
    print(f"  [NETWORK]     NO CALLS MADE — synthetic only")
    print(f"  [FILES]       NO ACTUAL FILE WRITES — simulation only")
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
    print(f"  [SAFE]        no subprocess calls, no network, no file writes — simulation only")
    return events
