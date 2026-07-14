from core.engine.payload_registry import register_payload
#!/usr/bin/env python3
# SHENRON: LSASS Credential Harvest — OS credential dumping simulator
# PURPOSE: Emit defender-observable telemetry for credential access patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1003 (OS Credential Dumping), T1003.001 (LSASS Memory),
#        T1003.002 (Security Account Manager), T1003.003 (NTDS),
#        T1003.004 (LSA Secrets), T1003.005 (Cached Domain Credentials),
#        T1555 (Credentials from Password Stores),
#        T1552 (Unsecured Credentials), T1552.001 (Credentials In Files)
# DETECTION NOTES:
#   - Alert on: process opening LSASS with PROCESS_VM_READ access rights
#   - MiniDumpWriteDump calls targeting lsass.exe
#   - reg save HKLM\SAM/SYSTEM/SECURITY to temp paths
#   - ntdsutil "ac i ntds" "ifm" "create full" invocations
#   - Access to LSA secrets registry keys
#   - Unusual process (non-werfault) accessing lsass.exe memory
#   - VSS/shadow copy creation followed by NTDS.dit access
# NO SUBPROCESS CALLS — all credential patterns are synthetic
# NO NETWORK CALLS — all exfil patterns are synthetic
# NO REAL CREDENTIAL ACCESS — simulation only

import os
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


# ── Synthetic data pools ───────────────────────────────────────────────────────

FAKE_TOOL_NAMES = [
    "procdump64.exe", "mimikatz.exe", "nanodump.exe",
    "lsass_dumper.exe", "wce.exe", "fgdump.exe",
    "taskhost.exe",   # masquerade
    "svchost.exe",    # masquerade
]

FAKE_DUMP_PATHS = [
    r"C:\Windows\Temp\lsass.dmp",
    r"C:\Users\Public\debug.bin",
    r"C:\ProgramData\.cache\mem.tmp",
    r"/tmp/.lsass_sim",
    r"/dev/shm/.dump_sim",
]

FAKE_SAM_PATHS = [
    r"C:\Windows\Temp\sam_sim",
    r"C:\Windows\Temp\system_sim",
    r"C:\Windows\Temp\security_sim",
]

FAKE_NTDS_PATHS = [
    r"C:\Windows\Temp\ntds_sim\ntds.dit",
    r"C:\IFM\Active Directory\ntds.dit",
]

FAKE_PROCESS_NAMES = [
    "explorer.exe", "svchost.exe", "cmd.exe",
    "powershell.exe", "wscript.exe", "msbuild.exe",
]

FAKE_HASHES = [
    "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
    "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
    "[SYNTHETIC_NTLM_HASH_SIM]",
]

FAKE_SECRET_KEYS = [
    r"SECURITY\Policy\Secrets\NL$KM",
    r"SECURITY\Policy\Secrets\$MACHINE.ACC",
    r"SECURITY\Policy\Secrets\DefaultPassword",
    r"SECURITY\Policy\Secrets\_SC_WdiServiceHost",
]


# ── Event emission helpers ─────────────────────────────────────────────────────

def _log_event(event: dict):
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(event) + "\n")


def _base_event(session_id: str, mitre: list,
                behavior: str, opps: list, phase: str) -> dict:
    return {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "layer":                   "credential_harvest_sim",
        "phase":                   phase,
        "mitre_techniques":        mitre,
        "behavior_class":          behavior,
        "detection_opportunities": opps,
        "simulation_only":         True,
        "executable":              False,
        "no_payload_present":      True,
        "network_calls_made":      False,
        "subprocess_spawned":      False,
        "real_credentials_accessed": False,
        "timestamp":               datetime.now(timezone.utc).isoformat(),
    }


# ── Phase 1: LSASS memory dump ────────────────────────────────────────────────
# Tool opens lsass.exe with VM_READ, calls MiniDumpWriteDump
# Detection: non-werfault process accessing lsass memory,
#            MiniDumpWriteDump API call, dump file written to temp path

def _phase_lsass_dump(session_id: str) -> dict:
    tool       = random.choice(FAKE_TOOL_NAMES)
    dump_path  = random.choice(FAKE_DUMP_PATHS)
    src_proc   = random.choice(FAKE_PROCESS_NAMES)
    access_mask = random.choice([
        "0x1410 (PROCESS_VM_READ|PROCESS_QUERY_INFO)",
        "0x1F0FFF (PROCESS_ALL_ACCESS)",
        "0x0010 (PROCESS_VM_READ)",
    ])

    event = _base_event(
        session_id,
        mitre=["T1003", "T1003.001"],
        behavior="lsass_memory_dump_sim",
        opps=[
            "non_werfault_process_opening_lsass_with_vm_read_sim",
            "minidumpwritedump_api_call_sim",
            "dump_file_written_to_temp_path_sim",
            "lsass_handle_open_unexpected_process_sim",
        ],
        phase="lsass_dump",
    )
    event.update({
        "source_process_sim":     src_proc,
        "tool_sim":               tool,
        "target_process_sim":     "lsass.exe (PID: 724 [SIM])",
        "access_mask_sim":        access_mask,
        "dump_path_sim":          dump_path,
        "api_sim":                "MiniDumpWriteDump(lsass_handle, 724, dump_fd, MiniDumpWithFullMemory)",
        "dump_size_sim":          f"{random.randint(30, 120)}MB [SIM]",
        "detection_note":         (
            f"'{tool}' (spawned from '{src_proc}') opened lsass.exe "
            f"with access mask {access_mask}. "
            f"MiniDumpWriteDump call detected. Dump written to '{dump_path}'. "
            f"Only werfault.exe/WerFaultSecure.exe legitimately open lsass with VM_READ."
        ),
    })
    _log_event(event)
    return event


# ── Phase 2: SAM/SYSTEM/SECURITY registry hive dump ──────────────────────────
# reg save HKLM\SAM C:\temp\sam — offline SAM extraction
# Detection: reg.exe saving SAM/SYSTEM/SECURITY to non-standard paths,
#            shadow copy access to bypass VSS locks

def _phase_sam_dump(session_id: str) -> dict:
    sam_path  = FAKE_SAM_PATHS[0]
    sys_path  = FAKE_SAM_PATHS[1]
    sec_path  = FAKE_SAM_PATHS[2]
    src_proc  = random.choice(FAKE_PROCESS_NAMES)

    event = _base_event(
        session_id,
        mitre=["T1003", "T1003.002"],
        behavior="sam_hive_dump_sim",
        opps=[
            "reg_save_sam_system_security_nonstandard_path_sim",
            "registry_hive_export_by_non_admin_tool_sim",
            "file_created_in_temp_with_sam_system_name_sim",
            "impacket_secretsdump_pattern_sim",
        ],
        phase="sam_dump",
    )
    event.update({
        "source_process_sim":     src_proc,
        "commands_sim":           [
            f"reg save HKLM\\SAM {sam_path}",
            f"reg save HKLM\\SYSTEM {sys_path}",
            f"reg save HKLM\\SECURITY {sec_path}",
        ],
        "output_paths_sim":       [sam_path, sys_path, sec_path],
        "offline_crack_tool_sim": "impacket-secretsdump / samdump2 [SIM]",
        "hash_format_sim":        random.choice(FAKE_HASHES),
        "detection_note":         (
            f"reg.exe (from '{src_proc}') saving SAM/SYSTEM/SECURITY hives "
            f"to temp paths. Offline extraction enables pass-the-hash without "
            f"live LSASS access. Alert: reg.exe child process writing to temp."
        ),
    })
    _log_event(event)
    return event


# ── Phase 3: NTDS.dit extraction ─────────────────────────────────────────────
# ntdsutil IFM / VSS shadow copy to extract NTDS.dit
# Detection: ntdsutil with "ifm" keyword, vssadmin create shadow,
#            NTDS.dit accessed outside of normal DC operation

def _phase_ntds_extraction(session_id: str) -> dict:
    method    = random.choice(["ntdsutil_ifm", "vss_shadow_copy", "volume_shadow_copy_wmi"])
    ntds_path = random.choice(FAKE_NTDS_PATHS)
    src_proc  = random.choice(FAKE_PROCESS_NAMES)

    ntdsutil_cmd = (
        'ntdsutil "ac i ntds" "ifm" '
        f'"create full C:\\IFM" q q'
    )
    vss_cmds = [
        "vssadmin create shadow /for=C:",
        f"copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit {ntds_path}",
        f"copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM {FAKE_SAM_PATHS[1]}",
    ]

    event = _base_event(
        session_id,
        mitre=["T1003", "T1003.003"],
        behavior="ntds_dit_extraction_sim",
        opps=[
            "ntdsutil_ifm_keyword_in_commandline_sim",
            "vssadmin_create_shadow_unusual_context_sim",
            "ntds_dit_access_outside_normal_dc_operation_sim",
            "system_hive_copy_paired_with_ntds_extraction_sim",
        ],
        phase="ntds_extraction",
    )
    event.update({
        "source_process_sim":     src_proc,
        "method_sim":             method,
        "command_sim":            ntdsutil_cmd if method == "ntdsutil_ifm" else vss_cmds,
        "ntds_output_path_sim":   ntds_path,
        "system_hive_path_sim":   FAKE_SAM_PATHS[1],
        "domain_account_count_sim": f"{random.randint(200, 5000)} [SIM]",
        "detection_note":         (
            f"NTDS.dit extraction via '{method}'. "
            f"Contains all domain account hashes — highest-value credential target. "
            f"Alert: ntdsutil with 'ifm' in args, OR vssadmin shadow creation "
            f"followed by ntds.dit file copy within 60s."
        ),
    })
    _log_event(event)
    return event


# ── Phase 4: LSA Secrets extraction ──────────────────────────────────────────
# Access HKLM\SECURITY\Policy\Secrets for service account creds
# Detection: process accessing LSA secrets registry path,
#            unusual process reading SECURITY hive keys

def _phase_lsa_secrets(session_id: str) -> dict:
    secret_key = random.choice(FAKE_SECRET_KEYS)
    tool       = random.choice(["mimikatz", "reg query", "secretsdump"])
    src_proc   = random.choice(FAKE_PROCESS_NAMES)

    event = _base_event(
        session_id,
        mitre=["T1003", "T1003.004"],
        behavior="lsa_secrets_access_sim",
        opps=[
            "security_hive_lsa_secrets_path_access_sim",
            "unusual_process_reading_security_registry_key_sim",
            "lsa_secrets_key_enumeration_sim",
            "service_account_credential_extraction_sim",
        ],
        phase="lsa_secrets",
    )
    event.update({
        "source_process_sim":     src_proc,
        "tool_sim":               tool,
        "registry_path_sim":      secret_key,
        "extracted_type_sim":     random.choice([
            "service_account_plaintext",
            "machine_account_hash",
            "autologon_credentials",
            "vpn_credentials",
        ]),
        "mimikatz_cmd_sim":       "lsadump::secrets",
        "detection_note":         (
            f"'{tool}' (from '{src_proc}') accessing LSA secrets at "
            f"'{secret_key}'. LSA secrets contain service account passwords, "
            f"machine account hashes, and cached credentials. "
            f"Non-SYSTEM processes reading SECURITY\\Policy\\Secrets is anomalous."
        ),
    })
    _log_event(event)
    return event


# ── Phase 5: Cached domain credentials ───────────────────────────────────────
# Extract NL$KM / cached logon hashes from SECURITY hive
# Detection: access to NL$KM registry key, offline hash cracking attempt

def _phase_cached_creds(session_id: str) -> dict:
    src_proc = random.choice(FAKE_PROCESS_NAMES)
    count    = random.randint(5, 25)

    event = _base_event(
        session_id,
        mitre=["T1003", "T1003.005"],
        behavior="cached_domain_cred_extraction_sim",
        opps=[
            "nl_km_registry_key_access_sim",
            "security_hive_cache_key_read_sim",
            "dcc2_hash_format_detected_sim",
            "offline_domain_cache_extraction_sim",
        ],
        phase="cached_creds",
    )
    event.update({
        "source_process_sim":     src_proc,
        "registry_key_sim":       r"HKLM\SECURITY\Cache\NL$KM",
        "cached_entry_count_sim": count,
        "hash_format_sim":        "DCC2 (Domain Cached Credentials v2)",
        "crack_difficulty_sim":   "high — DCC2 is slow to crack but offline",
        "tool_sim":               "impacket-secretsdump / cachedump [SIM]",
        "detection_note":         (
            f"Cached domain credential extraction — {count} DCC2 hashes [SIM]. "
            f"Cached creds enable offline cracking when DC is unreachable. "
            f"Alert: SECURITY\\Cache\\NL$KM access by non-winlogon process."
        ),
    })
    _log_event(event)
    return event


# ── Phase 6: Credential files sweep ──────────────────────────────────────────
# Search filesystem for credential files, browser stored passwords, SSH keys
# Detection: rapid enumeration of known credential file paths,
#            browser profile database access, .ssh directory reads

def _phase_credential_files(session_id: str) -> dict:
    src_proc = random.choice(FAKE_PROCESS_NAMES)
    cred_paths = [
        r"C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\logins.json",
        r"C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Login Data",
        r"C:\Users\*\.ssh\id_rsa",
        r"C:\Users\*\Documents\*password*.txt",
        r"/home/*/.ssh/id_rsa",
        r"/home/*/.aws/credentials",
        r"/root/.ssh/authorized_keys",
    ]

    event = _base_event(
        session_id,
        mitre=["T1552", "T1552.001", "T1555"],
        behavior="credential_file_sweep_sim",
        opps=[
            "browser_credential_db_access_sim",
            "ssh_private_key_file_read_sim",
            "plaintext_credential_file_enumeration_sim",
            "aws_credential_file_access_sim",
            "rapid_sensitive_path_enumeration_sim",
        ],
        phase="credential_files",
    )
    event.update({
        "source_process_sim":     src_proc,
        "paths_searched_sim":     cred_paths,
        "hits_sim":               random.randint(2, 8),
        "browser_dbs_sim":        ["Firefox logins.json [SIM]", "Chrome Login Data [SIM]"],
        "ssh_keys_sim":           ["/home/user/.ssh/id_rsa [SIM]"],
        "cloud_creds_sim":        ["/home/user/.aws/credentials [SIM]"],
        "detection_note":         (
            f"'{src_proc}' rapidly enumerating known credential file paths. "
            f"Browser credential DB access + SSH key reads within same session. "
            f"Alert: non-browser process opening Chrome/Firefox credential stores, "
            f"rapid access to multiple .ssh directories."
        ),
    })
    _log_event(event)
    return event


# ── Layer registration ─────────────────────────────────────────────────────────

@register_payload("credential_harvest_sim")
def main():
    session_id = str(uuid.uuid4())
    events     = []

    phases = [
        ("lsass_dump",        _phase_lsass_dump),
        ("sam_dump",          _phase_sam_dump),
        ("ntds_extraction",   _phase_ntds_extraction),
        ("lsa_secrets",       _phase_lsa_secrets),
        ("cached_creds",      _phase_cached_creds),
        ("credential_files",  _phase_credential_files),
    ]

    print(f"\n  [SIMULATION]  credential_harvest_sim")
    print(f"  [SESSION]     {session_id}")
    print(f"  [EVENTS]      {len(phases)}")
    print(f"  [MITRE]       T1003, T1003.001, T1003.002, T1003.003, T1003.004, T1003.005, T1552, T1552.001, T1555")
    print(f"  [SUBPROCESS]  NOT CALLED — synthetic only")
    print(f"  [NETWORK]     NO CALLS MADE — synthetic only")
    print(f"  [CREDENTIALS] NO REAL CREDENTIAL ACCESS — simulation only")
    print()

    for phase_name, phase_fn in phases:
        event  = phase_fn(session_id)
        events.append(event)
        print(f"  [PHASE: {phase_name}]")
        print(f"    behavior      : {event['behavior_class']}")
        print(f"    mitre         : {', '.join(event['mitre_techniques'])}")
        print(f"    detection     : {event['detection_opportunities'][0]}")
        print(f"    note          : {event.get('detection_note','')[:80]}")
        print()

    log_path = _get_artifact_log()
    print(f"  [LOGGED]      {log_path}")
    print(f"  [SAFE]        no subprocess calls, no network, no real credential access — simulation only")

    return events
