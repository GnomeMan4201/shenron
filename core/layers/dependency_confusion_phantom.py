"""
SHENRON Simulation Layer: dependency_confusion_phantom
Category: payload
Phase: supply_chain_infiltration
ATT&CK: T1195.001 (Supply Chain Compromise: Compromise Software Dependencies)
        T1059.007 (Command and Scripting Interpreter: JavaScript)
        T1071.001 (Application Layer Protocol: Web Protocols)
        T1036.005 (Masquerading: Match Legitimate Name or Location)
        T1082     (System Information Discovery)
        T1552.001 (Unsecured Credentials: Credentials In Files)

Behavioral model sourced from:
- Microsoft Threat Intelligence, May 2026 (33 malicious npm packages campaign)
- badBANANA Research Collective INV-004/INV-005 investigation patterns

Safety contract:
  simulation_only: true
  executable: false
  no_payload_present: true
  network_calls_made: false
  processes_spawned: false
  npm_registry_calls_made: false
  files_written_outside_log_dir: false

Observable adversarial behavior, not portable adversarial procedure.
"""

from core.engine.payload_registry import register_payload

import uuid
import time
import random
from datetime import datetime, timezone


LAYER_META = {
    "layer": "dependency_confusion_phantom",
    "category": "payload",
    "subcategory": "supply_chain",
    "phase": "supply_chain_infiltration",
    "mitre_techniques": [
        "T1195.001",
        "T1059.007",
        "T1071.001",
        "T1036.005",
        "T1082",
        "T1552.001",
    ],
    "mitre_labels": [
        "T1195.001 — Supply Chain Compromise: Compromise Software Dependencies",
        "T1059.007 — Command and Scripting Interpreter: JavaScript",
        "T1071.001 — Application Layer Protocol: Web Protocols",
        "T1036.005 — Masquerading: Match Legitimate Name or Location",
        "T1082     — System Information Discovery",
        "T1552.001 — Unsecured Credentials: Credentials In Files",
    ],
    "detection_opportunities": [
        "npm_postinstall_script_execution",
        "inflated_version_number",
        "spoofed_package_metadata",
        "namespace_squatting",
        "obfuscated_postinstall_js",
        "outbound_connection_during_npm_install",
        "payload_dropped_to_tmpdir",
        "detached_child_process_from_npm",
        "ci_environment_detection_attempt",
        "cache_dedup_directory_creation",
        "environment_variable_enumeration",
        "hardcoded_auth_header_in_outbound_request",
        "recon_only_flag_in_spawned_process",
        "project_root_traversal",
    ],
    "alert_signatures": [
        "postinstall hook in package.json from unrecognized scoped package",
        "npm package version >= 99.0.0 from public registry matching internal scope name",
        "outbound HTTPS connection from node process during npm install",
        "JS file dropped to os.tmpdir() by npm lifecycle script",
        "detached child process spawned with .unref() from npm install",
        "X-Secret header in outbound HTTP request from Node.js process",
        "~/.cache/._<scope>_init/ directory created during package install",
        "environment variable enumeration (PATH, HOME, CI, npm_*) from postinstall context",
    ],
    "log_sources": [
        "process (npm/node lifecycle events)",
        "network (outbound connections during install)",
        "filesystem (tmpdir writes, cache dir creation)",
        "npm audit log",
        "package-lock.json / yarn.lock delta",
    ],
    "simulation_only": True,
    "executable": False,
    "no_payload_present": True,
    "network_calls_made": False,
    "processes_spawned": False,
    "npm_registry_calls_made": False,
    "files_written_outside_log_dir": False,
}


# ── Synthetic data pools ───────────────────────────────────────────────────────

_SCOPES = [
    "@cloudplatform-infra",
    "@payments-core",
    "@data-platform",
    "@auth-services",
    "@internal-sdk",
    "@enterprise-tools",
]

_PACKAGE_NAMES = [
    "shared-front", "monitoring", "ssh-keys", "enterprise",
    "api-gateway", "auth-token", "ui-kit", "logging-service",
    "dataplatform-core", "security-groups",
]

_MAINTAINER_PATTERNS = [
    {"alias": "mr.researcher", "email_domain": "yandex.ru"},
    {"alias": "ce-dev", "email_domain": "proton.me"},
    {"alias": "platform-tools", "email_domain": "gmail.com"},
]

_INFLATED_VERSIONS = ["99.99.99", "100.100.100", "99.0.7", "3.5.22", "5.7.1"]

_C2_PATTERNS = [
    {"host": "oob.metrics-cdn.tech", "path": "/payload"},
    {"host": "npm-telemetry.io", "path": "/init"},
    {"host": "pkg-analytics.net", "path": "/collect"},
]


def _base_event(phase, behavior_class, artifact_id):
    return {
        "artifact_id": artifact_id,
        "layer": LAYER_META["layer"],
        "category": LAYER_META["category"],
        "subcategory": LAYER_META["subcategory"],
        "phase": phase,
        "behavior_class": behavior_class,
        "mitre_techniques": LAYER_META["mitre_techniques"],
        "detection_opportunities": LAYER_META["detection_opportunities"],
        "simulation_only": True,
        "executable": False,
        "timestamp_sim": datetime.now(timezone.utc).isoformat(),
    }


# ── Phase 1 — Package publication lure ────────────────────────────────────────
# Namespace squatting + spoofed metadata + inflated version number.
# Observable: package registry anomaly, version number spike, metadata mismatch.
# ──────────────────────────────────────────────────────────────────────────────
def phase_package_lure(artifact_id):
    events = []
    scope = random.choice(_SCOPES)
    pkg = random.choice(_PACKAGE_NAMES)
    version = random.choice(_INFLATED_VERSIONS)
    maintainer = random.choice(_MAINTAINER_PATTERNS)
    c2 = random.choice(_C2_PATTERNS)
    scope_clean = scope.lstrip("@").replace("/", "-")

    events.append({
        **_base_event("package_lure", "namespace_squatting", artifact_id),
        "detail": {
            "package_sim": f"{scope}/{pkg}",
            "version_sim": version,
            "maintainer_alias_sim": maintainer["alias"],
            "maintainer_email_sim": f"{maintainer['alias']}@{maintainer['email_domain']}",
            "spoofed_metadata_sim": {
                "repository": f"git+https://github.{scope_clean}.io/platform/{pkg}.git",
                "homepage": f"https://docs.{scope_clean}.io/platform/{pkg}",
                "bugs": f"https://jira.{scope_clean}.io/projects/PLATFORM",
                "author": f"{scope_clean} Platform Engineering <platform@{scope_clean}.io>",
            },
            "detection_signal": "inflated_version_number",
            "detection_signal_2": "spoofed_package_metadata",
            "note": (
                f"Version {version} wins npm dependency resolution over any real internal "
                f"package version. Spoofed metadata mimics enterprise GitHub/Jira/docs "
                f"infrastructure to pass casual code review."
            ),
        },
    })

    events.append({
        **_base_event("package_lure", "postinstall_hook_declared", artifact_id),
        "detail": {
            "package_sim": f"{scope}/{pkg}",
            "scripts_block_sim": {
                "build": "tsc --noEmit || true",
                "test": "node test/index.test.js",
                "postinstall": "node scripts/postinstall.js",
                "prepublishOnly": "echo 'Building...'",
            },
            "c2_host_sim": c2["host"],
            "stager_size_kb_sim": round(random.uniform(6.5, 14.0), 1),
            "obfuscation_technique_sim": "obfuscator.io-style: string array encoding + control flow flattening + dead code injection",
            "detection_signal": "npm_postinstall_script_execution",
            "note": (
                "postinstall executes automatically on every `npm install`. "
                "build/test scripts are cosmetic — designed to signal legitimate dev workflow."
            ),
        },
    })

    return events


# ── Phase 2 — CI/CD detection and evasion ─────────────────────────────────────
# Stager checks for CI env vars and aborts silently if detected.
# Observable: environment variable enumeration from postinstall context.
# ──────────────────────────────────────────────────────────────────────────────
def phase_ci_evasion(artifact_id):
    events = []
    scope = random.choice(_SCOPES)
    scope_clean = scope.lstrip("@").replace("/", "-").upper().replace("-", "_")

    events.append({
        **_base_event("ci_evasion", "ci_environment_detection", artifact_id),
        "detail": {
            "env_vars_checked_sim": [
                "CI",
                "CONTINUOUS_INTEGRATION",
                "GITHUB_ACTIONS",
                "GITLAB_CI",
                "CIRCLECI",
                f"{scope_clean}_NO_TELEMETRY",
            ],
            "node_version_check_sim": ">= 16.0",
            "behavior_on_ci_detected_sim": "silent abort — no network call made",
            "detection_signal": "ci_environment_detection_attempt",
            "stealth_note": (
                "CI abort reduces noise in monitored pipelines where security tooling "
                "is more likely to alert on anomalous network activity. "
                "The kill switch env var mimics legitimate telemetry opt-out patterns."
            ),
        },
    })

    return events


# ── Phase 3 — Cache deduplication ─────────────────────────────────────────────
# Stager creates ~/.cache/._<scope>_init/ to avoid re-running on repeat installs.
# Observable: unexpected cache directory creation during npm install.
# ──────────────────────────────────────────────────────────────────────────────
def phase_cache_dedup(artifact_id):
    events = []
    scope = random.choice(_SCOPES)
    scope_clean = scope.lstrip("@")

    events.append({
        **_base_event("cache_dedup", "cache_directory_creation", artifact_id),
        "detail": {
            "cache_dir_sim": f"~/.cache/._{scope_clean}_init/",
            "cache_key_components_sim": ["package_name", "version", "project_root_hash"],
            "expiry_behavior_sim": "exits if cache entry exists and not expired",
            "detection_signal": "cache_dedup_directory_creation",
            "note": (
                "Prevents payload re-execution on every npm install in same project. "
                "Reduces repeated outbound connections that would trigger anomaly detection. "
                "Pattern: ._<scope>_init/ in ~/.cache/ is a high-fidelity IOC."
            ),
        },
    })

    return events


# ── Phase 4 — Project root traversal ──────────────────────────────────────────
# Stager walks up directory tree to find project root for context collection.
# Observable: unexpected filesystem traversal from npm lifecycle script.
# ──────────────────────────────────────────────────────────────────────────────
def phase_project_traversal(artifact_id):
    events = []

    events.append({
        **_base_event("project_traversal", "project_root_traversal", artifact_id),
        "detail": {
            "traversal_anchors_sim": ["package.json", "yarn.lock", ".git"],
            "traversal_direction_sim": "upward from process.cwd()",
            "data_collected_sim": [
                "project_root_path",
                "presence_of_yarn_lock",
                "presence_of_git_directory",
            ],
            "detection_signal": "project_root_traversal",
            "note": (
                "Project root incorporated into cache key and passed to payload. "
                "Presence of .git signals developer workstation vs CI — "
                "high-value target discrimination."
            ),
        },
    })

    return events


# ── Phase 5 — C2 callback and payload drop ────────────────────────────────────
# Outbound HTTPS GET to C2, platform-specific payload download, tmpdir drop.
# Observable: outbound connection from node process, file write to tmpdir.
# ──────────────────────────────────────────────────────────────────────────────
def phase_c2_and_drop(artifact_id):
    events = []
    c2 = random.choice(_C2_PATTERNS)
    platform = random.choice(["win", "mac", "linux"])
    scope = random.choice(_SCOPES)
    scope_clean = scope.lstrip("@")
    secret_header = f"X-Secret: {''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=32))}"

    events.append({
        **_base_event("c2_callback", "outbound_connection_during_npm_install", artifact_id),
        "detail": {
            "c2_url_sim": f"https://{c2['host']}{c2['path']}/{platform}",
            "platform_detected_sim": platform,
            "request_headers_sim": {
                "X-Secret": secret_header.split(": ")[1],
                "X-Pkg": f"{scope}/monitoring",
                "X-Ver": random.choice(_INFLATED_VERSIONS),
            },
            "timeout_ms_sim": 30000,
            "detection_signal": "outbound_connection_during_npm_install",
            "detection_signal_2": "hardcoded_auth_header_in_outbound_request",
            "note": (
                "X-Secret is hardcoded and identical across all packages in a cluster — "
                "single-operator attribution marker. "
                "Connection initiated silently during npm install with no user prompt."
            ),
        },
    })

    events.append({
        **_base_event("c2_callback", "payload_dropped_to_tmpdir", artifact_id),
        "detail": {
            "drop_path_sim": f"/tmp/._{scope_clean}_init.js",
            "drop_pattern_sim": f"._<scope>_init.js in os.tmpdir()",
            "spawn_method_sim": "child_process.spawn() with detached: true and .unref()",
            "detection_signal": "payload_dropped_to_tmpdir",
            "detection_signal_2": "detached_child_process_from_npm",
            "note": (
                "Detached spawn with .unref() allows payload to outlive npm install process. "
                "File pattern ._<scope>_init.js in tmpdir is high-fidelity IOC — "
                "no legitimate npm package writes to tmpdir with this naming pattern."
            ),
        },
    })

    return events


# ── Phase 6 — Reconnaissance payload ─────────────────────────────────────────
# Two-phase design: RECON_ONLY=1 now, full exploitation toggled server-side.
# Observable: env var enumeration, system info collection, credential file access.
# ──────────────────────────────────────────────────────────────────────────────
def phase_recon(artifact_id):
    events = []
    scope = random.choice(_SCOPES)
    scope_clean = scope.lstrip("@").upper().replace("-", "_").replace("/", "_")

    events.append({
        **_base_event("recon", "environment_variable_enumeration", artifact_id),
        "detail": {
            "env_vars_collected_sim": [
                "PATH", "HOME", "USER", "HOSTNAME",
                "npm_config_registry", "npm_config_userconfig",
                "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                "GITHUB_TOKEN", "NPM_TOKEN",
                "CI", "GITHUB_ACTIONS", "GITLAB_CI",
            ],
            "recon_flag_sim": f"{scope_clean}_RECON_ONLY=1",
            "two_phase_design_sim": {
                "current_mode": "RECON_ONLY — environment fingerprinting and credential reconnaissance",
                "follow_on_capability": "RECON_ONLY can be toggled server-side for full exploitation",
            },
            "detection_signal": "environment_variable_enumeration",
            "detection_signal_2": "recon_only_flag_in_spawned_process",
            "stealth_note": (
                "RECON_ONLY minimizes detection risk during initial deployment. "
                "Builds target inventory for selective high-value exploitation later. "
                "AWS/GitHub/npm token enumeration confirms credential-theft as follow-on goal."
            ),
        },
    })

    events.append({
        **_base_event("recon", "system_information_discovery", artifact_id),
        "detail": {
            "data_collected_sim": [
                "os.hostname()",
                "os.platform()",
                "os.arch()",
                "os.homedir()",
                "process.versions.node",
                "installed package list (package.json walk)",
                "project root path",
            ],
            "exfil_method_sim": "HTTPS POST to C2 with collected data as JSON body",
            "detection_signal": "environment_variable_enumeration",
            "note": (
                "System fingerprint enables selective targeting — attacker identifies "
                "high-value developer workstations vs disposable CI runners."
            ),
        },
    })

    return events


# ── Layer runner ───────────────────────────────────────────────────────────────

def _get_artifact_log():
    from core.config import artifact_log_path as _artifact_log_path
    p = _artifact_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


@register_payload(name="dependency_confusion_phantom")
def run(dry_run=False):
    artifact_id = str(uuid.uuid4())
    events = []

    phases = [
        ("package_lure",        phase_package_lure),
        ("ci_evasion",          phase_ci_evasion),
        ("cache_dedup",         phase_cache_dedup),
        ("project_traversal",   phase_project_traversal),
        ("c2_and_drop",         phase_c2_and_drop),
        ("recon",               phase_recon),
    ]

    for phase_name, phase_fn in phases:
        phase_events = phase_fn(artifact_id)
        events.extend(phase_events)
        if not dry_run:
            time.sleep(round(random.uniform(0.01, 0.04), 3))

    if not dry_run:
        log_path = _get_artifact_log()
        with open(log_path, "a") as f:
            for ev in events:
                f.write(__import__("json").dumps(ev) + "\n")

        print(f"  [SIMULATION]  dependency_confusion_phantom")
        print(f"  [SESSION]     {artifact_id}")
        print(f"  [EVENTS]      {len(events)}")
        print(f"  [MITRE]       {', '.join(LAYER_META['mitre_techniques'])}")
        print(f"  [NETWORK]     NO CALLS MADE — synthetic only")
        print(f"  [EXECUTION]   NO SHELL COMMANDS — synthetic only")
        print(f"  [LOGGED]      {log_path}")
        print(f"  [SAFE]        simulation_only=True, executable=False")

    return {
        "layer": LAYER_META["layer"],
        "artifact_id": artifact_id,
        "event_count": len(events),
        "events": events,
        "meta": LAYER_META,
        "safety_contract": {
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "network_calls_made": False,
            "processes_spawned": False,
            "npm_registry_calls_made": False,
            "files_written_outside_log_dir": False,
        },
    }


if __name__ == "__main__":
    import json
    result = run(dry_run=True)
    print(json.dumps(result, indent=2))
