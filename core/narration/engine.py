#!/usr/bin/env python3
# SHENRON: Defensive narration engine
# Converts CompareReport data into analyst-quality plain-English defensive prose.
# Deterministic, template-based, no LLM required.
# No subprocess, no network, no execution.

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# ── Tactic family taxonomy ────────────────────────────────────────────────────
# Maps tactic family name → human description for use in prose

TACTIC_FAMILIES = {
    "command-and-control": {
        "label":       "Command-and-Control",
        "short":       "C2",
        "description": "periodic beaconing, encoded C2 traffic, DNS-based signaling, "
                       "and protocol tunneling shapes",
        "analyst_concern": (
            "If C2-shaped telemetry is not in your validation set, your detectors "
            "have not been tested against the phase where most APT campaigns are "
            "first visible — initial callback after compromise."
        ),
    },
    "lateral-movement": {
        "label":       "Lateral Movement",
        "short":       "lateral",
        "description": "subnet sweeping, SMB probing, share enumeration, "
                       "and remote service connection shapes",
        "analyst_concern": (
            "Lateral movement is frequently the highest-value detection opportunity "
            "in a real incident. Validators that skip it are testing for post-pivot "
            "behavior without testing the pivot itself."
        ),
    },
    "discovery": {
        "label":       "Discovery",
        "short":       "discovery",
        "description": "network service scanning, share enumeration, "
                       "and internal host mapping shapes",
        "analyst_concern": (
            "Discovery signals often precede lateral movement. Missing them in "
            "validation means the detection stack has not been tested against "
            "the reconnaissance phase that typically follows initial access."
        ),
    },
    "defense-evasion": {
        "label":       "Defense Evasion",
        "short":       "evasion",
        "description": "log deletion, timestamp manipulation, process masquerading, "
                       "command-line spoofing, and indicator removal shapes",
        "analyst_concern": (
            "Evasion-shaped telemetry is the most commonly missed validation gap. "
            "Detection rules that fire on clean telemetry may not fire when the "
            "same behavior is preceded by log clearing or timestamp rollback."
        ),
    },
    "persistence": {
        "label":       "Persistence",
        "short":       "persistence",
        "description": "scheduled task installation, service creation, registry "
                       "modification, hidden directory creation, and process "
                       "injection shapes",
        "analyst_concern": (
            "Persistence validation is the most common starting point for detection "
            "engineering. It is necessary but not sufficient — most campaigns "
            "establish C2 and perform reconnaissance before persistence."
        ),
    },
    "privilege-escalation": {
        "label":       "Privilege Escalation",
        "short":       "privesc",
        "description": "token impersonation, process injection for privilege gain, "
                       "and access token manipulation shapes",
        "analyst_concern": (
            "Privilege escalation signals often co-occur with persistence. "
            "Validating one without the other can create blind spots in "
            "correlation rules that expect both."
        ),
    },
    "exfiltration": {
        "label":       "Exfiltration",
        "short":       "exfil",
        "description": "data staging, encoded transfer, and covert channel shapes",
        "analyst_concern": (
            "Exfiltration is typically the final phase of a campaign. Validators "
            "that cover exfil but not the preceding phases may be testing the "
            "least detectable stage of an adversary's operation."
        ),
    },
    "execution": {
        "label":       "Execution",
        "short":       "execution",
        "description": "scripting interpreter invocation, command execution, "
                       "and process spawning shapes",
        "analyst_concern": (
            "Execution-shaped telemetry underlies most other tactic families. "
            "Missing it means correlated detection rules may not have been "
            "tested against their foundational trigger conditions."
        ),
    },
}

# ── Signal → tactic family mapping ───────────────────────────────────────────
# Maps signal names (from SHENRON artifacts) to tactic families and descriptions.

SIGNAL_TAXONOMY: Dict[str, dict] = {
    # Command-and-control
    "periodic_outbound_connection":    {"family": "command-and-control", "label": "periodic C2 beaconing"},
    "periodic_beacon":                 {"family": "command-and-control", "label": "periodic C2 beaconing"},
    "multi_interface_beacon":          {"family": "command-and-control", "label": "multi-interface C2 beacon"},
    "beacon_interval_pattern":         {"family": "command-and-control", "label": "beacon interval pattern"},
    "covert_channel_traffic":          {"family": "command-and-control", "label": "covert channel traffic"},
    "covert_channel_shape":            {"family": "command-and-control", "label": "covert channel shape"},
    "dns_subdomain_query":             {"family": "command-and-control", "label": "DNS-based C2 signaling"},
    "dns_burst":                       {"family": "command-and-control", "label": "DNS query burst"},
    "high_entropy_dns_labels":         {"family": "command-and-control", "label": "high-entropy DNS labels"},
    "encoded_uri_parameter":           {"family": "command-and-control", "label": "encoded URI C2 parameter"},
    "encoded_packet_sequence":         {"family": "command-and-control", "label": "encoded packet sequence"},
    "encapsulated_protocol_traffic":   {"family": "command-and-control", "label": "protocol encapsulation"},
    "non_standard_protocol":           {"family": "command-and-control", "label": "non-standard protocol C2"},
    "relay_no_app_logic":              {"family": "command-and-control", "label": "relay-only C2 proxy"},
    "thread_per_connection":           {"family": "command-and-control", "label": "thread-per-connection C2"},
    "tls_fingerprint_mismatch":        {"family": "command-and-control", "label": "TLS fingerprint anomaly"},
    "tls_ja3_shape":                   {"family": "command-and-control", "label": "TLS JA3 fingerprint shape"},
    "signal_clone":                    {"family": "command-and-control", "label": "signal clone"},
    "signal_clone_across_interfaces":  {"family": "command-and-control", "label": "cross-interface signal clone"},
    "web_service_c2":                  {"family": "command-and-control", "label": "web service C2"},
    "persistent_listener_nonstandard_port": {"family": "command-and-control", "label": "persistent listener on non-standard port"},

    # Lateral movement
    "subnet_sweep":                    {"family": "lateral-movement", "label": "subnet sweep"},
    "sequential_host_requests":        {"family": "lateral-movement", "label": "sequential host probing"},
    "smb_port_probe":                  {"family": "lateral-movement", "label": "SMB port probing"},
    "share_enumeration":               {"family": "lateral-movement", "label": "network share enumeration"},
    "lan_sweep":                       {"family": "lateral-movement", "label": "LAN sweep"},
    "multi_vector_probe":              {"family": "lateral-movement", "label": "multi-vector lateral probe"},
    "lateral_probe_shape":             {"family": "lateral-movement", "label": "lateral probe shape"},
    "rdp_lateral_signal":              {"family": "lateral-movement", "label": "RDP lateral movement"},
    "net_share_signal":                {"family": "lateral-movement", "label": "network share signal"},

    # Discovery
    "env_enum_signal":                 {"family": "discovery", "label": "environment enumeration"},
    "recursive_home_traversal":        {"family": "discovery", "label": "recursive home directory traversal"},
    "recursive_home_walk_non_backup":  {"family": "discovery", "label": "recursive home walk (non-backup)"},

    # Defense evasion
    "fake_cmdline":                    {"family": "defense-evasion", "label": "command-line spoofing"},
    "pid_masquerade":                  {"family": "defense-evasion", "label": "PID masquerading"},
    "process_name_spoof":              {"family": "defense-evasion", "label": "process name spoofing"},
    "identity_mismatch":               {"family": "defense-evasion", "label": "process identity mismatch"},
    "history_truncated":               {"family": "defense-evasion", "label": "shell history truncation"},
    "log_file_cleared":                {"family": "defense-evasion", "label": "log file clearing"},
    "mtime_spoof":                     {"family": "defense-evasion", "label": "file modification time spoofing"},
    "timestamp_rollback":              {"family": "defense-evasion", "label": "timestamp rollback"},
    "timestamp_modification":          {"family": "defense-evasion", "label": "timestamp modification"},
    "timestamp_rollback_signal":       {"family": "defense-evasion", "label": "timestamp rollback"},
    "entropy_spike":                   {"family": "defense-evasion", "label": "entropy spike (obfuscation)"},
    "obfuscation_pattern":             {"family": "defense-evasion", "label": "obfuscation pattern"},
    "anti_debug_signal":               {"family": "defense-evasion", "label": "anti-debug signal"},
    "sandbox_detect_signal":           {"family": "defense-evasion", "label": "sandbox detection"},
    "evasion_layer_sim":               {"family": "defense-evasion", "label": "evasion layer simulation"},
    "defensive_impair_signal":         {"family": "defense-evasion", "label": "defensive impairment signal"},
    "mimic_scripts_generated_shenron_cache": {"family": "defense-evasion", "label": "script cache mimicry"},
    "script_files_cached_hidden_dotdir":     {"family": "defense-evasion", "label": "scripts in hidden dot directory"},
    "fake_log_event":                  {"family": "defense-evasion", "label": "fake log event injection"},
    "log_source_spoof":                {"family": "defense-evasion", "label": "log source spoofing"},
    "event_injection":                 {"family": "defense-evasion", "label": "event log injection"},

    # Persistence
    "scheduled_task_creation":         {"family": "persistence", "label": "scheduled task creation"},
    "task_sched_signal":               {"family": "persistence", "label": "scheduled task signal"},
    "service_install_signal":          {"family": "persistence", "label": "service installation"},
    "reg_run_key_signal":              {"family": "persistence", "label": "registry run key modification"},
    "startup_persist_signal":          {"family": "persistence", "label": "startup folder persistence"},
    "hidden_temp_directory":           {"family": "persistence", "label": "hidden temporary directory"},
    "artifact_cleanup":                {"family": "persistence", "label": "artifact cleanup (anti-forensics/persistence)"},
    "seed_drop_attempt":               {"family": "persistence", "label": "payload seed drop"},
    "state_file_round_counter_hidden_dotpath": {"family": "persistence", "label": "hidden state file"},
    "script_file_append":              {"family": "persistence", "label": "script file modification"},
    "unauthorized_file_copy":          {"family": "persistence", "label": "unauthorized file copy"},

    # Privilege escalation / execution
    "process_injection_attempt":       {"family": "privilege-escalation", "label": "process injection attempt"},
    "process_revival":                 {"family": "privilege-escalation", "label": "process revival"},
    "signal_handler_modification":     {"family": "privilege-escalation", "label": "signal handler modification"},
    "sandboxed_command_execution":     {"family": "execution", "label": "sandboxed command execution"},
    "wmi_exec_signal":                 {"family": "execution", "label": "WMI execution shape"},
    "ps_invocation_signal":            {"family": "execution", "label": "PowerShell invocation shape"},
    "dll_load_signal":                 {"family": "execution", "label": "DLL load order shape"},
    "proc_mem_access":                 {"family": "privilege-escalation", "label": "process memory access"},
    "rwx_region_write":                {"family": "privilege-escalation", "label": "RWX region write"},
    "token_impersonation":             {"family": "privilege-escalation", "label": "token impersonation"},
    "subprocess_popen_chain_on_state": {"family": "execution", "label": "subprocess chain on state"},
    "execution_logged":                {"family": "execution", "label": "execution logged"},
    "layer_load_logged":               {"family": "execution", "label": "layer load logged"},

    # Exfiltration
    "exfil_volume_shape":              {"family": "exfiltration", "label": "exfiltration volume shape"},
    "staged_loader_signal":            {"family": "exfiltration", "label": "staged loader signal"},
}

# ── MITRE → tactic family mapping ────────────────────────────────────────────

MITRE_TAXONOMY: Dict[str, dict] = {
    # C2
    "T1071":  {"family": "command-and-control", "name": "Application Layer Protocol"},
    "T1072":  {"family": "command-and-control", "name": "Software Deployment Tools"},
    "T1090":  {"family": "command-and-control", "name": "Proxy"},
    "T1095":  {"family": "command-and-control", "name": "Non-Application Layer Protocol"},
    "T1102":  {"family": "command-and-control", "name": "Web Service"},
    "T1132":  {"family": "command-and-control", "name": "Data Encoding"},
    "T1572":  {"family": "command-and-control", "name": "Protocol Tunneling"},
    "T1573":  {"family": "command-and-control", "name": "Encrypted Channel"},
    "T1001":  {"family": "command-and-control", "name": "Data Obfuscation"},
    # Lateral movement
    "T1021":  {"family": "lateral-movement",    "name": "Remote Services"},
    "T1570":  {"family": "lateral-movement",    "name": "Lateral Tool Transfer"},
    # Discovery
    "T1046":  {"family": "discovery",           "name": "Network Service Discovery"},
    "T1135":  {"family": "discovery",           "name": "Network Share Discovery"},
    "T1119":  {"family": "discovery",           "name": "Automated Collection"},
    # Defense evasion
    "T1014":  {"family": "defense-evasion",     "name": "Rootkit"},
    "T1027":  {"family": "defense-evasion",     "name": "Obfuscated Files or Information"},
    "T1036":  {"family": "defense-evasion",     "name": "Masquerading"},
    "T1070":  {"family": "defense-evasion",     "name": "Indicator Removal"},
    "T1107":  {"family": "defense-evasion",     "name": "File Deletion"},
    "T1140":  {"family": "defense-evasion",     "name": "Deobfuscate/Decode Files"},
    "T1564":  {"family": "defense-evasion",     "name": "Hide Artifacts"},
    "T1620":  {"family": "defense-evasion",     "name": "Reflective Code Loading"},
    # Persistence
    "T1053":  {"family": "persistence",         "name": "Scheduled Task/Job"},
    "T1078":  {"family": "persistence",         "name": "Valid Accounts"},
    "T1105":  {"family": "persistence",         "name": "Ingress Tool Transfer"},
    "T1542":  {"family": "persistence",         "name": "Pre-OS Boot"},
    "T1543":  {"family": "persistence",         "name": "Create or Modify System Process"},
    "T1547":  {"family": "persistence",         "name": "Boot or Logon Autostart Execution"},
    # Privilege escalation
    "T1055":  {"family": "privilege-escalation","name": "Process Injection"},
    "T1134":  {"family": "privilege-escalation","name": "Access Token Manipulation"},
    # Execution
    "T1059":  {"family": "execution",           "name": "Command and Scripting Interpreter"},
    # Exfiltration
    "T1041":  {"family": "exfiltration",        "name": "Exfiltration Over C2 Channel"},
    "T1048":  {"family": "exfiltration",        "name": "Exfiltration Over Alternative Protocol"},
    # Impact
    "T1485":  {"family": "impact",              "name": "Data Destruction"},
    "T1565":  {"family": "impact",              "name": "Data Manipulation"},
    # Collection
    "T1005":  {"family": "collection",          "name": "Data from Local System"},
}

# Sub-technique inherits parent family
def _resolve_mitre_family(technique_id: str) -> Optional[str]:
    tid = technique_id.strip()
    if tid in MITRE_TAXONOMY:
        return MITRE_TAXONOMY[tid]["family"]
    parent = tid.split(".")[0]
    if parent in MITRE_TAXONOMY:
        return MITRE_TAXONOMY[parent]["family"]
    return None


def _resolve_mitre_name(technique_id: str) -> str:
    tid = technique_id.strip()
    if tid in MITRE_TAXONOMY:
        return MITRE_TAXONOMY[tid]["name"]
    parent = tid.split(".")[0]
    if parent in MITRE_TAXONOMY:
        return MITRE_TAXONOMY[parent]["name"]
    return tid


# ── Profile characterizer ─────────────────────────────────────────────────────

@dataclass
class RunProfile:
    campaign_name:  str
    run_id:         str
    tactic_families: Dict[str, List[str]] = field(default_factory=dict)  # family → [signal labels]
    mitre_families:  Dict[str, List[str]] = field(default_factory=dict)  # family → [technique IDs]
    dominant_family: Optional[str] = None
    breadth:         str = "narrow"  # narrow | moderate | broad


def _classify_signals(signals: List[str]) -> Dict[str, List[str]]:
    """Classify a list of signal names into tactic families."""
    families: Dict[str, List[str]] = {}
    for sig in signals:
        sig_lower = sig.lower().strip()
        meta = SIGNAL_TAXONOMY.get(sig_lower) or SIGNAL_TAXONOMY.get(
            sig_lower.replace("-", "_").replace(" ", "_")
        )
        if meta:
            fam = meta["family"]
            families.setdefault(fam, []).append(meta["label"])
    return families


def _classify_techniques(techniques: List[str]) -> Dict[str, List[str]]:
    """Classify MITRE technique IDs into tactic families."""
    families: Dict[str, List[str]] = {}
    for t in techniques:
        fam = _resolve_mitre_family(t)
        name = _resolve_mitre_name(t)
        if fam:
            families.setdefault(fam, []).append(t)
    return families


def build_profile(
    campaign_name: str,
    run_id: str,
    signals: List[str],
    techniques: List[str],
) -> RunProfile:
    sig_fams  = _classify_signals(signals)
    tech_fams = _classify_techniques(techniques)

    # Merge
    all_fams: Dict[str, List[str]] = {}
    for fam, labels in sig_fams.items():
        all_fams.setdefault(fam, []).extend(labels)
    for fam in tech_fams:
        if fam not in all_fams:
            all_fams[fam] = []

    # Dominant family = most signals
    dominant = max(all_fams, key=lambda f: len(all_fams[f])) if all_fams else None

    n_families = len(all_fams)
    breadth = "broad" if n_families >= 4 else "moderate" if n_families >= 2 else "narrow"

    return RunProfile(
        campaign_name   = campaign_name,
        run_id          = run_id,
        tactic_families = all_fams,
        mitre_families  = tech_fams,
        dominant_family = dominant,
        breadth         = breadth,
    )


def _describe_profile(profile: RunProfile) -> str:
    """Produce a 2-3 sentence plain English description of what a run covers."""
    fams = profile.tactic_families
    if not fams:
        return (
            f"Run {profile.run_id[:8]} ({profile.campaign_name}) produced signals "
            f"that could not be classified into known tactic families."
        )

    fam_labels = [
        TACTIC_FAMILIES[f]["label"]
        for f in fams
        if f in TACTIC_FAMILIES
    ]

    if profile.breadth == "broad":
        breadth_phrase = "a broad tactic coverage profile"
    elif profile.breadth == "moderate":
        breadth_phrase = "a moderate tactic coverage profile"
    else:
        breadth_phrase = "a focused, single-family coverage profile"

    fam_str = _join_list(fam_labels)

    lines = [
        f"Run {profile.run_id[:8]} ({profile.campaign_name}) expresses {breadth_phrase}. "
        f"Its signal vocabulary spans {fam_str}."
    ]

    # Add specifics for dominant family
    if profile.dominant_family and profile.dominant_family in TACTIC_FAMILIES:
        dom = TACTIC_FAMILIES[profile.dominant_family]
        dom_signals = fams.get(profile.dominant_family, [])
        if dom_signals:
            sig_examples = ", ".join(dom_signals[:3])
            if len(dom_signals) > 3:
                sig_examples += f", and {len(dom_signals) - 3} more"
            lines.append(
                f"The strongest signal family is {dom['label']}, "
                f"including: {sig_examples}."
            )

    return " ".join(lines)


# ── Gap narrator ──────────────────────────────────────────────────────────────

def _join_list(items: List[str], conjunction: str = "and") -> str:
    if not items:
        return "nothing"
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} {conjunction} {items[1]}"
    return ", ".join(items[:-1]) + f", {conjunction} {items[-1]}"


def _gap_family_analysis(
    lost_signals:    List[str],
    lost_techniques: List[str],
) -> Dict[str, dict]:
    """
    Identify which tactic families are lost between Run A and Run B.
    Returns a dict of family → {signals, techniques, concern}.
    """
    gaps: Dict[str, dict] = {}

    for sig in lost_signals:
        sig_lower = sig.lower().strip()
        meta = SIGNAL_TAXONOMY.get(sig_lower) or SIGNAL_TAXONOMY.get(
            sig_lower.replace("-", "_").replace(" ", "_")
        )
        if meta:
            fam = meta["family"]
            gaps.setdefault(fam, {"signals": [], "techniques": [], "concern": ""})
            gaps[fam]["signals"].append(meta["label"])

    for t in lost_techniques:
        fam = _resolve_mitre_family(t)
        if fam:
            gaps.setdefault(fam, {"signals": [], "techniques": [], "concern": ""})
            gaps[fam]["techniques"].append(t)

    # Attach concern language
    for fam in gaps:
        if fam in TACTIC_FAMILIES:
            gaps[fam]["concern"] = TACTIC_FAMILIES[fam]["analyst_concern"]

    return gaps


def _scope_boundary_note(profile_a: RunProfile, profile_b: RunProfile) -> str:
    """
    Generate the scope boundary explanation — this is not a failure,
    it is a documented scope difference.
    """
    if profile_a.breadth == "broad" and profile_b.breadth == "narrow":
        return (
            f"This gap is expected if {profile_b.campaign_name} is intentionally "
            f"scoped to {profile_b.dominant_family or 'a specific tactic family'}. "
            f"The concern is not that {profile_b.campaign_name} is incomplete — "
            f"it is if its results are treated as broad adversarial-behavior "
            f"coverage when they are, more precisely, "
            f"{profile_b.dominant_family or 'single-family'} coverage."
        )
    elif profile_a.breadth == "narrow" and profile_b.breadth == "broad":
        return (
            f"Run B ({profile_b.campaign_name}) is broader than Run A. "
            f"This represents a coverage expansion, not a gap. "
            f"The signals lost from Run A are a smaller focused set compared "
            f"to the broader vocabulary introduced in Run B."
        )
    else:
        return (
            f"Both runs represent specific validation scopes. "
            f"Neither is a substitute for the other. "
            f"The gap documents where their signal vocabularies diverge."
        )


def _recommendation(gaps: Dict[str, dict], profile_b: RunProfile) -> str:
    """Produce a concrete next-step recommendation based on the gap families."""
    if not gaps:
        return (
            "No significant tactic family gaps detected. "
            "Consider running a broader scenario to confirm coverage breadth."
        )

    gap_family_labels = [
        TACTIC_FAMILIES[f]["label"]
        for f in gaps
        if f in TACTIC_FAMILIES
    ]

    gap_str = _join_list(gap_family_labels)

    # Suggest a scenario that covers the missing families
    suggestions = []
    families = set(gaps.keys())

    if "command-and-control" in families and "lateral-movement" in families:
        suggestions.append("apt_kill_chain (covers C2, lateral movement, persistence, and evasion)")
    elif "command-and-control" in families:
        suggestions.append("basic_c2_persistence or recon_to_exfil (covers C2 beaconing)")
    elif "lateral-movement" in families or "discovery" in families:
        suggestions.append("basic_c2_persistence (covers subnet sweeping and lateral probing)")
    if "defense-evasion" in families:
        suggestions.append("evasion_stress_test (covers masquerading, log deletion, and anti-forensics)")

    rec = (
        f"To close the {gap_str} gap{'s' if len(gap_family_labels) > 1 else ''}, "
        f"run a scenario that includes those signal families alongside "
        f"{profile_b.campaign_name}."
    )
    if suggestions:
        rec += f" Suggested: {_join_list(suggestions, 'or')}."

    return rec


# ── Main narration assembler ──────────────────────────────────────────────────

def narrate(compare_report) -> str:
    """
    Generate a full defensive narrative from a CompareReport.
    Returns a markdown string.

    compare_report must have fields:
      run_id_a, run_id_b, campaign_a, campaign_b,
      coverage_a, coverage_b, coverage_delta,
      verdict_a, verdict_b,
      gained (list of signal names), lost (list of signal names),
      mitre_a (list), mitre_b (list),
      mitre_lost (list), mitre_gained (list), mitre_retained (list),
      signals (list of SignalDelta with .name and .direction),
      safety_a, safety_b
    """
    r = compare_report

    # Extract signal lists per run from the full signals list
    signals_a = [s.name for s in r.signals if s.status_a in ("PASS", "PARTIAL")]
    signals_b = [s.name for s in r.signals if s.status_b in ("PASS", "PARTIAL")]

    profile_a = build_profile(r.campaign_a, r.run_id_a, signals_a, r.mitre_a)
    profile_b = build_profile(r.campaign_b, r.run_id_b, signals_b, r.mitre_b)

    gaps = _gap_family_analysis(r.lost, r.mitre_lost)

    desc_a = _describe_profile(profile_a)
    desc_b = _describe_profile(profile_b)
    scope_note = _scope_boundary_note(profile_a, profile_b)
    recommendation = _recommendation(gaps, profile_b)

    arrow = "▲" if r.coverage_delta >= 0 else "▼"
    sign  = "+" if r.coverage_delta >= 0 else ""

    lines = [
        "# SHENRON Defensive Narrative",
        "",
        "> **SYNTHETIC TELEMETRY** — This narrative is generated from SHENRON simulation",
        "> run comparisons. It describes signal vocabulary differences, not real",
        "> adversarial execution or confirmed detector efficacy.",
        "",
        "---",
        "",
        "## Run Comparison Summary",
        "",
        f"| | Run A | Run B |",
        f"|---|---|---|",
        f"| Run ID | `{r.run_id_a[:8]}` | `{r.run_id_b[:8]}` |",
        f"| Campaign | `{r.campaign_a}` | `{r.campaign_b}` |",
        f"| Coverage | {r.coverage_a}% | {r.coverage_b}% |",
        f"| Delta | | {arrow} {sign}{r.coverage_delta}% |",
        f"| Verdict | {r.verdict_a} | {r.verdict_b} |",
        f"| Signals lost | {len(r.lost)} | — |",
        f"| Signals gained | — | +{len(r.gained)} |",
        f"| MITRE descriptors | {len(r.mitre_a)} | {len(r.mitre_b)} |",
        f"| Safety failures | {r.safety_a} | {r.safety_b} |",
        "",
        "---",
        "",
        f"## What Run A covers",
        "",
        desc_a,
        "",
    ]

    # List tactic families for A
    if profile_a.tactic_families:
        lines.append("**Signal families observed in Run A:**")
        lines.append("")
        for fam, sig_labels in sorted(profile_a.tactic_families.items()):
            if fam in TACTIC_FAMILIES:
                fam_meta = TACTIC_FAMILIES[fam]
                examples = ", ".join(dict.fromkeys(sig_labels[:3]))
                if len(sig_labels) > 3:
                    examples += f" (+{len(sig_labels)-3} more)"
                lines.append(f"- **{fam_meta['label']}**: {examples}")
        lines.append("")

    lines += [
        f"## What Run B covers",
        "",
        desc_b,
        "",
    ]

    if profile_b.tactic_families:
        lines.append("**Signal families observed in Run B:**")
        lines.append("")
        for fam, sig_labels in sorted(profile_b.tactic_families.items()):
            if fam in TACTIC_FAMILIES:
                fam_meta = TACTIC_FAMILIES[fam]
                examples = ", ".join(dict.fromkeys(sig_labels[:3]))
                if len(sig_labels) > 3:
                    examples += f" (+{len(sig_labels)-3} more)"
                lines.append(f"- **{fam_meta['label']}**: {examples}")
        lines.append("")

    lines += [
        "---",
        "",
        "## The coverage gap",
        "",
    ]

    if not gaps:
        lines += [
            "No significant tactic family gaps were identified between these two runs.",
            "The signal vocabularies are closely aligned.",
            "",
        ]
    else:
        gap_family_labels = [
            TACTIC_FAMILIES[f]["label"]
            for f in gaps
            if f in TACTIC_FAMILIES
        ]
        lines += [
            f"Moving from Run A to Run B removes coverage for "
            f"**{len(r.lost)} signal types** and "
            f"**{len(r.mitre_lost)} MITRE technique descriptors**. "
            f"The missing capability {'families are' if len(gap_family_labels) > 1 else 'family is'}: "
            f"**{_join_list(gap_family_labels)}**.",
            "",
        ]

        for fam, gap_data in sorted(gaps.items()):
            if fam not in TACTIC_FAMILIES:
                continue
            fam_meta = TACTIC_FAMILIES[fam]
            techs = gap_data["techniques"]
            sigs  = gap_data["signals"]

            lines.append(f"### {fam_meta['label']}")
            lines.append("")

            if techs:
                lines.append(
                    f"**MITRE descriptors not present in Run B:** "
                    f"{', '.join(techs)}"
                )
            if sigs:
                sig_str = _join_list(list(dict.fromkeys(sigs[:5])))
                if len(sigs) > 5:
                    sig_str += f", and {len(sigs)-5} more"
                lines.append(
                    f"**Signal shapes absent from Run B:** {sig_str}."
                )

            lines.append("")
            lines.append(fam_meta["description"].capitalize() + " shapes are not "
                         "expressed in Run B's telemetry.")
            lines.append("")
            if gap_data["concern"]:
                lines.append(f"> {gap_data['concern']}")
            lines.append("")

    lines += [
        "---",
        "",
        "## What this means for your detection stack",
        "",
    ]

    if gaps:
        gap_family_labels = [
            TACTIC_FAMILIES[f]["label"]
            for f in gaps
            if f in TACTIC_FAMILIES
        ]
        gap_str = _join_list(gap_family_labels)
        lines += [
            f"A detection stack validated only against Run B "
            f"(`{r.campaign_b}`) has not been tested against "
            f"{gap_str}-shaped telemetry.",
            "",
            scope_note,
            "",
        ]

        # Add signal-level specifics for the most important gap
        primary_gap = next(iter(gaps)) if gaps else None
        if primary_gap and primary_gap in TACTIC_FAMILIES:
            pg = TACTIC_FAMILIES[primary_gap]
            pg_sigs = gaps[primary_gap]["signals"]
            if pg_sigs:
                lines += [
                    f"Concretely, signals such as "
                    f"**{_join_list(list(dict.fromkeys(pg_sigs[:3])))}** "
                    f"were present in Run A and are absent from Run B. "
                    f"Detection rules that depend on these signal shapes "
                    f"have not been exercised by Run B's telemetry.",
                    "",
                ]
    else:
        lines += [
            f"The signal vocabularies of Run A and Run B are closely aligned. "
            f"No significant unvalidated tactic family gaps were identified.",
            "",
        ]

    lines += [
        "---",
        "",
        "## Recommended next step",
        "",
        recommendation,
        "",
        "---",
        "",
        "## What this does not prove",
        "",
        "- That real adversarial techniques were executed in either run",
        "- That real detection rules fired on any of these signals",
        "- That a SIEM or EDR would catch the behaviors described",
        "- That coverage in SHENRON equals coverage in production",
        "- That the recommended scenarios will close gaps in your actual environment",
        "",
        "---",
        "",
        "## Signal inventory",
        "",
        "### Signals present only in Run A (lost in Run B)",
        "",
    ]

    if r.lost:
        for sig in sorted(r.lost):
            meta = SIGNAL_TAXONOMY.get(sig.lower())
            family_label = TACTIC_FAMILIES.get(
                meta["family"], {}
            ).get("label", meta["family"]) if meta else "unclassified"
            lines.append(f"- `{sig}` — {family_label}")
    else:
        lines.append("None.")
    lines.append("")

    lines += [
        "### Signals present only in Run B (gained)",
        "",
    ]
    if r.gained:
        for sig in sorted(r.gained):
            meta = SIGNAL_TAXONOMY.get(sig.lower())
            family_label = TACTIC_FAMILIES.get(
                meta["family"], {}
            ).get("label", meta["family"]) if meta else "unclassified"
            lines.append(f"- `{sig}` — {family_label}")
    else:
        lines.append("None.")
    lines.append("")

    lines += [
        "---",
        "",
        "*SHENRON — Observable adversarial behavior, not portable adversarial procedure.*",
    ]

    return "\n".join(lines)


def print_narrative_summary(compare_report) -> None:
    """Print a compact terminal summary of the narrative."""
    r = compare_report
    gaps = _gap_family_analysis(r.lost, r.mitre_lost)

    gap_labels = [
        TACTIC_FAMILIES[f]["label"]
        for f in gaps
        if f in TACTIC_FAMILIES
    ]

    print()
    print(f"  [NARRATIVE]   {r.campaign_a} → {r.campaign_b}")
    print()

    if gap_labels:
        print(f"  Coverage gap families ({len(gap_labels)}):")
        for label in gap_labels:
            fam_key = next(
                (k for k, v in TACTIC_FAMILIES.items() if v["label"] == label), None
            )
            if fam_key:
                print(f"    ✗  {label}")
        print()
        print(f"  Primary concern:")
        primary = next(iter(gaps))
        if primary in TACTIC_FAMILIES:
            concern = TACTIC_FAMILIES[primary]["analyst_concern"]
            # Wrap at 70 chars
            words = concern.split()
            line, out = [], []
            for w in words:
                if sum(len(x) + 1 for x in line) + len(w) > 68:
                    out.append("    " + " ".join(line))
                    line = [w]
                else:
                    line.append(w)
            if line:
                out.append("    " + " ".join(line))
            for l in out:
                print(l)
    else:
        print(f"  No significant tactic family gaps detected.")
    print()
