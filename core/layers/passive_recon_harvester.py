from core.engine.payload_registry import register_payload
#!/usr/bin/env python3
# SHENRON: Passive Reconnaissance Harvester — pre-attack intelligence gathering simulator
# PURPOSE: Emit defender-observable telemetry for reconnaissance patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1589 (Gather Victim Identity Information),
#        T1589.001 (Credentials), T1589.002 (Email Addresses), T1589.003 (Employee Names),
#        T1590 (Gather Victim Network Information),
#        T1590.001 (Domain Properties), T1590.004 (Network Topology),
#        T1591 (Gather Victim Org Information), T1591.004 (Identify Roles),
#        T1592 (Gather Victim Host Information), T1592.002 (Software),
#        T1593 (Search Open Websites/Domains), T1593.001 (Social Media),
#        T1594 (Search Victim-Owned Websites),
#        T1596 (Search Open Technical Databases), T1596.001 (DNS/Passive DNS),
#        T1596.005 (Scan Databases)
# DETECTION NOTES:
#   - Alert on: passive DNS queries for target domains from unusual sources
#   - Certificate transparency log queries (crt.sh, censys) for org
#   - LinkedIn/social media scraping patterns targeting org employees
#   - Shodan/Censys queries for org IP ranges
#   - WHOIS lookups correlated with later intrusion activity
#   - Job posting scraping — reveals tech stack
# NO SUBPROCESS CALLS — all recon patterns are synthetic
# NO NETWORK CALLS — all queries are synthetic

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


FAKE_ORG_DOMAINS = [
    "target-corp-sim.com", "victim-org-sim.net", "enterprise-target-sim.io"
]
FAKE_EMPLOYEE_NAMES = [
    "John Smith", "Sarah Johnson", "Michael Chen", "Emily Rodriguez",
    "David Kim", "Jessica Wang", "Robert Taylor", "Amanda Martinez"
]
FAKE_EMAIL_PATTERNS = [
    "{first}.{last}@target-corp-sim.com",
    "{first[0]}{last}@target-corp-sim.com",
    "{first}_{last}@target-corp-sim.com"
]
FAKE_IP_RANGES = ["198.51.100.0/24", "203.0.113.0/24", "192.0.2.0/24"]
FAKE_SUBDOMAINS = [
    "mail", "vpn", "remote", "citrix", "webmail", "exchange",
    "portal", "admin", "dev", "staging", "api", "git"
]
FAKE_TECH_STACK = [
    "Microsoft Exchange 2019", "Cisco ASA 9.x", "Juniper SRX",
    "VMware vSphere 7.0", "Confluence 7.x", "Jira 8.x"
]


def _log_event(event: dict):
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(event) + "\n")


def _base_event(session_id, mitre, behavior, opps, phase):
    return {
        "artifact_id":             str(uuid.uuid4()),
        "session_id":              session_id,
        "layer":                   "passive_recon_harvester",
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


def _phase_identity_harvest(session_id):
    domain = random.choice(FAKE_ORG_DOMAINS)
    employees = random.sample(FAKE_EMPLOYEE_NAMES, 4)
    pattern = random.choice(FAKE_EMAIL_PATTERNS)
    source = random.choice(["LinkedIn scrape", "Hunter.io query", "OSINT framework", "breach data"])

    event = _base_event(session_id,
        mitre=["T1589", "T1589.002", "T1589.003"],
        behavior="employee_identity_harvest_sim",
        opps=[
            "linkedin_profile_bulk_scrape_sim",
            "email_pattern_inference_from_public_data_sim",
            "breach_data_correlation_with_live_org_sim",
            "osint_framework_org_enumeration_sim",
        ],
        phase="identity_harvest")
    event.update({
        "target_org_sim":         domain,
        "source_sim":             source,
        "employees_found_sim":    employees,
        "email_pattern_sim":      pattern,
        "email_count_sim":        random.randint(40, 800),
        "linkedin_profiles_sim":  random.randint(20, 400),
        "detection_note": (
            f"Employee identity harvesting via '{source}' targeting '{domain}'. "
            f"{random.randint(40,800)} valid emails inferred. "
            f"Pre-attack phase — detectable via HoneyEmployee records in LinkedIn."
        ),
    })
    _log_event(event)
    return event


def _phase_network_recon(session_id):
    domain = random.choice(FAKE_ORG_DOMAINS)
    ip_range = random.choice(FAKE_IP_RANGES)
    subdomains = random.sample(FAKE_SUBDOMAINS, 5)
    source = random.choice(["Shodan", "Censys", "SecurityTrails", "passive DNS"])

    event = _base_event(session_id,
        mitre=["T1590", "T1590.001", "T1596", "T1596.001", "T1596.005"],
        behavior="network_infrastructure_recon_sim",
        opps=[
            "shodan_censys_org_query_correlation_sim",
            "passive_dns_enumeration_sim",
            "certificate_transparency_subdomain_discovery_sim",
            "ip_range_asn_attribution_sim",
        ],
        phase="network_recon")
    event.update({
        "target_domain_sim":      domain,
        "ip_range_sim":           ip_range,
        "source_sim":             source,
        "subdomains_found_sim":   [f"{s}.{domain}" for s in subdomains],
        "open_ports_sim":         random.sample([22, 25, 80, 443, 3389, 8080, 8443, 9443], 4),
        "cert_sans_sim":          [f"{s}.{domain}" for s in subdomains[:3]],
        "detection_note": (
            f"Network infrastructure recon via '{source}' for '{domain}'. "
            f"Subdomain enumeration via CT logs reveals internal naming conventions. "
            f"Detect: honeypot subdomains in CT logs, monitor crt.sh queries for org name."
        ),
    })
    _log_event(event)
    return event


def _phase_org_recon(session_id):
    domain = random.choice(FAKE_ORG_DOMAINS)
    roles = ["IT Director", "CISO", "DevOps Lead", "Network Admin", "Help Desk"]
    tech = random.sample(FAKE_TECH_STACK, 3)

    event = _base_event(session_id,
        mitre=["T1591", "T1591.004", "T1593", "T1593.001", "T1594"],
        behavior="org_structure_recon_sim",
        opps=[
            "job_posting_tech_stack_inference_sim",
            "social_media_org_chart_reconstruction_sim",
            "company_website_scrape_for_roles_sim",
            "conference_speaking_attribution_sim",
        ],
        phase="org_recon")
    event.update({
        "target_org_sim":         domain,
        "identified_roles_sim":   roles,
        "tech_stack_inferred_sim": tech,
        "job_postings_scraped_sim": random.randint(5, 30),
        "social_profiles_sim":    random.randint(15, 200),
        "detection_note": (
            f"Org structure recon via job postings + social media for '{domain}'. "
            f"Tech stack '{tech[0]}' inferred from job requirements. "
            f"Roles map to likely phishing targets. "
            f"Detect: HoneyEmployee profiles, monitor for bulk LinkedIn views."
        ),
    })
    _log_event(event)
    return event


def _phase_host_recon(session_id):
    domain = random.choice(FAKE_ORG_DOMAINS)
    tech = random.sample(FAKE_TECH_STACK, 2)
    source = random.choice(["Shodan banner", "HTTP headers", "SSL cert metadata", "job postings"])

    event = _base_event(session_id,
        mitre=["T1592", "T1592.002"],
        behavior="host_software_fingerprint_sim",
        opps=[
            "banner_grabbing_software_version_detection_sim",
            "ssl_cert_metadata_org_attribution_sim",
            "http_header_server_version_disclosure_sim",
            "software_version_cve_correlation_sim",
        ],
        phase="host_recon")
    event.update({
        "target_domain_sim":      domain,
        "source_sim":             source,
        "software_identified_sim": tech,
        "cve_candidates_sim":     [f"CVE-2024-{random.randint(1000,9999)} [SIM]" for _ in tech],
        "patch_lag_estimate_sim": f"{random.randint(30,180)} days [SIM]",
        "detection_note": (
            f"Host software fingerprinting via '{source}' for '{domain}'. "
            f"'{tech[0]}' version disclosure enables targeted CVE selection. "
            f"Detect: suppress server version headers, use WAF to strip banners."
        ),
    })
    _log_event(event)
    return event


@register_payload("passive_recon_harvester")
def main():
    session_id = str(uuid.uuid4())
    phases = [
        ("identity_harvest", _phase_identity_harvest),
        ("network_recon",    _phase_network_recon),
        ("org_recon",        _phase_org_recon),
        ("host_recon",       _phase_host_recon),
    ]

    print(f"\n  [SIMULATION]  passive_recon_harvester")
    print(f"  [SESSION]     {session_id}")
    print(f"  [EVENTS]      {len(phases)}")
    print(f"  [MITRE]       T1589.x, T1590.x, T1591.x, T1592.x, T1593.x, T1594, T1596.x")
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
