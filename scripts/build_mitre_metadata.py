#!/usr/bin/env python3
# SHENRON: Build MITRE ATT&CK metadata into manifest
# PURPOSE: Label each layer with techniques it simulates for detection coverage mapping

import json
from pathlib import Path

MANIFEST_PATH = Path(__file__).parent.parent / "shenron_manifest.json"

MITRE_MAP = {
    "beacon_emitter_cloak":          {"techniques": ["T1071", "T1132"],          "tactic": "command-and-control"},
    "autonomous_signal_cloner":      {"techniques": ["T1071", "T1102"],          "tactic": "command-and-control"},
    "lateral_webcrawler":            {"techniques": ["T1021", "T1046", "T1135"], "tactic": "lateral-movement"},
    "parasitic_mesh_crawler":        {"techniques": ["T1021", "T1570"],          "tactic": "lateral-movement"},
    "spectral_packet_weaver":        {"techniques": ["T1095", "T1001"],          "tactic": "command-and-control"},
    "temporal_mirage_emulator":      {"techniques": ["T1070", "T1036"],          "tactic": "defense-evasion"},
    "temporal_payload_phaser":       {"techniques": ["T1027", "T1140"],          "tactic": "defense-evasion"},
    "dreamdive_overlay":             {"techniques": ["T1070.001", "T1036"],      "tactic": "defense-evasion"},
    "dormant_sleeper_seed":          {"techniques": ["T1053", "T1547"],          "tactic": "persistence"},
    "undead_memory_latch":           {"techniques": ["T1055", "T1547"],          "tactic": "persistence"},
    "memory_hijack_inheritor":       {"techniques": ["T1055", "T1134"],          "tactic": "privilege-escalation"},
    "shadow_system_rebuilder":       {"techniques": ["T1547", "T1543"],          "tactic": "persistence"},
    "self_sealing_nano_sandbox":     {"techniques": ["T1055", "T1564"],          "tactic": "defense-evasion"},
    "poltergeist_file_infector":     {"techniques": ["T1027", "T1564.001"],      "tactic": "defense-evasion"},
    "anti_forensics_molt":           {"techniques": ["T1070", "T1107"],          "tactic": "defense-evasion"},
    "airlock_quarantine_cloak":      {"techniques": ["T1564", "T1036"],          "tactic": "defense-evasion"},
    "evasion_lure_illusion":         {"techniques": ["T1036", "T1055"],          "tactic": "defense-evasion"},
    "mirror_loop_deflector":         {"techniques": ["T1036.005", "T1070"],      "tactic": "defense-evasion"},
    "spectral_rootkit_shroud":       {"techniques": ["T1014", "T1564"],          "tactic": "defense-evasion"},
    "dark_signature_morpher":        {"techniques": ["T1027", "T1036"],          "tactic": "defense-evasion"},
    "payload_skinwalker":            {"techniques": ["T1027", "T1059"],          "tactic": "execution"},
    "obfuscated_skinwalker_dropper": {"techniques": ["T1027", "T1105"],          "tactic": "command-and-control"},
    "deadzone_payload":              {"techniques": ["T1027", "T1140"],          "tactic": "defense-evasion"},
    "symbiote_payload":              {"techniques": ["T1055", "T1027"],          "tactic": "defense-evasion"},
    "ethereal_payload_reanimator":   {"techniques": ["T1055", "T1620"],          "tactic": "defense-evasion"},
    "recursive_payload_seedbank":    {"techniques": ["T1027", "T1547"],          "tactic": "persistence"},
    "transient_exfil_shell":         {"techniques": ["T1041", "T1048"],          "tactic": "exfiltration"},
    "void_gateway_tunnel":           {"techniques": ["T1572", "T1090"],          "tactic": "command-and-control"},
    "cognitive_replicator":          {"techniques": ["T1036", "T1078"],          "tactic": "defense-evasion"},
    "forged_bios_artifact":          {"techniques": ["T1542", "T1036"],          "tactic": "persistence"},
    "shenron_bio_replication":       {"techniques": ["T1036", "T1027"],          "tactic": "defense-evasion"},
    "stealth_mimic":                 {"techniques": ["T1036", "T1134"],          "tactic": "defense-evasion"},
    "quantum_entropy_distorter":     {"techniques": ["T1027", "T1001"],          "tactic": "defense-evasion"},
    "entropy_flux_disruptor":        {"techniques": ["T1027.002"],               "tactic": "defense-evasion"},
    "entropy_anchor_dropper":        {"techniques": ["T1027", "T1140"],          "tactic": "defense-evasion"},
    "neural_entropy_seeder":         {"techniques": ["T1027", "T1036"],          "tactic": "defense-evasion"},
    "quantum_state_shuffler":        {"techniques": ["T1027", "T1001"],          "tactic": "defense-evasion"},
    "quantum_trace_rewinder":        {"techniques": ["T1070", "T1027"],          "tactic": "defense-evasion"},
    "quantum_entanglement_relay":    {"techniques": ["T1095", "T1572"],          "tactic": "command-and-control"},
    "synthetic_splinter_seed":       {"techniques": ["T1027", "T1105"],          "tactic": "command-and-control"},
    "llm_echo_chamber":              {"techniques": ["T1565", "T1036"],          "tactic": "impact"},
    "llm_shroud_writer":             {"techniques": ["T1027", "T1036"],          "tactic": "defense-evasion"},
    "dragons_breath_destructor":     {"techniques": ["T1070", "T1485"],          "tactic": "impact"},
    "encrypted_echo_chamber":        {"techniques": ["T1573", "T1132"],          "tactic": "command-and-control"},
    "adaptive_brainstem":            {"techniques": ["T1027", "T1620"],          "tactic": "defense-evasion"},
    "manifest_vampire":              {"techniques": ["T1005", "T1119"],          "tactic": "collection"},
    "mutation_history":              {"techniques": ["T1027", "T1036"],          "tactic": "defense-evasion"},
    "phantom_thread_fabricator":     {"techniques": ["T1055.003", "T1036"],      "tactic": "defense-evasion"},
    "polymorph_chain_stats":         {"techniques": [],                           "tactic": "meta"},
    "shenron_holo_emitter":          {"techniques": ["T1036", "T1027"],          "tactic": "defense-evasion"},
}

LOG_SOURCES = {
    "command-and-control":  ["network", "dns", "proxy"],
    "lateral-movement":     ["network", "process", "authentication"],
    "persistence":          ["process", "registry", "filesystem", "scheduled-task"],
    "defense-evasion":      ["process", "filesystem", "memory"],
    "privilege-escalation": ["process", "authentication", "memory"],
    "execution":            ["process", "command-line"],
    "exfiltration":         ["network", "dns", "proxy"],
    "collection":           ["filesystem", "process"],
    "impact":               ["filesystem", "process", "log"],
    "meta":                 [],
}

def build():
    manifest = json.loads(MANIFEST_PATH.read_text())
    mapped = 0
    unmapped = []

    for layer in manifest["layers"]:
        name = layer["name"]
        mitre = MITRE_MAP.get(name)
        if mitre:
            tactic = mitre["tactic"]
            layer["mitre"] = {
                "techniques": mitre["techniques"],
                "tactic": tactic,
            }
            layer["detection"] = {
                "log_sources": LOG_SOURCES.get(tactic, []),
                "expected_events": [],
                "alert_signatures": [],
            }
            layer["simulation"] = {
                "fidelity": "stub",
                "emits": [],
                "safe": True,
            }
            mapped += 1
        else:
            unmapped.append(name)

    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2))
    print(f"[+] MITRE metadata added to {mapped} layers")
    if unmapped:
        print(f"[!] Unmapped: {unmapped}")

    print("\n  COVERAGE SUMMARY:")
    tactic_counts = {}
    for layer in manifest["layers"]:
        tactic = layer.get("mitre", {}).get("tactic", "unmapped")
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    for tactic, count in sorted(tactic_counts.items()):
        techniques = set()
        for layer in manifest["layers"]:
            if layer.get("mitre", {}).get("tactic") == tactic:
                techniques.update(layer["mitre"]["techniques"])
        print(f"  {tactic:<25} {count:2} layers  {len(techniques):2} unique techniques")

if __name__ == "__main__":
    build()
