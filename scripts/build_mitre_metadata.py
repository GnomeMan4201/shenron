#!/usr/bin/env python3
# SHENRON: Build MITRE ATT&CK metadata into manifest
# PURPOSE: Label each layer with techniques it simulates for detection coverage mapping

import json
from pathlib import Path

MANIFEST_PATH = Path(__file__).parent.parent / "shenron_manifest.json"

MITRE_MAP = {
    "beacon_emitter_cloak":          {"techniques": ["T1071", "T1132"],          "tactic": "command-and-control"},
    "signal_replication_sim":      {"techniques": ["T1071", "T1102"],          "tactic": "command-and-control"},
    "lateral_webcrawler":            {"techniques": ["T1021", "T1046", "T1135"], "tactic": "lateral-movement"},
    "parasitic_mesh_crawler":        {"techniques": ["T1021", "T1570"],          "tactic": "lateral-movement"},
    "packet_covert_channel_sim":        {"techniques": ["T1095", "T1001"],          "tactic": "command-and-control"},
    "timestamp_decoy_sim":      {"techniques": ["T1070", "T1036"],          "tactic": "defense-evasion"},
    "payload_timing_sim":       {"techniques": ["T1027", "T1140"],          "tactic": "defense-evasion"},
    "memory_overlay_sim":             {"techniques": ["T1070.001", "T1036"],      "tactic": "defense-evasion"},
    "dormant_persistence_sim":          {"techniques": ["T1053", "T1547"],          "tactic": "persistence"},
    "memory_persistence_sim":           {"techniques": ["T1055", "T1547"],          "tactic": "persistence"},
    "memory_hijack_inheritor":       {"techniques": ["T1055", "T1134"],          "tactic": "privilege-escalation"},
    "system_rebuild_sim":       {"techniques": ["T1547", "T1543"],          "tactic": "persistence"},
    "self_sealing_nano_sandbox":     {"techniques": ["T1055", "T1564"],          "tactic": "defense-evasion"},
    "file_infector_sim":     {"techniques": ["T1027", "T1564.001"],      "tactic": "defense-evasion"},
    "anti_forensics_molt":           {"techniques": ["T1070", "T1107"],          "tactic": "defense-evasion"},
    "sandbox_evasion_sim":      {"techniques": ["T1564", "T1036"],          "tactic": "defense-evasion"},
    "decoy_artifact_sim":         {"techniques": ["T1036", "T1055"],          "tactic": "defense-evasion"},
    "traffic_reflection_sim":         {"techniques": ["T1036.005", "T1070"],      "tactic": "defense-evasion"},
    "rootkit_evasion_sim":       {"techniques": ["T1014", "T1564"],          "tactic": "defense-evasion"},
    "signature_mutation_sim":        {"techniques": ["T1027", "T1036"],          "tactic": "defense-evasion"},
    "payload_skinwalker":            {"techniques": ["T1027", "T1059"],          "tactic": "execution"},
    "obfuscated_skinwalker_dropper": {"techniques": ["T1027", "T1105"],          "tactic": "command-and-control"},
    "deadzone_payload":              {"techniques": ["T1027", "T1140"],          "tactic": "defense-evasion"},
    "process_injection_symbiote_sim":              {"techniques": ["T1055", "T1027"],          "tactic": "defense-evasion"},
    "payload_revival_sim":   {"techniques": ["T1055", "T1620"],          "tactic": "defense-evasion"},
    "payload_seedbank_sim":    {"techniques": ["T1027", "T1547"],          "tactic": "persistence"},
    "transient_exfil_sim":         {"techniques": ["T1041", "T1048"],          "tactic": "exfiltration"},
    "covert_tunnel_sim":           {"techniques": ["T1572", "T1090"],          "tactic": "command-and-control"},
    "file_replica_dropper":          {"techniques": ["T1036", "T1078"],          "tactic": "defense-evasion"},
    "firmware_artifact_sim":          {"techniques": ["T1542", "T1036"],          "tactic": "persistence"},
    "device_fingerprint_spoof":       {"techniques": ["T1036", "T1027"],          "tactic": "defense-evasion"},
    "stealth_mimic":                 {"techniques": ["T1036", "T1134"],          "tactic": "defense-evasion"},
    "entropy_injection_sim":     {"techniques": ["T1027", "T1001"],          "tactic": "defense-evasion"},
    "entropy_flux_disruptor":        {"techniques": ["T1027.002"],               "tactic": "defense-evasion"},
    "entropy_anchor_sim":        {"techniques": ["T1027", "T1140"],          "tactic": "defense-evasion"},
    "entropy_seeder_sim":         {"techniques": ["T1027", "T1036"],          "tactic": "defense-evasion"},
    "payload_hash_shuffler":        {"techniques": ["T1027", "T1001"],          "tactic": "defense-evasion"},
    "timestamp_spoof_sim":        {"techniques": ["T1070", "T1027"],          "tactic": "defense-evasion"},
    "covert_socket_relay":    {"techniques": ["T1095", "T1572"],          "tactic": "command-and-control"},
    "synthetic_splinter_seed":       {"techniques": ["T1027", "T1105"],          "tactic": "command-and-control"},
    "llm_echo_chamber":              {"techniques": ["T1565", "T1036"],          "tactic": "impact"},
    "llm_shroud_writer":             {"techniques": ["T1027", "T1036"],          "tactic": "defense-evasion"},
    "antiforensic_wipe_sim":     {"techniques": ["T1070", "T1485"],          "tactic": "impact"},
    "encrypted_echo_chamber":        {"techniques": ["T1573", "T1132"],          "tactic": "command-and-control"},
    "adaptive_layer_selector":            {"techniques": ["T1027", "T1620"],          "tactic": "defense-evasion"},
    "manifest_hijack_sim":              {"techniques": ["T1005", "T1119"],          "tactic": "collection"},
    "mutation_history":              {"techniques": ["T1027", "T1036"],          "tactic": "defense-evasion"},
    "thread_injection_sim":     {"techniques": ["T1055.003", "T1036"],      "tactic": "defense-evasion"},
    "polymorph_chain_stats":         {"techniques": [],                           "tactic": "meta"},
    "process_masquerade_sim":          {"techniques": ["T1036", "T1027"],          "tactic": "defense-evasion"},
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
