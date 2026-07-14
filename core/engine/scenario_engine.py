#!/usr/bin/env python3
# SHENRON: Scenario Engine — chains simulation layers into unified kill chain timelines
# PURPOSE: Produce structured JSONL timelines for SIEM and detection system testing
# PRINCIPLE: Represent adversarial shape without adversarial capability
# All stages run safe simulators only — no real network calls, no execution

import os
import json
import uuid
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.engine.layer_loader import load_layer, discover_canonical
from core.engine import payload_registry

SCENARIO_DIR = Path(__file__).parent.parent.parent / "scenarios"
from core.config import timeline_log_path as _timeline_log_path, artifact_log_path
def _get_timeline_log_compat():
    p = _timeline_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

def _get_timeline_log():
    p = _timeline_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

# ── Built-in scenarios ────────────────────────────────────────────────────────
BUILTIN_SCENARIOS = {
    "basic_c2_persistence": {
        "name": "basic_c2_persistence",
        "description": "C2 establishment followed by lateral movement and dual persistence",
        "author": "gnomeman4201",
        "stages": [
            {"layer": "beacon_emitter_cloak", "delay_sim": 0,   "label": "initial_c2"},
            {"layer": "lateral_webcrawler",   "delay_sim": 120, "label": "recon_lateral"},
            {"layer": "dormant_persistence_sim", "delay_sim": 300, "label": "persistence_1"},
            {"layer": "memory_persistence_sim",  "delay_sim": 310, "label": "persistence_2"},
        ],
        "mitre_coverage": ["T1071", "T1132", "T1021", "T1046", "T1135", "T1053", "T1547", "T1055"],
        "expected_detection_points": [
            "periodic beacon to external host",
            "subnet sweep from internal host",
            "smb share enumeration",
            "scheduled task creation",
            "process injection attempt",
            "signal handler modification",
        ],
    },
    "recon_to_exfil": {
        "name": "recon_to_exfil",
        "description": "Network reconnaissance followed by C2 beacon and exfil simulation",
        "author": "gnomeman4201",
        "stages": [
            {"layer": "lateral_webcrawler",   "delay_sim": 0,   "label": "initial_recon"},
            {"layer": "beacon_emitter_cloak", "delay_sim": 60,  "label": "c2_check_in"},
            {"layer": "beacon_emitter_cloak", "delay_sim": 180, "label": "c2_data_staging"},
            {"layer": "dormant_persistence_sim", "delay_sim": 240, "label": "persistence"},
        ],
        "mitre_coverage": ["T1046", "T1135", "T1071", "T1132", "T1053"],
        "expected_detection_points": [
            "internal network sweep",
            "repeated beacon to same external host",
            "scheduled task after recon activity",
        ],
    },

    "persistence_runbook": {
        "name": "persistence_runbook",
        "description": "Full persistence category test — all six persistence mechanisms in sequence",
        "author": "gnomeman4201",
        "stages": [
            {"layer": "dormant_persistence_sim",      "delay_sim": 0,   "label": "sleeper_plant"},
            {"layer": "memory_persistence_sim",        "delay_sim": 30,  "label": "memory_latch"},
            {"layer": "memory_hijack_inheritor",    "delay_sim": 60,  "label": "memory_hijack"},
            {"layer": "system_rebuild_sim",    "delay_sim": 90,  "label": "shadow_rebuild"},
            {"layer": "self_sealing_nano_sandbox",  "delay_sim": 120, "label": "sandbox_seal"},
            {"layer": "file_infector_sim",  "delay_sim": 150, "label": "file_infect"},
        ],
        "mitre_coverage": ["T1053", "T1547", "T1055", "T1134", "T1543", "T1564", "T1027"],
        "expected_detection_points": [
            "scheduled task creation",
            "process injection pattern",
            "token impersonation",
            "system file hash change",
            "hidden temp directory",
            "script file modification",
        ],
    },
    "evasion_stress_test": {
        "name": "evasion_stress_test",
        "description": "Evasion-focused scenario — tests anti-forensics, log manipulation, and masquerading detection",
        "author": "gnomeman4201",
        "stages": [
            {"layer": "anti_forensics_molt",      "delay_sim": 0,   "label": "forensics_wipe"},
            {"layer": "traffic_reflection_sim",    "delay_sim": 30,  "label": "process_mirror"},
            {"layer": "decoy_artifact_sim",    "delay_sim": 60,  "label": "lure_deploy"},
            {"layer": "sandbox_evasion_sim", "delay_sim": 90,  "label": "quarantine_cloak"},
            {"layer": "rootkit_evasion_sim",  "delay_sim": 120, "label": "rootkit_shroud"},
            {"layer": "rootkit_evasion_sim",  "delay_sim": 150, "label": "rootkit_shroud_2"},
        ],
        "mitre_coverage": ["T1070", "T1107", "T1036", "T1036.005", "T1055", "T1564", "T1014"],
        "expected_detection_points": [
            "log deletion or tampering",
            "process name masquerading",
            "lure file deployment",
            "quarantine bypass attempt",
            "rootkit artifact",
            "payload hash change",
        ],
    },
    "apt_kill_chain": {
        "name": "apt_kill_chain",
        "description": "Full APT-style kill chain — C2, recon, lateral movement, persistence, evasion, exfil",
        "author": "gnomeman4201",
        "stages": [
            {"layer": "beacon_emitter_cloak",      "delay_sim": 0,    "label": "initial_c2"},
            {"layer": "lateral_webcrawler",        "delay_sim": 120,  "label": "recon"},
            {"layer": "dormant_persistence_sim",      "delay_sim": 300,  "label": "persistence_plant"},
            {"layer": "memory_hijack_inheritor",   "delay_sim": 360,  "label": "memory_hijack"},
            {"layer": "anti_forensics_molt",       "delay_sim": 420,  "label": "cover_tracks"},
            {"layer": "traffic_reflection_sim",     "delay_sim": 450,  "label": "masquerade"},
            {"layer": "system_rebuild_sim",   "delay_sim": 480,  "label": "persistence_reinforce"},
            {"layer": "file_infector_sim", "delay_sim": 510,  "label": "file_plant"},
            {"layer": "beacon_emitter_cloak",      "delay_sim": 600,  "label": "exfil_c2"},
        ],
        "mitre_coverage": [
            "T1071", "T1132", "T1021", "T1046", "T1135",
            "T1053", "T1547", "T1055", "T1134",
            "T1070", "T1107", "T1036", "T1036.005",
            "T1543", "T1027", "T1564"
        ],
        "expected_detection_points": [
            "periodic c2 beacon",
            "subnet sweep from internal host",
            "scheduled task creation",
            "process injection",
            "log deletion",
            "process masquerading",
            "system file restoration",
            "script file modification",
            "c2 exfil beacon",
        ],
    },
}

# ── Engine ────────────────────────────────────────────────────────────────────
def run_scenario(scenario_name_or_path, dry_run=False, verbose=True):
    # Load scenario definition
    if scenario_name_or_path in BUILTIN_SCENARIOS:
        scenario = BUILTIN_SCENARIOS[scenario_name_or_path].copy()
    else:
        p = Path(scenario_name_or_path)
        if not p.exists():
            print(f"  [!] Scenario not found: {scenario_name_or_path}")
            print(f"  Built-in: {', '.join(BUILTIN_SCENARIOS.keys())}")
            return None
        scenario = json.loads(p.read_text())

    scenario_id = str(uuid.uuid4())
    base_time = datetime.now(timezone.utc)
    canonical = discover_canonical()

    if verbose:
        print(f"\n  [SCENARIO]    {scenario['name']}")
        print(f"  [ID]          {scenario_id}")
        print(f"  [DESC]        {scenario['description']}")
        print(f"  [STAGES]      {len(scenario['stages'])}")
        print(f"  [MITRE]       {', '.join(scenario['mitre_coverage'])}")
        if dry_run:
            print(f"  [MODE]        DRY RUN")
        print()

    # Validate all layers exist before running
    missing = [s["layer"] for s in scenario["stages"] if s["layer"] not in canonical]
    if missing:
        print(f"  [!] Missing layers: {missing}")
        return None

    # Write scenario header to timeline
    header = {
        "record_type": "scenario_start",
        "scenario_id": scenario_id,
        "scenario_name": scenario["name"],
        "description": scenario["description"],
        "timestamp": base_time.isoformat(),
        "stages": len(scenario["stages"]),
        "mitre_coverage": scenario["mitre_coverage"],
        "expected_detection_points": scenario.get("expected_detection_points", []),
        "dry_run": dry_run,
        "simulation_only": True,
    }
    with open(_get_timeline_log(), "a") as f:
        f.write(json.dumps(header) + "\n")

    # Run each stage
    results = []
    for i, stage in enumerate(scenario["stages"]):
        layer = stage["layer"]
        label = stage["label"]
        delay = stage["delay_sim"]
        sim_time = (base_time + timedelta(seconds=delay)).isoformat()

        if verbose:
            mode = "DRY RUN" if dry_run else "EXECUTE"
            print(f"  [STAGE {i+1}/{len(scenario['stages'])}] {label} — {layer}")
            print(f"  sim_time_offset : +{delay}s ({sim_time[:19]})")

        # Write stage marker to timeline
        stage_marker = {
            "record_type": "stage_start",
            "scenario_id": scenario_id,
            "stage": i + 1,
            "label": label,
            "layer": layer,
            "sim_timestamp": sim_time,
            "delay_sim": delay,
            "simulation_only": True,
        }
        with open(_get_timeline_log(), "a") as f:
            f.write(json.dumps(stage_marker) + "\n")

        if not dry_run:
            payload_registry.clear()
            ok, err = load_layer(layer, canonical[layer])
            if ok:
                payload_registry.run(layer)
                results.append({"stage": i+1, "layer": layer, "status": "executed"})
                if verbose:
                    print(f"  status          : executed\n")
            else:
                results.append({"stage": i+1, "layer": layer, "status": f"failed: {err}"})
                if verbose:
                    print(f"  status          : FAILED — {err}\n")
        else:
            results.append({"stage": i+1, "layer": layer, "status": "dry-run-ok"})
            if verbose:
                print(f"  status          : dry-run-ok\n")

    # Write scenario footer
    ok_count = sum(1 for r in results if "failed" not in r["status"])
    footer = {
        "record_type": "scenario_end",
        "scenario_id": scenario_id,
        "scenario_name": scenario["name"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stages_run": len(results),
        "stages_ok": ok_count,
        "stages_failed": len(results) - ok_count,
        "simulation_only": True,
    }
    with open(_get_timeline_log(), "a") as f:
        f.write(json.dumps(footer) + "\n")

    if verbose:
        print(f"  [COMPLETE]    {ok_count}/{len(results)} stages ok")
        print(f"  [TIMELINE]    {_get_timeline_log()}")
        print(f"  [ARTIFACTS]   {artifact_log_path()}")
        print()

    return scenario_id, results

def list_scenarios():
    print("\n  BUILT-IN SCENARIOS:")
    for name, s in BUILTIN_SCENARIOS.items():
        print(f"\n  [{name}]")
        print(f"    {s['description']}")
        print(f"    stages : {len(s['stages'])}")
        print(f"    mitre  : {', '.join(s['mitre_coverage'])}")
        stages = " → ".join(s["label"] for s in s["stages"])
        print(f"    flow   : {stages}")

    custom = list(SCENARIO_DIR.glob("*.json")) if SCENARIO_DIR.exists() else []
    if custom:
        print(f"\n  CUSTOM SCENARIOS ({len(custom)}):")
        for p in custom:
            print(f"    {p.name}")
    print()

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(prog="scenario_engine")
    p.add_argument("--run",      type=str, help="scenario name or path")
    p.add_argument("--list",     action="store_true")
    p.add_argument("--dry-run",  action="store_true")
    args = p.parse_args()

    if args.list:
        list_scenarios()
    elif args.run:
        run_scenario(args.run, dry_run=args.dry_run)
    else:
        p.print_help()
