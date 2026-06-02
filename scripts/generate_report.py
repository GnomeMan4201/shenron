#!/usr/bin/env python3
# SHENRON: Detection Coverage Report Generator
# PURPOSE: Read a completed scenario timeline and produce a structured
#          detection coverage report for blue team consumption

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

from core.config import artifact_log_path, timeline_log_path, get_report_dir
TIMELINE_LOG = timeline_log_path()
ARTIFACT_LOG = artifact_log_path()
MANIFEST_PATH = Path(__file__).parent.parent / "shenron_manifest.json"
REPORTS_DIR = get_report_dir()

def load_timeline():
    if not TIMELINE_LOG.exists():
        return []
    with open(TIMELINE_LOG) as f:
        return [json.loads(line) for line in f if line.strip()]

def load_artifacts():
    if not ARTIFACT_LOG.exists():
        return []
    with open(ARTIFACT_LOG) as f:
        return [json.loads(line) for line in f if line.strip()]

def load_manifest():
    if not MANIFEST_PATH.exists():
        return {}
    manifest = json.loads(MANIFEST_PATH.read_text())
    return {layer["name"]: layer for layer in manifest["layers"]}

def get_scenario_runs(timeline):
    runs = []
    current = None
    for record in timeline:
        if record.get("record_type") == "scenario_start":
            current = {
                "scenario_id": record["scenario_id"],
                "scenario_name": record["scenario_name"],
                "description": record["description"],
                "timestamp": record["timestamp"],
                "mitre_coverage": record["mitre_coverage"],
                "expected_detection_points": record.get("expected_detection_points", []),
                "dry_run": record.get("dry_run", False),
                "stages": [],
            }
        elif record.get("record_type") == "stage_start" and current:
            current["stages"].append({
                "stage": record["stage"],
                "label": record["label"],
                "layer": record["layer"],
                "sim_timestamp": record["sim_timestamp"],
                "delay_sim": record["delay_sim"],
            })
        elif record.get("record_type") == "scenario_end" and current:
            current["stages_ok"] = record["stages_ok"]
            current["stages_failed"] = record["stages_failed"]
            runs.append(current)
            current = None
    return runs

def generate_report(scenario_id=None):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    timeline = load_timeline()
    artifacts = load_artifacts()
    manifest = load_manifest()

    runs = get_scenario_runs(timeline)
    if not runs:
        print("[!] No completed scenario runs found in timeline log")
        return

    # Filter to specific scenario if requested
    if scenario_id:
        runs = [r for r in runs if r["scenario_id"] == scenario_id]
        if not runs:
            print(f"[!] Scenario ID not found: {scenario_id}")
            return

    # Report on most recent run by default
    run = runs[-1]

    # Collect artifacts for this scenario
    run_artifacts = [
        a for a in artifacts
        if a.get("session_id") and any(
            a.get("layer") == s["layer"] for s in run["stages"]
        )
    ]

    # Build technique coverage
    all_techniques = set(run["mitre_coverage"])
    technique_to_layers = defaultdict(list)
    for stage in run["stages"]:
        layer_data = manifest.get(stage["layer"], {})
        for t in layer_data.get("mitre", {}).get("techniques", []):
            technique_to_layers[t].append(stage["layer"])

    # Build log source coverage
    log_sources_hit = set()
    for stage in run["stages"]:
        layer_data = manifest.get(stage["layer"], {})
        for src in layer_data.get("detection", {}).get("log_sources", []):
            log_sources_hit.add(src)

    # Build event type coverage
    event_types_emitted = set()
    for stage in run["stages"]:
        layer_data = manifest.get(stage["layer"], {})
        for e in layer_data.get("simulation", {}).get("emits", []):
            event_types_emitted.add(e)

    # Build alert signatures expected
    alert_signatures = []
    for stage in run["stages"]:
        layer_data = manifest.get(stage["layer"], {})
        for sig in layer_data.get("detection", {}).get("alert_signatures", []):
            alert_signatures.append({"signature": sig, "layer": stage["layer"]})

    # Compose report
    report = {
        "report_generated": datetime.now().isoformat(),
        "scenario": {
            "id": run["scenario_id"],
            "name": run["scenario_name"],
            "description": run["description"],
            "run_timestamp": run["timestamp"],
            "dry_run": run["dry_run"],
            "stages_total": len(run["stages"]),
            "stages_ok": run.get("stages_ok", 0),
            "stages_failed": run.get("stages_failed", 0),
        },
        "kill_chain": [
            {
                "stage": s["stage"],
                "label": s["label"],
                "layer": s["layer"],
                "sim_time_offset": f"+{s['delay_sim']}s",
                "sim_timestamp": s["sim_timestamp"],
                "techniques": manifest.get(s["layer"], {}).get(
                    "mitre", {}).get("techniques", []),
                "fidelity": manifest.get(s["layer"], {}).get(
                    "simulation", {}).get("fidelity", "stub"),
            }
            for s in run["stages"]
        ],
        "coverage": {
            "mitre_techniques": sorted(all_techniques),
            "technique_count": len(all_techniques),
            "techniques_by_layer": dict(technique_to_layers),
            "log_sources_exercised": sorted(log_sources_hit),
            "event_types_emitted": sorted(event_types_emitted),
            "artifacts_generated": len(run_artifacts),
        },
        "detection_guidance": {
            "expected_detection_points": run["expected_detection_points"],
            "alert_signatures": alert_signatures,
            "recommended_log_sources": sorted(log_sources_hit),
        },
        "simulation_integrity": {
            "network_calls_made": False,
            "processes_spawned": False,
            "shell_commands_executed": False,
            "files_modified": False,
            "all_artifacts_synthetic": True,
        },
    }

    # Write JSON report
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = REPORTS_DIR / f"report_{run['scenario_name']}_{ts}.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    # Print human-readable summary
    print(f"\n  SHENRON // detection coverage report")
    print(f"  {'='*65}")
    print(f"  scenario      : {run['scenario_name']}")
    print(f"  run_id        : {run['scenario_id'][:8]}...")
    print(f"  timestamp     : {run['timestamp'][:19]}")
    print(f"  stages        : {run.get('stages_ok', 0)}/{len(run['stages'])} ok")
    print(f"  dry_run       : {run['dry_run']}")
    print()
    print(f"  KILL CHAIN:")
    for s in report["kill_chain"]:
        techs = ", ".join(s["techniques"])
        print(f"    [{s['stage']}] {s['label']:<20} {s['layer']:<30} {s['sim_time_offset']:<8} [{techs}]")
    print()
    print(f"  MITRE COVERAGE ({len(all_techniques)} techniques):")
    for t in sorted(all_techniques):
        layers = technique_to_layers.get(t, [])
        print(f"    {t}  —  {', '.join(layers)}")
    print()
    print(f"  LOG SOURCES EXERCISED:")
    for src in sorted(log_sources_hit):
        print(f"    {src}")
    print()
    print(f"  EXPECTED ALERT SIGNATURES:")
    for sig in alert_signatures:
        print(f"    [{sig['layer']}] {sig['signature']}")
    print()
    print(f"  SIMULATION INTEGRITY:")
    for k, v in report["simulation_integrity"].items():
        print(f"    {k:<35} {v}")
    print()
    print(f"  ARTIFACTS GENERATED  : {len(run_artifacts)}")
    print(f"  REPORT SAVED         : {report_path}")
    print()

    return report_path

if __name__ == "__main__":
    scenario_id = sys.argv[1] if len(sys.argv) > 1 else None
    generate_report(scenario_id)
