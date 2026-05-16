#!/usr/bin/env python3
# SHENRON: Evidence loader — reads JSONL artifacts and validates safety contract
import json
from pathlib import Path
from typing import Optional
from core.reports.model import (
    ShenronReport, Finding, DetectionOpportunity,
    EvidenceRef, MITRECoverage, SafetyVerification
)

ARTIFACT_LOG  = Path("/home/gnomeman4201/SHENRON/logs/simulation_artifacts.jsonl")
TIMELINE_LOG  = Path("/home/gnomeman4201/SHENRON/logs/scenario_timelines.jsonl")
MANIFEST_PATH = Path(__file__).parent.parent.parent / "shenron_manifest.json"

REQUIRED_SAFE = {
    "simulation_only": True,
    "executable":      False,
}
FORBIDDEN_TRUE = ["network_calls_made", "processes_spawned", "socket_bound"]


def load_artifacts(path: Path = ARTIFACT_LOG) -> list:
    if not path.exists():
        return []
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records


def load_timeline(path: Path = TIMELINE_LOG) -> list:
    return load_artifacts(path)


def get_campaign_runs(timeline: list) -> list:
    runs = []
    current = None
    for record in timeline:
        rt = record.get("record_type", "")
        if rt == "bananatree_campaign_start":
            current = {
                "run_id":        record.get("run_id"),
                "campaign_name": record.get("campaign_name"),
                "timestamp":     record.get("timestamp"),
                "dry_run":       record.get("dry_run", True),
                "scenario":      record.get("scenario"),
                "phases":        [],
            }
        elif rt == "bananatree_phase_end" and current:
            current["phases"].append({
                "phase":       record.get("phase"),
                "layers_run":  record.get("layers_run", []),
                "findings":    record.get("findings", []),
                "mitre":       record.get("mitre_techniques", []),
                "errors":      record.get("errors", []),
            })
        elif rt == "bananatree_campaign_end" and current:
            current["completed_at"] = record.get("timestamp")
            current["total_layers"] = record.get("total_layers", 0)
            current["all_mitre"]    = record.get("all_mitre", [])
            runs.append(current)
            current = None
    return runs


def group_artifacts_by_layer(artifacts: list) -> dict:
    grouped = {}
    for art in artifacts:
        layer = art.get("layer", "unknown")
        grouped.setdefault(layer, []).append(art)
    return grouped


def verify_safety(artifacts: list) -> SafetyVerification:
    sv = SafetyVerification()
    # Only validate actual simulation artifacts — not timeline/header records
    sim_arts = [
        a for a in artifacts
        if "artifact_id" in a
    ]
    return sv.evaluate(sim_arts)


def _load_manifest_index() -> dict:
    if not MANIFEST_PATH.exists():
        return {}
    manifest = json.loads(MANIFEST_PATH.read_text())
    return {layer["name"]: layer for layer in manifest.get("layers", [])}


def build_report_from_run(run: dict, artifacts: list) -> ShenronReport:
    manifest = _load_manifest_index()
    run_id   = run.get("run_id", "")

    # Filter artifacts to this run's layers
    all_layer_names = set()
    for phase in run.get("phases", []):
        for l in phase.get("layers_run", []):
            all_layer_names.add(l)

    run_artifacts = [
        a for a in artifacts
        if a.get("layer") in all_layer_names
    ]

    report = ShenronReport(
        run_id        = run_id,
        campaign_name = run.get("campaign_name", ""),
        scenario_path = run.get("scenario", ""),
        dry_run       = run.get("dry_run", True),
        phases_run    = [p["phase"] for p in run.get("phases", [])],
        layers_run    = list(all_layer_names),
        total_events  = len(run_artifacts),
    )

    # Safety
    report.safety = verify_safety(run_artifacts)

    # MITRE
    mitre = MITRECoverage()
    mitre.techniques = list(run.get("all_mitre", []))
    for layer_name in all_layer_names:
        layer_data = manifest.get(layer_name, {})
        techs = layer_data.get("mitre", {}).get("techniques", [])
        tactic = layer_data.get("mitre", {}).get("tactic", "")
        mitre.by_layer[layer_name] = techs
        if tactic and tactic not in mitre.tactics:
            mitre.tactics.append(tactic)
    report.mitre = mitre

    # Findings per phase
    for phase_data in run.get("phases", []):
        phase_name = phase_data.get("phase", "")
        for layer_name in phase_data.get("layers_run", []):
            layer_data  = manifest.get(layer_name, {})
            techniques  = layer_data.get("mitre", {}).get("techniques", [])
            alert_sigs  = layer_data.get("detection", {}).get("alert_signatures", [])
            exp_events  = layer_data.get("detection", {}).get("expected_events", [])

            finding = Finding(
                phase       = phase_name,
                layer       = layer_name,
                description = layer_data.get("description", f"{layer_name} simulation"),
                mitre       = techniques,
                detections  = exp_events,
            )
            # Attach evidence refs
            for art in run_artifacts:
                if art.get("layer") == layer_name:
                    finding.evidence.append(EvidenceRef(
                        artifact_id = art.get("artifact_id", ""),
                        layer       = layer_name,
                        phase       = phase_name,
                        timestamp   = art.get("timestamp", ""),
                        behavior    = art.get("behavior_class", art.get("phase", "")),
                        safe        = art.get("simulation_only", False),
                    ))

            report.findings.append(finding)
            report.alert_signatures.extend([
                {"layer": layer_name, "phase": phase_name, "signature": s}
                for s in alert_sigs
            ])

            # Detection opportunities
            for opp in exp_events:
                report.detections.append(DetectionOpportunity(
                    layer       = layer_name,
                    phase       = phase_name,
                    opportunity = opp,
                    mitre       = techniques,
                ))

    # Evidence appendix
    grouped = group_artifacts_by_layer(run_artifacts)
    for layer_name, arts in grouped.items():
        for art in arts[:3]:  # cap per layer
            report.artifacts.append(EvidenceRef(
                artifact_id = art.get("artifact_id", ""),
                layer       = layer_name,
                phase       = art.get("phase", ""),
                timestamp   = art.get("timestamp", ""),
                behavior    = art.get("behavior_class", art.get("phase", "")),
                safe        = art.get("simulation_only", False),
            ))

    return report


def load_latest_report() -> Optional[ShenronReport]:
    timeline  = load_timeline()
    artifacts = load_artifacts()
    runs = get_campaign_runs(timeline)
    if not runs:
        return None
    return build_report_from_run(runs[-1], artifacts)


def load_report_by_run_id(run_id: str) -> Optional[ShenronReport]:
    timeline  = load_timeline()
    artifacts = load_artifacts()
    runs = get_campaign_runs(timeline)
    for run in reversed(runs):
        if run.get("run_id") == run_id:
            return build_report_from_run(run, artifacts)
    return None
