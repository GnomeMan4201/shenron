#!/usr/bin/env python3
# SHENRON: Evidence loader — reads JSONL artifacts and validates safety contract
import json
from pathlib import Path
from typing import Optional
from core.reports.model import (
    ShenronReport, Finding, DetectionOpportunity,
    EvidenceRef, MITRECoverage, SafetyVerification
)

from core.config import artifact_log_path as _artifact_log_path, timeline_log_path as _timeline_log_path

MANIFEST_PATH = Path(__file__).parent.parent.parent / "shenron_manifest.json"

REQUIRED_SAFE = {
    "simulation_only": True,
    "executable":      False,
}
FORBIDDEN_TRUE = ["network_calls_made", "processes_spawned", "socket_bound"]


def load_artifacts(path: Path = None) -> list:
    if path is None:
        path = _artifact_log_path()
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


def load_timeline(path: Path = None) -> list:
    if path is None:
        path = _timeline_log_path()
    return load_artifacts(path)


def get_campaign_runs(timeline: list) -> list:
    """
    Parse timeline into a unified run list.
    Handles both record families:
      - bananatree_campaign_start/phase_end/campaign_end  (bananaTREE campaigns)
      - scenario_start/stage_start/scenario_end           (--scenario runs)
    Both are normalised to the same dict shape so score_by_run_id and
    compare_runs work against either without modification.
    """
    runs = []
    current = None

    for record in timeline:
        rt = record.get("record_type", "")

        # ── bananaTREE campaign records ──────────────────────────────────────
        if rt == "bananatree_campaign_start":
            current = {
                "run_id":        record.get("run_id"),
                "campaign_name": record.get("campaign_name"),
                "timestamp":     record.get("timestamp"),
                "dry_run":       record.get("dry_run", True),
                "scenario":      record.get("scenario"),
                "all_mitre":     [],
                "phases":        [],
                "_type":         "bananatree",
            }
        elif rt == "bananatree_phase_end" and current and current.get("_type") == "bananatree":
            current["phases"].append({
                "phase":       record.get("phase"),
                "layers_run":  record.get("layers_run", []),
                "findings":    record.get("findings", []),
                "mitre":       record.get("mitre_techniques", []),
                "errors":      record.get("errors", []),
            })
        elif rt == "bananatree_campaign_end" and current and current.get("_type") == "bananatree":
            current["completed_at"] = record.get("timestamp")
            current["total_layers"] = record.get("total_layers", 0)
            current["all_mitre"]    = record.get("all_mitre", [])
            runs.append(current)
            current = None

        # ── scenario records ─────────────────────────────────────────────────
        elif rt == "scenario_start":
            current = {
                "run_id":        record.get("scenario_id"),
                "campaign_name": record.get("scenario_name"),
                "timestamp":     record.get("timestamp"),
                "dry_run":       record.get("dry_run", True),
                "scenario":      record.get("scenario_name"),
                "all_mitre":     record.get("mitre_coverage", []),
                "phases":        [],
                "_type":         "scenario",
                "_stages":       [],
            }
        elif rt == "stage_start" and current and current.get("_type") == "scenario":
            current["_stages"].append(record.get("layer", ""))
        elif rt == "scenario_end" and current and current.get("_type") == "scenario":
            current["completed_at"] = record.get("timestamp")
            current["total_layers"] = record.get("stages_run", 0)
            # Synthesise a single phase containing all layers so score_run works
            current["phases"] = [{
                "phase":      "SCENARIO",
                "layers_run": current.pop("_stages", []),
                "findings":   [],
                "mitre":      current.get("all_mitre", []),
                "errors":     [],
            }]
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
