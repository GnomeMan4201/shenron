#!/usr/bin/env python3
# bananaTREE: Scenario Runner
import json, sys, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.bananatree.cycle import BananaTreeCycle, Phase, PhaseResult, SAFETY_CONTRACT
from core.engine.layer_loader import discover_canonical, load_layer
from core.engine import payload_registry

ARTIFACT_LOG  = Path("/home/gnomeman4201/SHENRON/logs/simulation_artifacts.jsonl")
TIMELINE_LOG  = Path("/home/gnomeman4201/SHENRON/logs/scenario_timelines.jsonl")
MANIFEST_PATH = Path(__file__).parent.parent.parent / "shenron_manifest.json"


def _load_manifest_index() -> dict:
    if not MANIFEST_PATH.exists():
        return {}
    manifest = json.loads(MANIFEST_PATH.read_text())
    return {layer["name"]: layer for layer in manifest.get("layers", [])}


def _write_timeline(record: dict):
    TIMELINE_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(TIMELINE_LOG, "a") as f:
        f.write(json.dumps(record) + "\n")


class ScenarioValidationError(Exception):
    pass


def load_scenario(path) -> dict:
    p = Path(path)
    if not p.exists():
        raise ScenarioValidationError(f"Scenario not found: {path}")
    scenario = json.loads(p.read_text())
    for key in ["name", "phases"]:
        if key not in scenario:
            raise ScenarioValidationError(f"Scenario missing key: {key!r}")
    if not isinstance(scenario["phases"], dict):
        raise ScenarioValidationError("phases must be a dict")
    valid = {p.value for p in Phase}
    for phase_name in scenario["phases"]:
        if phase_name not in valid:
            raise ScenarioValidationError(f"Unknown phase {phase_name!r}. Valid: {valid}")
    return scenario


def validate_layers(scenario: dict, canonical: dict) -> list:
    unknown = []
    for phase_name, phase_def in scenario["phases"].items():
        for layer_name in phase_def.get("layers", []):
            if layer_name not in canonical:
                unknown.append(f"{phase_name}/{layer_name}")
    if unknown:
        raise ScenarioValidationError(f"Unknown layers: {unknown}")
    return []


def run_scenario(scenario_path, dry_run=True, campaign_name=None, verbose=True) -> BananaTreeCycle:
    scenario  = load_scenario(scenario_path)
    canonical = discover_canonical()
    manifest  = _load_manifest_index()
    validate_layers(scenario, canonical)

    cycle = BananaTreeCycle(
        campaign_name = campaign_name or scenario.get("name", "unnamed"),
        dry_run       = dry_run,
        scenario_path = str(scenario_path),
    )

    if verbose:
        print(f"\n  [bananaTREE]  {cycle.campaign_name}")
        print(f"  [RUN_ID]      {cycle.run_id}")
        print(f"  [MODE]        {'DRY RUN' if dry_run else 'SIMULATE'}")
        print()

    _write_timeline({
        "record_type": "bananatree_campaign_start",
        "run_id": cycle.run_id,
        "campaign_name": cycle.campaign_name,
        "timestamp": cycle.started_at,
        "dry_run": dry_run,
        "safety_contract": SAFETY_CONTRACT,
    })

    for phase_value, phase_def in scenario["phases"].items():
        phase  = Phase(phase_value)
        result = cycle.start_phase(phase)
        layers = phase_def.get("layers", [])

        if verbose:
            print(f"  ── {phase.value} ──")
            desc = phase_def.get("description", "")
            if desc:
                print(f"  {desc}")

        _write_timeline({
            "record_type": "bananatree_phase_start",
            "run_id": cycle.run_id,
            "phase": phase.value,
            "layers": layers,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        for layer_name in layers:
            if layer_name not in canonical:
                result.errors.append(f"unknown: {layer_name}")
                continue
            layer_data = manifest.get(layer_name, {})
            for t in layer_data.get("mitre", {}).get("techniques", []):
                if t not in result.mitre_techniques:
                    result.mitre_techniques.append(t)

            if verbose:
                print(f"  [{phase.value}] {layer_name}")

            if not dry_run:
                payload_registry.clear()
                ok, err = load_layer(layer_name, canonical[layer_name])
                if ok:
                    payload_registry.run(layer_name)
                    result.layers_run.append(layer_name)
                    if verbose:
                        print(f"           → executed")
                else:
                    result.errors.append(f"{layer_name}: {err}")
            else:
                result.layers_run.append(layer_name)
                if verbose:
                    print(f"           → dry-run-ok")

        for finding in phase_def.get("expected_findings", []):
            result.findings.append(finding)

        _write_timeline({
            "record_type": "bananatree_phase_end",
            "run_id": cycle.run_id,
            "phase": phase.value,
            "layers_run": result.layers_run,
            "findings": result.findings,
            "errors": result.errors,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        if verbose:
            print()

    cycle.complete()
    _write_timeline({
        "record_type": "bananatree_campaign_end",
        "run_id": cycle.run_id,
        "timestamp": cycle.completed_at,
        "total_layers": cycle.total_layers,
        "all_mitre": cycle.all_mitre,
    })

    if verbose:
        print(f"  [COMPLETE]  {cycle.total_layers} layers, {len(cycle.phases)} phases")
        print(f"  [MITRE]     {', '.join(cycle.all_mitre)}")
        print()

    return cycle
