#!/usr/bin/env python3
# SHENRON: Expected detection loader
import json, re
from pathlib import Path
from typing import Optional
from core.validation.coverage import DetectionExpectation

MANIFEST_PATH = Path(__file__).parent.parent.parent / "shenron_manifest.json"


def _normalize(name: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace."""
    name = name.lower().strip()
    name = re.sub(r"-", "_", name)
    name = re.sub(r"[^a-z0-9_\s]", "", name)
    name = re.sub(r"[\s_]+", "_", name)
    return name


def load_from_scenario(scenario: dict) -> list:
    """Extract DetectionExpectation objects from all phases of a scenario."""
    expectations = []
    manifest = _load_manifest_index()

    for phase_name, phase_def in scenario.get("phases", {}).items():
        # expected_findings from scenario JSON
        for finding in phase_def.get("expected_findings", []):
            exp = DetectionExpectation(
                name       = finding,
                normalized = _normalize(finding),
                phase      = phase_name,
            )
            expectations.append(exp)

        # expected_events from manifest per layer
        for layer_name in phase_def.get("layers", []):
            layer_data = manifest.get(layer_name, {})
            for event in layer_data.get("detection", {}).get("expected_events", []):
                techs = layer_data.get("mitre", {}).get("techniques", [])
                exp = DetectionExpectation(
                    name            = event,
                    normalized      = _normalize(event),
                    layer           = layer_name,
                    mitre_technique = techs[0] if techs else None,
                    phase           = phase_name,
                )
                expectations.append(exp)

    # Deduplicate by normalized name
    seen = set()
    unique = []
    for e in expectations:
        if e.normalized not in seen:
            seen.add(e.normalized)
            unique.append(e)
    return unique


def load_from_scenario_file(path) -> list:
    p = Path(path)
    if not p.exists():
        return []
    scenario = json.loads(p.read_text())
    return load_from_scenario(scenario)


def _load_manifest_index() -> dict:
    if not MANIFEST_PATH.exists():
        return {}
    manifest = json.loads(MANIFEST_PATH.read_text())
    return {layer["name"]: layer for layer in manifest.get("layers", [])}
