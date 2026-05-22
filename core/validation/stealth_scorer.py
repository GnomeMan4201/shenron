#!/usr/bin/env python3
# SHENRON: Stealth scorer
# Computes a 0-100 stealth score for a layer execution based on
# detection surface — fewer detectable signals = higher stealth.

import json
import os
from pathlib import Path
from typing import Optional

from core.reports.evidence import _load_manifest_index

# ── Penalty weights ───────────────────────────────────────────────────────────
_W_DETECTION_OP   = 3.0   # per detection_opportunity signal in artifact
_W_ALERT_SIG      = 4.0   # per alert_signature in manifest
_W_EXPECTED_EVENT = 2.0   # per expected_event in manifest
_W_LOG_SOURCE     = 2.5   # per log source exposed
_W_EXECUTABLE     = 20.0  # penalty if executable=True
_W_FILES_CREATED  = 10.0  # penalty if files_created=True
_BONUS_SAFE       = 5.0   # bonus if simulation_only + executable=False


def score_layer(layer_name: str, artifacts: list) -> int:
    """
    Compute stealth score (0-100) for a single layer given its artifacts.
    Lower detection surface = higher score.
    """
    manifest = _load_manifest_index()
    layer_artifacts = [
        a for a in artifacts
        if a.get('layer') == layer_name
    ]

    penalty = 0.0

    # ── Artifact-level penalties ─────────────────────────────────────────────
    detection_ops = set()
    for art in layer_artifacts:
        # detection opportunities
        dops = art.get('detection_opportunities', [])
        if isinstance(dops, list):
            for d in dops:
                detection_ops.add(str(d))

        # executable penalty
        if art.get('executable') is True:
            penalty += _W_EXECUTABLE

        # files created penalty
        if art.get('files_created') is True:
            penalty += _W_FILES_CREATED

        # safe flag collected — applied once below, not per artifact
        pass

    # one-time safe bonus if all artifacts are simulation_only and non-executable
    if layer_artifacts and all(
        a.get('simulation_only') is True and a.get('executable') is not True
        for a in layer_artifacts
    ):
        penalty -= _BONUS_SAFE

    penalty += len(detection_ops) * _W_DETECTION_OP

    # ── Manifest-level penalties ─────────────────────────────────────────────
    layer_data = manifest.get(layer_name, {})
    det = layer_data.get('detection', {})

    alert_sigs    = det.get('alert_signatures', [])
    expected_evts = det.get('expected_events', [])
    log_sources   = det.get('log_sources', [])

    penalty += len(alert_sigs)    * _W_ALERT_SIG
    penalty += len(expected_evts) * _W_EXPECTED_EVENT
    penalty += len(log_sources)   * _W_LOG_SOURCE

    score = max(0, min(100, round(100 - penalty)))
    return score


def score_layer_from_log(layer_name: str) -> int:
    """
    Load artifacts from the simulation log and score a layer.
    Returns -1 if no artifacts found for the layer.
    """
    log_path = Path(os.path.expanduser('~/SHENRON/logs/simulation_artifacts.jsonl'))
    if not log_path.exists():
        return -1

    artifacts = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if obj.get('layer') == layer_name:
                    artifacts.append(obj)
            except Exception:
                pass

    if not artifacts:
        # no artifacts — score from manifest only
        return score_layer(layer_name, [])

    return score_layer(layer_name, artifacts)


def score_all_layers() -> dict:
    """
    Score all layers that have artifacts in the simulation log.
    Returns {layer_name: score}.
    """
    log_path = Path(os.path.expanduser('~/SHENRON/logs/simulation_artifacts.jsonl'))
    if not log_path.exists():
        return {}

    # group artifacts by layer
    by_layer = {}
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                layer = obj.get('layer')
                if layer:
                    by_layer.setdefault(layer, []).append(obj)
            except Exception:
                pass

    return {
        layer: score_layer(layer, arts)
        for layer, arts in by_layer.items()
    }
