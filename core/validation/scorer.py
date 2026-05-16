#!/usr/bin/env python3
# SHENRON: Detector validation scorer
import json
from pathlib import Path
from typing import Optional
from core.validation.coverage import (
    DetectionExpectation, DetectionResult, DetectionStatus,
    DetectionCoverageReport,
)
from core.validation.expectations import _normalize, load_from_scenario
from core.reports.evidence import (
    load_artifacts, load_timeline, get_campaign_runs,
    group_artifacts_by_layer, verify_safety, _load_manifest_index,
)

from core.config import artifact_log_path as _artifact_log_path, timeline_log_path as _timeline_log_path


# ── Matching helpers ──────────────────────────────────────────────────────────

def _tokens(s: str) -> set:
    return set(_normalize(s).split("_"))


def _exact_match(exp_norm: str, candidate: str) -> bool:
    return exp_norm == _normalize(candidate)


def _partial_match(exp_norm: str, candidate: str) -> bool:
    exp_tokens = _tokens(exp_norm)
    cand_tokens = _tokens(candidate)
    if not exp_tokens:
        return False
    overlap = exp_tokens & cand_tokens
    return len(overlap) / len(exp_tokens) >= 0.5


def _artifact_signals(artifact: dict) -> list:
    """Extract all matchable signal strings from an artifact."""
    signals = []
    for field in ["behavior_class", "phase", "detection_opportunities",
                  "expected_events", "alert_signatures"]:
        val = artifact.get(field)
        if isinstance(val, str):
            signals.append(val)
        elif isinstance(val, list):
            signals.extend(str(v) for v in val)
    # Also check nested detection_opportunities
    for key, val in artifact.items():
        if isinstance(val, dict):
            for sub in val.values():
                if isinstance(sub, list):
                    signals.extend(str(s) for s in sub)
    return signals


def _match_expectation(
    exp: DetectionExpectation,
    artifacts_by_layer: dict,
    all_artifacts: list,
    manifest: dict,
) -> DetectionResult:
    result = DetectionResult(expectation=exp)

    # Candidate artifacts: prefer layer-specific, fall back to all
    candidates = []
    if exp.layer and exp.layer in artifacts_by_layer:
        candidates = artifacts_by_layer[exp.layer]
    else:
        candidates = all_artifacts

    # Also check manifest alert_signatures and expected_events for all layers
    manifest_signals = []
    for layer_name, layer_data in manifest.items():
        det = layer_data.get("detection", {})
        for sig in det.get("alert_signatures", []):
            manifest_signals.append((layer_name, sig))
        for evt in det.get("expected_events", []):
            manifest_signals.append((layer_name, evt))

    # 1. Exact match against artifact signals
    for art in candidates:
        signals = _artifact_signals(art)
        for sig in signals:
            if _exact_match(exp.normalized, sig):
                result.status        = DetectionStatus.PASS
                result.matched_layer = art.get("layer", exp.layer)
                result.matched_artifact = art.get("artifact_id", "")
                result.match_reason  = f"exact match on '{sig}'"
                result.evidence_count += 1
                return result

    # 2. Exact match against manifest signals
    for layer_name, sig in manifest_signals:
        if _exact_match(exp.normalized, sig):
            result.status        = DetectionStatus.PASS
            result.matched_layer = layer_name
            result.match_reason  = f"manifest exact match on '{sig}'"
            result.evidence_count = 1
            return result

    # 3. Partial match against artifact signals
    for art in candidates:
        signals = _artifact_signals(art)
        for sig in signals:
            if _partial_match(exp.normalized, sig):
                result.status        = DetectionStatus.PARTIAL
                result.matched_layer = art.get("layer", exp.layer)
                result.match_reason  = f"partial match on '{sig}'"
                result.evidence_count += 1

    if result.status == DetectionStatus.PARTIAL:
        return result

    # 4. Partial match against manifest
    for layer_name, sig in manifest_signals:
        if _partial_match(exp.normalized, sig):
            result.status        = DetectionStatus.PARTIAL
            result.matched_layer = layer_name
            result.match_reason  = f"manifest partial match on '{sig}'"
            result.evidence_count = 1
            return result

    # 5. MITRE technique match
    if exp.mitre_technique:
        for art in all_artifacts:
            techs = art.get("mitre_techniques", [])
            if exp.mitre_technique in techs:
                result.status        = DetectionStatus.PARTIAL
                result.matched_layer = art.get("layer", "")
                result.match_reason  = f"MITRE technique match {exp.mitre_technique}"
                result.evidence_count += 1
                return result

    result.status       = DetectionStatus.MISS
    result.match_reason = "no matching artifact or manifest signal found"
    return result


# ── Main scorer ───────────────────────────────────────────────────────────────

def score_run(run: dict, artifacts: list, scenario: Optional[dict] = None) -> DetectionCoverageReport:
    manifest = _load_manifest_index()

    all_layer_names = set()
    for phase in run.get("phases", []):
        for l in phase.get("layers_run", []):
            all_layer_names.add(l)

    # All artifacts for this run (for safety checking)
    all_run_artifacts = [
        a for a in artifacts
        if a.get("layer") in all_layer_names
        and "artifact_id" in a
    ]
    # Only simulation_only=True artifacts for scoring
    run_artifacts = [
        a for a in all_run_artifacts
        if a.get("simulation_only") is True
    ]

    artifacts_by_layer = group_artifacts_by_layer(run_artifacts)

    # Safety check
    safety = verify_safety(all_run_artifacts)
    safety_failures = len(safety.violations)

    # High signal events
    high_signal = sum(
        1 for a in run_artifacts
        if a.get("detection_opportunities") or a.get("alert_signatures")
    )

    # Load expectations
    expectations = []
    if scenario:
        expectations = load_from_scenario(scenario)
    else:
        # Build from manifest data for layers in this run
        for layer_name in all_layer_names:
            layer_data = manifest.get(layer_name, {})
            det = layer_data.get("detection", {})
            for evt in det.get("expected_events", []):
                from core.validation.expectations import DetectionExpectation, _normalize
                expectations.append(DetectionExpectation(
                    name=evt, normalized=_normalize(evt), layer=layer_name
                ))

    # Score each expectation
    results = []
    for exp in expectations:
        result = _match_expectation(exp, artifacts_by_layer, run_artifacts, manifest)
        results.append(result)

    report = DetectionCoverageReport(
        run_id               = run.get("run_id", ""),
        campaign_name        = run.get("campaign_name", ""),
        scenario_path        = run.get("scenario", ""),
        high_signal_count    = high_signal,
        safety_failure_count = safety_failures,
        results              = results,
    )
    report.compute()
    return report


def score_latest(scenario: Optional[dict] = None) -> Optional[DetectionCoverageReport]:
    timeline  = load_timeline()
    artifacts = load_artifacts()
    runs = get_campaign_runs(timeline)
    if not runs:
        return None
    return score_run(runs[-1], artifacts, scenario)


def score_by_run_id(run_id: str, scenario: Optional[dict] = None) -> Optional[DetectionCoverageReport]:
    timeline  = load_timeline()
    artifacts = load_artifacts()
    runs = get_campaign_runs(timeline)
    for run in reversed(runs):
        if run.get("run_id") == run_id:
            return score_run(run, artifacts, scenario)
    return None
