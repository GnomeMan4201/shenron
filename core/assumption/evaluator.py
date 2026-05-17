#!/usr/bin/env python3
# SHENRON: Assumption evaluator
# Scores a CoverageAssumption against a set of JSONL telemetry records.
# No subprocess, no network, no execution.

import re
from dataclasses import dataclass, field
from typing import List, Optional

from core.assumption.parser import CoverageAssumption


# ── Result dataclasses ────────────────────────────────────────────────────────

@dataclass
class ClaimResult:
    claim:          str
    verdict:        str       # "SUPPORTED" | "PARTIAL" | "UNSUPPORTED" | "UNTESTED"
    evidence:       List[str] = field(default_factory=list)
    note:           str       = ""


@dataclass
class TechniqueResult:
    technique:      str
    status:         str       # "OBSERVED" | "MISSING"
    matched_signal: Optional[str] = None


@dataclass
class SignalResult:
    signal:         str
    status:         str       # "OBSERVED" | "MISSING"
    matched_field:  Optional[str] = None


@dataclass
class PhaseResult:
    phase:          str
    status:         str       # "OBSERVED" | "MISSING"
    event_count:    int       = 0


@dataclass
class AssumptionAuditResult:
    assumption_name:        str
    assumption_description: str
    source_path:            Optional[str]
    records_checked:        int
    safety_violations:      int

    claim_results:          List[ClaimResult]      = field(default_factory=list)
    technique_results:      List[TechniqueResult]  = field(default_factory=list)
    signal_results:         List[SignalResult]      = field(default_factory=list)
    phase_results:          List[PhaseResult]       = field(default_factory=list)

    # Aggregates
    techniques_observed:    List[str] = field(default_factory=list)
    techniques_missing:     List[str] = field(default_factory=list)
    signals_observed:       List[str] = field(default_factory=list)
    signals_missing:        List[str] = field(default_factory=list)
    phases_observed:        List[str] = field(default_factory=list)
    phases_missing:         List[str] = field(default_factory=list)
    claims_supported:       int       = 0
    claims_partial:         int       = 0
    claims_unsupported:     int       = 0
    verdict:                str       = "UNKNOWN"
    coverage_percent:       float     = 0.0


# ── Normalization ─────────────────────────────────────────────────────────────

def _normalize(s: str) -> str:
    s = s.lower().strip()
    s = re.sub(r"[-\s]+", "_", s)
    s = re.sub(r"[^a-z0-9_]", "", s)
    return s


def _tokens(s: str) -> set:
    return set(_normalize(s).split("_"))


def _partial_match(a: str, b: str) -> bool:
    ta, tb = _tokens(a), _tokens(b)
    if not ta:
        return False
    return len(ta & tb) / len(ta) >= 0.5


# ── Signal extraction from records ───────────────────────────────────────────

def _extract_signals(record: dict) -> list:
    signals = []
    for field_name in [
        "signal", "behavior_class", "phase", "event_type",
        "detection_opportunities", "expected_events", "alert_signatures",
    ]:
        val = record.get(field_name)
        if isinstance(val, str) and val:
            signals.append(val)
        elif isinstance(val, list):
            signals.extend(str(v) for v in val if v)
    return signals


def _extract_techniques(record: dict) -> list:
    techs = []
    for field_name in ["mitre_technique", "mitre_techniques"]:
        val = record.get(field_name)
        if isinstance(val, str) and val:
            techs.append(val.strip())
        elif isinstance(val, list):
            techs.extend(str(v).strip() for v in val if v)
    return techs


# ── Claim scoring ─────────────────────────────────────────────────────────────

def _score_claim(claim: str, records: list) -> ClaimResult:
    """
    Score a single claim string against all records.
    Uses keyword overlap to find supporting evidence.
    """
    claim_norm = _normalize(claim)
    evidence = []

    for record in records:
        signals = _extract_signals(record)
        for sig in signals:
            if _partial_match(claim_norm, sig):
                layer = record.get("layer", "unknown")
                evidence.append(f"{sig} (layer: {layer})")
                break

    if len(evidence) >= 2:
        verdict = "SUPPORTED"
    elif len(evidence) == 1:
        verdict = "PARTIAL"
    else:
        verdict = "UNSUPPORTED"

    note = ""
    if verdict == "UNSUPPORTED":
        note = "No matching signals found in artifact records."
    elif verdict == "PARTIAL":
        note = "Weak signal match — only one supporting record found."

    return ClaimResult(
        claim=claim,
        verdict=verdict,
        evidence=evidence[:5],
        note=note,
    )


# ── Main evaluator ────────────────────────────────────────────────────────────

def evaluate(
    assumption: CoverageAssumption,
    records: list,
) -> AssumptionAuditResult:
    """
    Evaluate a CoverageAssumption against a list of JSONL records.
    Returns a fully populated AssumptionAuditResult.
    """
    # Safety check
    safety_violations = sum(
        1 for r in records
        if r.get("safety", {}).get("simulation_only") is not True
    )

    # Build index structures
    all_techniques = set()
    all_signals    = set()
    all_phases     = set()

    for r in records:
        all_techniques.update(_extract_techniques(r))
        all_signals.update(_extract_signals(r))
        phase = r.get("phase", "")
        if phase:
            all_phases.add(phase.upper())

    # Score techniques
    technique_results = []
    techniques_observed = []
    techniques_missing  = []
    for t in assumption.expected_techniques:
        if t in all_techniques:
            technique_results.append(TechniqueResult(t, "OBSERVED"))
            techniques_observed.append(t)
        else:
            technique_results.append(TechniqueResult(t, "MISSING"))
            techniques_missing.append(t)

    # Score signals
    signal_results   = []
    signals_observed = []
    signals_missing  = []
    for sig in assumption.expected_signals:
        sig_norm = _normalize(sig)
        matched = None
        for observed in all_signals:
            if _normalize(observed) == sig_norm or _partial_match(sig_norm, observed):
                matched = observed
                break
        if matched:
            signal_results.append(SignalResult(sig, "OBSERVED", matched_field=matched))
            signals_observed.append(sig)
        else:
            signal_results.append(SignalResult(sig, "MISSING"))
            signals_missing.append(sig)

    # Score phases
    phase_results   = []
    phases_observed = []
    phases_missing  = []
    for phase in assumption.expected_phases:
        phase_up = phase.upper()
        count = sum(1 for r in records if r.get("phase", "").upper() == phase_up)
        if count > 0:
            phase_results.append(PhaseResult(phase_up, "OBSERVED", count))
            phases_observed.append(phase_up)
        else:
            phase_results.append(PhaseResult(phase_up, "MISSING", 0))
            phases_missing.append(phase_up)

    # Score claims
    claim_results      = []
    claims_supported   = 0
    claims_partial     = 0
    claims_unsupported = 0
    for claim in assumption.claims:
        cr = _score_claim(claim, records)
        claim_results.append(cr)
        if cr.verdict == "SUPPORTED":
            claims_supported += 1
        elif cr.verdict == "PARTIAL":
            claims_partial += 1
        else:
            claims_unsupported += 1

    # Coverage percent — weighted across all checked dimensions
    total_items = (
        len(assumption.expected_techniques) +
        len(assumption.expected_signals) +
        len(assumption.expected_phases) +
        len(assumption.claims)
    )
    observed_items = (
        len(techniques_observed) +
        len(signals_observed) +
        len(phases_observed) +
        claims_supported +
        (claims_partial * 0.5)
    )
    coverage_percent = round(
        (observed_items / total_items * 100) if total_items > 0 else 0.0, 1
    )

    # Verdict
    if safety_violations > 0:
        verdict = "UNSAFE"
    elif claims_unsupported > 0 or techniques_missing or signals_missing or phases_missing:
        verdict = "PARTIAL" if coverage_percent >= 50.0 else "FAIL"
    else:
        verdict = "PASS"

    return AssumptionAuditResult(
        assumption_name        = assumption.name,
        assumption_description = assumption.description,
        source_path            = assumption.source_path,
        records_checked        = len(records),
        safety_violations      = safety_violations,
        claim_results          = claim_results,
        technique_results      = technique_results,
        signal_results         = signal_results,
        phase_results          = phase_results,
        techniques_observed    = techniques_observed,
        techniques_missing     = techniques_missing,
        signals_observed       = signals_observed,
        signals_missing        = signals_missing,
        phases_observed        = phases_observed,
        phases_missing         = phases_missing,
        claims_supported       = claims_supported,
        claims_partial         = claims_partial,
        claims_unsupported     = claims_unsupported,
        verdict                = verdict,
        coverage_percent       = coverage_percent,
    )
