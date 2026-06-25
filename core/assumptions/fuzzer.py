"""
core/assumptions/fuzzer.py

SHENRON Assumption Fuzzer.

Systematically mutates assumption YAML files to measure which claims your
detection posture is most sensitive to. Answers the question:

  "Which assumptions are load-bearing — and which are redundant?"

Mutation strategies:
  - claim_drop:        Remove one claim at a time, re-validate
  - technique_swap:    Replace a technique ID with a related but wrong one
  - technique_add:     Inject an unsupported technique requirement
  - signal_corrupt:    Corrupt a required signal name
  - signal_add:        Inject a signal that does not exist in the artifact
  - severity_escalate: Escalate all claim severities to HIGH
  - oos_inject:        Inject an out-of-scope claim that should trigger violation

Sensitivity score per claim:
  - 1.0 = removing/corrupting this claim changes the validation verdict
  - 0.0 = removing/corrupting this claim has no effect on verdict

Design constraints:
- New file only. Zero modifications to existing core files.
- Uses: core/assumptions/validator.py, core/assumptions/loader.py,
        core/assumptions/model.py
- No subprocess, no network, no real file writes outside output path.
"""

import copy
import json
import yaml
import tempfile
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

from core.assumptions.validator import validate_assumption
from core.assumptions.model import AssumptionStatus


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class ClaimFuzzResult:
    claim_id: str
    strategy: str
    original_status: str
    mutated_status: str
    verdict_changed: bool
    sensitivity_score: float
    note: str


@dataclass
class FuzzReport:
    assumption_id: str
    assumption_path: str
    artifact_path: str
    generated_at: str
    original_status: str
    total_mutations: int
    verdict_changing_mutations: int
    claim_sensitivity: Dict[str, float]
    most_sensitive_claim: str
    least_sensitive_claim: str
    load_bearing_claims: List[str]
    redundant_claims: List[str]
    results: List[ClaimFuzzResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "assumption_id": self.assumption_id,
            "assumption_path": self.assumption_path,
            "artifact_path": self.artifact_path,
            "generated_at": self.generated_at,
            "original_status": self.original_status,
            "total_mutations": self.total_mutations,
            "verdict_changing_mutations": self.verdict_changing_mutations,
            "claim_sensitivity": self.claim_sensitivity,
            "most_sensitive_claim": self.most_sensitive_claim,
            "least_sensitive_claim": self.least_sensitive_claim,
            "load_bearing_claims": self.load_bearing_claims,
            "redundant_claims": self.redundant_claims,
            "results": [
                {
                    "claim_id": r.claim_id,
                    "strategy": r.strategy,
                    "original_status": r.original_status,
                    "mutated_status": r.mutated_status,
                    "verdict_changed": r.verdict_changed,
                    "sensitivity_score": r.sensitivity_score,
                    "note": r.note,
                }
                for r in self.results
            ],
        }

    def to_markdown(self) -> str:
        lines = [
            "# SHENRON Assumption Fuzz Report",
            "",
            f"**Assumption:** {self.assumption_id}  ",
            f"**Artifact:** {self.artifact_path}  ",
            f"**Generated:** {self.generated_at}  ",
            f"**Original Status:** {self.original_status}  ",
            f"**Total Mutations:** {self.total_mutations}  ",
            f"**Verdict-Changing Mutations:** {self.verdict_changing_mutations}  ",
            "",
            "## Claim Sensitivity",
            "",
            "| Claim | Sensitivity | Load-Bearing |",
            "|-------|------------|-------------|",
        ]
        for claim_id, score in sorted(
            self.claim_sensitivity.items(), key=lambda x: x[1], reverse=True
        ):
            lb = "YES" if claim_id in self.load_bearing_claims else "no"
            lines.append(f"| {claim_id} | {score:.2f} | {lb} |")

        lines += [
            "",
            "## Load-Bearing Claims",
            "*(Removing or corrupting these changes the validation verdict)*",
            "",
        ]
        if self.load_bearing_claims:
            for c in self.load_bearing_claims:
                lines.append(f"- **{c}**")
        else:
            lines.append("*(none — assumption may be over-specified or artifact is comprehensive)*")

        lines += [
            "",
            "## Redundant Claims",
            "*(These claims can be removed without changing the verdict)*",
            "",
        ]
        if self.redundant_claims:
            for c in self.redundant_claims:
                lines.append(f"- {c}")
        else:
            lines.append("*(none — all claims are load-bearing)*")

        lines += [
            "",
            "## Full Mutation Results",
            "",
            "| Claim | Strategy | Original | Mutated | Changed |",
            "|-------|----------|----------|---------|---------|",
        ]
        for r in self.results:
            changed = "YES" if r.verdict_changed else "no"
            lines.append(
                f"| {r.claim_id} | {r.strategy} | {r.original_status} | "
                f"{r.mutated_status} | {changed} |"
            )
        return "\n".join(lines)


# ── YAML loader ────────────────────────────────────────────────────────────────

def _load_assumption_yaml(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _write_temp_assumption(data: dict) -> str:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    ) as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
        return f.name


# ── Mutation strategies ────────────────────────────────────────────────────────

# Technique IDs that are similar but wrong — used for swap mutations
_TECHNIQUE_SWAPS = {
    "T1071": "T1095",
    "T1095": "T1071",
    "T1053": "T1543",
    "T1543": "T1053",
    "T1055": "T1134",
    "T1134": "T1055",
    "T1027": "T1140",
    "T1140": "T1027",
    "T1036": "T1014",
    "T1014": "T1036",
    "T1021": "T1570",
    "T1570": "T1021",
    "T1070": "T1107",
    "T1589": "T1592",
    "T1592": "T1589",
}

_NOISE_TECHNIQUES = ["T1999", "T1998", "T1997", "T1996"]
_NOISE_SIGNALS = [
    "nonexistent_signal_xyz",
    "phantom_detection_opportunity",
    "ghost_behavior_class",
    "synthetic_signal_not_in_artifact",
]
_OOS_TECHNIQUES = ["T1485", "T1486", "T1490"]  # impact techniques unlikely in most artifacts


def _mutate_claim_drop(assumption: dict, claim_idx: int) -> Tuple[dict, str]:
    """Remove claim at index from the claims list."""
    mutated = copy.deepcopy(assumption)
    claims = mutated.get("claims", [])
    if claim_idx >= len(claims):
        return mutated, "no-op"
    removed = claims.pop(claim_idx)
    claim_id = removed.get("id", f"claim_{claim_idx}")
    return mutated, f"dropped claim {claim_id}"


def _mutate_technique_swap(assumption: dict, claim_idx: int) -> Tuple[dict, str]:
    """Replace technique IDs in one claim with wrong-but-plausible ones."""
    mutated = copy.deepcopy(assumption)
    claims = mutated.get("claims", [])
    if claim_idx >= len(claims):
        return mutated, "no-op"
    claim = claims[claim_idx]
    techs = claim.get("requires_techniques", [])
    if not techs:
        return mutated, "no-op (no techniques)"
    swapped = [_TECHNIQUE_SWAPS.get(t, t + "999") for t in techs]
    claim["requires_techniques"] = swapped
    return mutated, f"swapped techniques {techs} -> {swapped}"


def _mutate_technique_add(assumption: dict, claim_idx: int,
                           noise_idx: int = 0) -> Tuple[dict, str]:
    """Add an unsupported technique requirement to one claim."""
    mutated = copy.deepcopy(assumption)
    claims = mutated.get("claims", [])
    if claim_idx >= len(claims):
        return mutated, "no-op"
    noise_tech = _NOISE_TECHNIQUES[noise_idx % len(_NOISE_TECHNIQUES)]
    claim = claims[claim_idx]
    claim.setdefault("requires_techniques", []).append(noise_tech)
    return mutated, f"added unsupported technique {noise_tech}"


def _mutate_signal_corrupt(assumption: dict, claim_idx: int) -> Tuple[dict, str]:
    """Corrupt a required signal name in one claim."""
    mutated = copy.deepcopy(assumption)
    claims = mutated.get("claims", [])
    if claim_idx >= len(claims):
        return mutated, "no-op"
    claim = claims[claim_idx]
    signals = claim.get("requires_signals", [])
    if not signals:
        return mutated, "no-op (no signals)"
    claim["requires_signals"] = [s + "_CORRUPTED" for s in signals]
    return mutated, f"corrupted signals {signals}"


def _mutate_signal_add(assumption: dict, claim_idx: int,
                        noise_idx: int = 0) -> Tuple[dict, str]:
    """Inject a phantom signal requirement into one claim."""
    mutated = copy.deepcopy(assumption)
    claims = mutated.get("claims", [])
    if claim_idx >= len(claims):
        return mutated, "no-op"
    noise_sig = _NOISE_SIGNALS[noise_idx % len(_NOISE_SIGNALS)]
    claim = claims[claim_idx]
    claim.setdefault("requires_signals", []).append(noise_sig)
    return mutated, f"added phantom signal {noise_sig}"


def _mutate_severity_escalate(assumption: dict, claim_idx: int) -> Tuple[dict, str]:
    """Escalate claim severity to HIGH."""
    mutated = copy.deepcopy(assumption)
    claims = mutated.get("claims", [])
    if claim_idx >= len(claims):
        return mutated, "no-op"
    original = claims[claim_idx].get("severity", "medium")
    claims[claim_idx]["severity"] = "high"
    return mutated, f"severity {original} -> high"


def _mutate_oos_inject(assumption: dict, noise_idx: int = 0) -> Tuple[dict, str]:
    """Inject an out-of-scope claim that should trigger a violation."""
    mutated = copy.deepcopy(assumption)
    oos_tech = _OOS_TECHNIQUES[noise_idx % len(_OOS_TECHNIQUES)]
    oos_claim = {
        "id": f"fuzz_oos_injection_{noise_idx}",
        "type": "out_of_scope_claim",
        "severity": "high",
        "description": "Fuzzer-injected OOS claim",
        "requires_techniques": [oos_tech],
        "requires_signals": [],
    }
    mutated.setdefault("claims", []).append(oos_claim)
    return mutated, f"injected OOS claim requiring {oos_tech}"


# ── Evaluator ──────────────────────────────────────────────────────────────────

def _run_mutated(mutated_assumption: dict, artifact_path: str) -> str:
    """Write mutated assumption to temp file, validate, return status string."""
    tmp = _write_temp_assumption(mutated_assumption)
    try:
        result = validate_assumption(tmp, artifact_path)
        return result.status.value
    except Exception as e:
        return f"ERROR: {e}"
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass


def _verdict_changed(original: str, mutated: str) -> bool:
    """Return True if the validation verdict meaningfully changed."""
    if original == mutated:
        return False
    if "ERROR" in mutated:
        return False
    return True


# ── Main fuzzer ────────────────────────────────────────────────────────────────

def fuzz_assumption(
    assumption_path: str,
    artifact_path: str,
    strategies: Optional[List[str]] = None,
    verbose: bool = True,
) -> FuzzReport:
    """
    Fuzz an assumption YAML against a SHENRON artifact.

    Args:
        assumption_path: Path to assumption YAML file
        artifact_path:   Path to SHENRON JSONL artifact
        strategies:      List of mutation strategies to apply (default: all)
        verbose:         Print progress

    Returns:
        FuzzReport with sensitivity scores per claim
    """
    now = datetime.now(timezone.utc).isoformat()

    # Load original assumption
    assumption = _load_assumption_yaml(assumption_path)
    assumption_id = assumption.get("id", Path(assumption_path).stem)
    claims = assumption.get("claims", [])

    # Get original validation status
    original_result = validate_assumption(assumption_path, artifact_path)
    original_status = original_result.status.value

    if verbose:
        print(f"\n  [FUZZ] Assumption  : {assumption_id}")
        print(f"  [FUZZ] Claims      : {len(claims)}")
        print(f"  [FUZZ] Artifact    : {artifact_path}")
        print(f"  [FUZZ] Orig status : {original_status}")
        print()

    all_strategies = strategies or [
        "claim_drop", "technique_swap", "technique_add",
        "signal_corrupt", "signal_add", "oos_inject",
    ]

    fuzz_results: List[ClaimFuzzResult] = []
    claim_sensitivity_scores: Dict[str, List[float]] = {}

    for i, claim in enumerate(claims):
        claim_id = claim.get("id", f"claim_{i}")
        claim_sensitivity_scores[claim_id] = []

        for strategy in all_strategies:
            if strategy == "oos_inject":
                # OOS inject is global, not per-claim
                continue

            # Build mutated assumption
            if strategy == "claim_drop":
                mutated, note = _mutate_claim_drop(assumption, i)
            elif strategy == "technique_swap":
                mutated, note = _mutate_technique_swap(assumption, i)
            elif strategy == "technique_add":
                mutated, note = _mutate_technique_add(assumption, i, i)
            elif strategy == "signal_corrupt":
                mutated, note = _mutate_signal_corrupt(assumption, i)
            elif strategy == "signal_add":
                mutated, note = _mutate_signal_add(assumption, i, i)
            elif strategy == "severity_escalate":
                mutated, note = _mutate_severity_escalate(assumption, i)
            else:
                continue

            if note == "no-op" or note.startswith("no-op"):
                sensitivity = 0.0
                mutated_status = original_status
                changed = False
            else:
                mutated_status = _run_mutated(mutated, artifact_path)
                changed = _verdict_changed(original_status, mutated_status)
                sensitivity = 1.0 if changed else 0.0

            claim_sensitivity_scores[claim_id].append(sensitivity)

            fuzz_results.append(ClaimFuzzResult(
                claim_id=claim_id,
                strategy=strategy,
                original_status=original_status,
                mutated_status=mutated_status,
                verdict_changed=changed,
                sensitivity_score=sensitivity,
                note=note,
            ))

            if verbose:
                mark = "!" if changed else "."
                print(f"  [{mark}] {claim_id:<35} {strategy:<20} {mutated_status}")

    # OOS inject (global, not per-claim)
    if "oos_inject" in all_strategies:
        for idx in range(min(3, len(_OOS_TECHNIQUES))):
            mutated, note = _mutate_oos_inject(assumption, idx)
            mutated_status = _run_mutated(mutated, artifact_path)
            changed = _verdict_changed(original_status, mutated_status)
            fuzz_results.append(ClaimFuzzResult(
                claim_id="(global)",
                strategy=f"oos_inject_{idx}",
                original_status=original_status,
                mutated_status=mutated_status,
                verdict_changed=changed,
                sensitivity_score=1.0 if changed else 0.0,
                note=note,
            ))
            if verbose:
                mark = "!" if changed else "."
                print(f"  [{mark}] {'(global)':<35} oos_inject_{idx:<16} {mutated_status}")

    # Compute per-claim sensitivity
    claim_sensitivity = {
        cid: round(sum(scores) / len(scores), 3) if scores else 0.0
        for cid, scores in claim_sensitivity_scores.items()
    }

    load_bearing = [cid for cid, s in claim_sensitivity.items() if s >= 0.5]
    redundant = [cid for cid, s in claim_sensitivity.items() if s == 0.0]

    most_sensitive = max(claim_sensitivity, key=claim_sensitivity.get) if claim_sensitivity else ""
    least_sensitive = min(claim_sensitivity, key=claim_sensitivity.get) if claim_sensitivity else ""

    verdict_changing = sum(1 for r in fuzz_results if r.verdict_changed)

    if verbose:
        print()
        print(f"  [FUZZ] Total mutations       : {len(fuzz_results)}")
        print(f"  [FUZZ] Verdict-changing      : {verdict_changing}")
        print(f"  [FUZZ] Load-bearing claims   : {load_bearing}")
        print(f"  [FUZZ] Redundant claims      : {redundant}")
        print()

    return FuzzReport(
        assumption_id=assumption_id,
        assumption_path=assumption_path,
        artifact_path=artifact_path,
        generated_at=now,
        original_status=original_status,
        total_mutations=len(fuzz_results),
        verdict_changing_mutations=verdict_changing,
        claim_sensitivity=claim_sensitivity,
        most_sensitive_claim=most_sensitive,
        least_sensitive_claim=least_sensitive,
        load_bearing_claims=load_bearing,
        redundant_claims=redundant,
        results=fuzz_results,
    )
