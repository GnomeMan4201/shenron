"""
core/campaign/adaptation.py

SHENRON Adversary Adaptation Engine.

Simulates an adversary that observes which detection rules fire on their
campaign and mutates to evade them. Measures how many adaptation iterations
are required before the campaign goes undetected across a rule set.

This is the feedback loop nobody has built:
  Campaign → Sigma evaluation → rules fire → adversary mutates →
  re-evaluate → repeat until undetected or max iterations reached.

Key metrics:
  - iterations_to_evasion: how many mutations before all rules stop firing
  - rules_evaded: which specific rules were neutralized
  - surviving_rules: rules that fired throughout all iterations
  - adaptation_path: the sequence of mutations applied
  - evasion_achieved: whether full evasion was reached

Design constraints:
- New file only. Zero modifications to existing core files.
- Uses: core/campaign/builder.py, core/mutation/sigma_aware.py,
        core/mutation/engine.py, core/sigma/evaluator.py,
        core/sigma/loader.py, core/sigma/model.py
- No subprocess, no network, no execution.
- All mutations preserve the safety contract.
"""

import json
import os
import copy
import uuid
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

from core.sigma.evaluator import evaluate_sigma_rule
from core.sigma.model import RuleVerdict
from core.mutation.engine import (
    mutate_field_drop,
    mutate_timing_jitter,
    mutate_label_ambiguity,
    mutate_signal_density_low,
    mutate_technique_noise,
    mutate_phase_imbalance,
)
from core.mutation.sigma_aware import SigmaAwareMutator


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class RuleFireResult:
    rule_id: str
    rule_title: str
    rule_path: str
    verdict: str
    triggered: bool


@dataclass
class AdaptationIteration:
    iteration: int
    mutation_applied: str
    mutation_run_id: str
    rules_fired: List[RuleFireResult]
    rules_fired_count: int
    rules_evaded_count: int
    evasion_rate: float
    artifact_event_count: int
    safety_intact: bool


@dataclass
class AdaptationReport:
    campaign_id: str
    scenario_name: str
    rules_dir_primary: str
    rules_dir_secondary: str
    generated_at: str
    total_rules_evaluated: int
    rules_firing_on_original: int
    iterations_run: int
    iterations_to_evasion: Optional[int]
    evasion_achieved: bool
    surviving_rules: List[str]
    evaded_rules: List[str]
    adaptation_path: List[str]
    iterations: List[AdaptationIteration] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "campaign_id": self.campaign_id,
            "scenario_name": self.scenario_name,
            "rules_dir_primary": self.rules_dir_primary,
            "rules_dir_secondary": self.rules_dir_secondary,
            "generated_at": self.generated_at,
            "total_rules_evaluated": self.total_rules_evaluated,
            "rules_firing_on_original": self.rules_firing_on_original,
            "iterations_run": self.iterations_run,
            "iterations_to_evasion": self.iterations_to_evasion,
            "evasion_achieved": self.evasion_achieved,
            "surviving_rules": self.surviving_rules,
            "evaded_rules": self.evaded_rules,
            "adaptation_path": self.adaptation_path,
            "iterations": [
                {
                    "iteration": it.iteration,
                    "mutation_applied": it.mutation_applied,
                    "rules_fired_count": it.rules_fired_count,
                    "rules_evaded_count": it.rules_evaded_count,
                    "evasion_rate": it.evasion_rate,
                    "artifact_event_count": it.artifact_event_count,
                    "safety_intact": it.safety_intact,
                }
                for it in self.iterations
            ],
        }

    def to_markdown(self) -> str:
        evasion_str = (
            f"**YES** — achieved in {self.iterations_to_evasion} iteration(s)"
            if self.evasion_achieved
            else f"**NO** — {len(self.surviving_rules)} rule(s) survived all {self.iterations_run} iterations"
        )
        lines = [
            "# SHENRON Adversary Adaptation Report",
            "",
            f"**Campaign:** {self.scenario_name} (`{self.campaign_id[:16]}...`)  ",
            f"**Generated:** {self.generated_at}  ",
            f"**Rules Evaluated:** {self.total_rules_evaluated}  ",
            f"**Rules Firing on Original:** {self.rules_firing_on_original}  ",
            f"**Iterations Run:** {self.iterations_run}  ",
            f"**Full Evasion Achieved:** {evasion_str}  ",
            "",
            "## Adaptation Path",
            "",
            " → ".join(self.adaptation_path) if self.adaptation_path else "*(no mutations applied)*",
            "",
            "## Per-Iteration Results",
            "",
            "| Iteration | Mutation | Rules Fired | Evaded | Evasion Rate |",
            "|-----------|----------|------------|--------|-------------|",
        ]
        for it in self.iterations:
            lines.append(
                f"| {it.iteration} | {it.mutation_applied} | "
                f"{it.rules_fired_count} | {it.rules_evaded_count} | "
                f"{it.evasion_rate:.2f} |"
            )
        lines += [
            "",
            "## Evaded Rules",
            "",
        ]
        if self.evaded_rules:
            for r in self.evaded_rules:
                lines.append(f"- {r}")
        else:
            lines.append("*(none)*")
        lines += [
            "",
            "## Surviving Rules (Detection-Robust)",
            "",
        ]
        if self.surviving_rules:
            for r in self.surviving_rules:
                lines.append(f"- {r}")
        else:
            lines.append("*(all rules evaded)*")
        return "\n".join(lines)


# ── Rule loader ────────────────────────────────────────────────────────────────

def _collect_rules(rules_dirs: List[str]) -> List[Path]:
    """Collect all .yml rule files from one or more directories."""
    rule_paths = []
    seen = set()
    for d in rules_dirs:
        p = Path(d)
        if not p.exists():
            continue
        for rule_file in sorted(p.rglob("*.yml")):
            if str(rule_file) not in seen:
                rule_paths.append(rule_file)
                seen.add(str(rule_file))
    return rule_paths


# ── Artifact I/O ───────────────────────────────────────────────────────────────

def _write_temp_artifact(events: List[dict]) -> str:
    """Write events to a temp JSONL file, return path."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
    ) as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
        return f.name


def _safety_intact(events: List[dict]) -> bool:
    """Verify all events still carry the simulation_only safety field."""
    for ev in events:
        if ev.get("simulation_only") is False:
            return False
        safety = ev.get("safety", {})
        if isinstance(safety, dict):
            if safety.get("executable") is True:
                return False
            if safety.get("payload_present") is True:
                return False
    return True


# ── Rule evaluation ────────────────────────────────────────────────────────────

def _evaluate_rules(
    rule_paths: List[Path],
    artifact_path: str,
    match_mode: str = "tolerant",
) -> List[RuleFireResult]:
    """Evaluate all rules against an artifact. Returns fire results."""
    results = []
    for rp in rule_paths:
        try:
            result = evaluate_sigma_rule(str(rp), artifact_path, match_mode=match_mode)
            rule_id = result.rule_id
            rule_title = result.rule_title
            triggered = result.verdict == RuleVerdict.TRIGGERED
            results.append(RuleFireResult(
                rule_id=rule_id,
                rule_title=rule_title,
                rule_path=str(rp),
                verdict=result.verdict.value,
                triggered=triggered,
            ))
        except Exception:
            continue
    return results


def _firing_rule_ids(fire_results: List[RuleFireResult]) -> set:
    return {r.rule_id for r in fire_results if r.triggered}


# ── Mutation strategy selector ─────────────────────────────────────────────────

# Ordered adaptation strategies — adversary tries these in sequence
ADAPTATION_STRATEGIES = [
    "label_ambiguity",
    "field_drop",
    "timing_jitter",
    "technique_noise",
    "signal_density_low",
    "phase_imbalance",
    "sigma_aware_case_flip",
    "sigma_aware_unicode",
    "sigma_aware_whitespace",
    "sigma_aware_value_swap",
    "sigma_aware_field_omit",
    "combined",
]


def _apply_mutation(
    events: List[dict],
    strategy: str,
    run_id: str,
    seed: int,
    sigma_mutator: Optional[SigmaAwareMutator],
) -> List[dict]:
    """Apply a named mutation strategy to a list of events."""

    if strategy == "label_ambiguity":
        result = mutate_label_ambiguity(events, run_id=run_id, seed=seed)
        return result.records

    if strategy == "field_drop":
        result = mutate_field_drop(events, run_id=run_id, seed=seed)
        return result.records

    if strategy == "timing_jitter":
        result = mutate_timing_jitter(events, run_id=run_id, seed=seed)
        return result.records

    if strategy == "technique_noise":
        result = mutate_technique_noise(events, run_id=run_id, seed=seed)
        return result.records

    if strategy == "signal_density_low":
        result = mutate_signal_density_low(events, run_id=run_id,
                                           keep_fraction=0.6, seed=seed)
        return result.records

    if strategy == "phase_imbalance":
        result = mutate_phase_imbalance(events, run_id=run_id, seed=seed)
        return result.records

    if strategy.startswith("sigma_aware_") and sigma_mutator:
        sigma_strategy = strategy.replace("sigma_aware_", "")
        mutated = []
        for ev in events:
            mutated.append(sigma_mutator.mutate_targeted(ev, sigma_strategy, seed=seed))
        return mutated

    if strategy == "combined":
        # Layer multiple strategies
        r1 = mutate_label_ambiguity(events, run_id=run_id + "_la", seed=seed)
        r2 = mutate_timing_jitter(r1.records, run_id=run_id + "_tj", seed=seed + 1)
        if sigma_mutator:
            mutated = []
            for ev in r2.records:
                mutated.append(sigma_mutator.mutate_targeted(ev, "case_flip", seed=seed))
            return mutated
        return r2.records

    return events


# ── Main adaptation engine ─────────────────────────────────────────────────────

def run_adaptation(
    artifact_path: str,
    rules_dirs: List[str],
    max_iterations: int = 12,
    match_mode: str = "tolerant",
    verbose: bool = True,
    seed: int = 42,
) -> AdaptationReport:
    """
    Run the adversary adaptation loop against a SHENRON artifact.

    Args:
        artifact_path:  Path to SHENRON JSONL artifact (campaign or layer run)
        rules_dirs:     List of directories containing Sigma rules
        max_iterations: Maximum adaptation iterations before giving up
        match_mode:     Sigma match mode (tolerant/strict/explain)
        verbose:        Print progress
        seed:           Random seed for reproducibility
        
    Returns:
        AdaptationReport with full iteration history and evasion metrics
    """
    now = datetime.now(timezone.utc).isoformat()

    # Load original artifact
    original_events = []
    with open(artifact_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    original_events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    # Extract campaign metadata from first event
    first_ev = original_events[0] if original_events else {}
    campaign_id = first_ev.get("campaign_id") or first_ev.get("session_id") or str(uuid.uuid4())
    scenario_name = first_ev.get("scenario_name") or first_ev.get("stage") or "unknown"

    # Collect rules
    rule_paths = _collect_rules(rules_dirs)
    rules_dir_primary = rules_dirs[0] if rules_dirs else ""
    rules_dir_secondary = rules_dirs[1] if len(rules_dirs) > 1 else ""

    if verbose:
        print(f"\n  [ADAPT] Artifact     : {artifact_path}")
        print(f"  [ADAPT] Events       : {len(original_events)}")
        print(f"  [ADAPT] Rules loaded : {len(rule_paths)}")
        print(f"  [ADAPT] Max iters    : {max_iterations}")
        print(f"  [ADAPT] Match mode   : {match_mode}")
        print()

    if not rule_paths:
        if verbose:
            print("  [ADAPT] No rules found — nothing to evade.")
        return AdaptationReport(
            campaign_id=campaign_id,
            scenario_name=scenario_name,
            rules_dir_primary=rules_dir_primary,
            rules_dir_secondary=rules_dir_secondary,
            generated_at=now,
            total_rules_evaluated=0,
            rules_firing_on_original=0,
            iterations_run=0,
            iterations_to_evasion=None,
            evasion_achieved=False,
            surviving_rules=[],
            evaded_rules=[],
            adaptation_path=[],
        )

    # Build sigma-aware mutator using primary rules dir
    try:
        sigma_mutator = SigmaAwareMutator(rules_dir_primary)
    except Exception:
        sigma_mutator = None

    # Evaluate original artifact
    tmp_original = _write_temp_artifact(original_events)
    try:
        original_results = _evaluate_rules(rule_paths, tmp_original, match_mode)
    finally:
        try:
            os.unlink(tmp_original)
        except Exception:
            pass

    originally_firing = _firing_rule_ids(original_results)
    rules_firing_on_original = len(originally_firing)

    if verbose:
        print(f"  [ADAPT] Rules firing on original: {rules_firing_on_original}/{len(rule_paths)}")

    if rules_firing_on_original == 0:
        if verbose:
            print("  [ADAPT] No rules fire on original artifact — nothing to evade.")
        return AdaptationReport(
            campaign_id=campaign_id,
            scenario_name=scenario_name,
            rules_dir_primary=rules_dir_primary,
            rules_dir_secondary=rules_dir_secondary,
            generated_at=now,
            total_rules_evaluated=len(rule_paths),
            rules_firing_on_original=0,
            iterations_run=0,
            iterations_to_evasion=None,
            evasion_achieved=False,
            surviving_rules=[],
            evaded_rules=[],
            adaptation_path=[],
        )

    # Adaptation loop
    current_events = copy.deepcopy(original_events)
    still_firing = set(originally_firing)
    evaded = set()
    adaptation_path = []
    iterations_detail = []
    iterations_to_evasion = None
    evasion_achieved = False

    for iteration in range(1, max_iterations + 1):
        strategy = ADAPTATION_STRATEGIES[(iteration - 1) % len(ADAPTATION_STRATEGIES)]
        run_id = f"adapt-{iteration:02d}-{strategy[:8]}"
        iter_seed = seed + iteration * 7

        if verbose:
            print(f"  [ADAPT] Iter {iteration:02d}/{max_iterations} — strategy: {strategy}")

        # Apply mutation
        mutated_events = _apply_mutation(
            current_events, strategy, run_id, iter_seed, sigma_mutator
        )

        # Safety check
        intact = _safety_intact(mutated_events)
        if not intact:
            if verbose:
                print(f"  [ADAPT]   Safety contract violated — skipping iteration")
            continue

        # Evaluate mutated artifact
        tmp_mutated = _write_temp_artifact(mutated_events)
        try:
            mutated_results = _evaluate_rules(rule_paths, tmp_mutated, match_mode)
        finally:
            try:
                os.unlink(tmp_mutated)
            except Exception:
                pass

        now_firing = _firing_rule_ids(mutated_results)
        newly_evaded = still_firing - now_firing
        evaded |= newly_evaded
        still_firing = now_firing & originally_firing  # only track originally-firing rules

        evasion_rate = 1.0 - (len(still_firing) / rules_firing_on_original) if rules_firing_on_original > 0 else 0.0

        iter_detail = AdaptationIteration(
            iteration=iteration,
            mutation_applied=strategy,
            mutation_run_id=run_id,
            rules_fired=[r for r in mutated_results if r.triggered],
            rules_fired_count=len(now_firing),
            rules_evaded_count=len(evaded),
            evasion_rate=round(evasion_rate, 3),
            artifact_event_count=len(mutated_events),
            safety_intact=intact,
        )
        iterations_detail.append(iter_detail)
        adaptation_path.append(strategy)

        if verbose:
            print(f"  [ADAPT]   Firing: {len(still_firing):3d} | Evaded: {len(evaded):3d} | Rate: {evasion_rate:.2f}")

        # Update current events for next iteration (adversary adapts cumulatively)
        current_events = mutated_events

        if len(still_firing) == 0:
            evasion_achieved = True
            iterations_to_evasion = iteration
            if verbose:
                print(f"\n  [ADAPT] *** Full evasion achieved at iteration {iteration} ***")
            break

    surviving = [
        r.rule_title or r.rule_id
        for r in original_results
        if r.rule_id in still_firing
    ]
    evaded_list = [
        r.rule_title or r.rule_id
        for r in original_results
        if r.rule_id in evaded
    ]

    if verbose:
        print()
        print(f"  [ADAPT] Iterations run       : {len(iterations_detail)}")
        print(f"  [ADAPT] Evasion achieved     : {evasion_achieved}")
        if iterations_to_evasion:
            print(f"  [ADAPT] Iterations to evasion: {iterations_to_evasion}")
        print(f"  [ADAPT] Surviving rules      : {len(surviving)}")
        print(f"  [ADAPT] Evaded rules         : {len(evaded_list)}")
        if surviving:
            print(f"\n  [ADAPT] Detection-robust rules (survived all mutations):")
            for r in surviving:
                print(f"    [+] {r}")
        print()

    return AdaptationReport(
        campaign_id=campaign_id,
        scenario_name=scenario_name,
        rules_dir_primary=rules_dir_primary,
        rules_dir_secondary=rules_dir_secondary,
        generated_at=now,
        total_rules_evaluated=len(rule_paths),
        rules_firing_on_original=rules_firing_on_original,
        iterations_run=len(iterations_detail),
        iterations_to_evasion=iterations_to_evasion,
        evasion_achieved=evasion_achieved,
        surviving_rules=surviving,
        evaded_rules=evaded_list,
        adaptation_path=adaptation_path,
        iterations=iterations_detail,
    )
