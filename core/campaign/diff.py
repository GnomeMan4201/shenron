"""
core/campaign/diff.py

SHENRON Campaign Diff Tool.

Takes two SHENRON campaign runs of the same (or different) scenarios
and produces a structured diff: which techniques appeared in one but
not the other, which phases had different signal density, where behavior
diverged, and whether detection coverage is seed-dependent.

The core question this answers:
  "Is your detection coverage stable across adversary variation,
   or does it depend on a specific random seed?"

Diff dimensions:
  - technique_diff:   MITRE techniques present in A but not B, or B but not A
  - phase_diff:       Phases present in one run but not the other
  - signal_diff:      Detection opportunities unique to each run
  - density_diff:     Per-phase event count delta between runs
  - layer_diff:       Layers activated in one run but not the other
  - coverage_delta:   Net change in detection surface between runs

Stability score:
  1.0 = runs are identical in technique/signal coverage (seed-stable)
  0.0 = runs share no techniques or signals (maximally divergent)

Design constraints:
- New file only. Zero modifications to existing core files.
- Works on any two SHENRON JSONL artifacts — campaign runs, scenario runs,
  layer runs, or mixed.
- No subprocess, no network, no execution.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class PhaseDensity:
    phase: str
    count_a: int
    count_b: int
    delta: int
    delta_pct: float


@dataclass
class CampaignDiffReport:
    artifact_a: str
    artifact_b: str
    generated_at: str

    # Technique diff
    techniques_a: List[str]
    techniques_b: List[str]
    techniques_common: List[str]
    techniques_only_a: List[str]
    techniques_only_b: List[str]

    # Phase diff
    phases_a: List[str]
    phases_b: List[str]
    phases_common: List[str]
    phases_only_a: List[str]
    phases_only_b: List[str]

    # Signal diff
    signals_a: List[str]
    signals_b: List[str]
    signals_common: List[str]
    signals_only_a: List[str]
    signals_only_b: List[str]

    # Layer diff
    layers_a: List[str]
    layers_b: List[str]
    layers_common: List[str]
    layers_only_a: List[str]
    layers_only_b: List[str]

    # Density diff per phase
    phase_density: List[PhaseDensity]

    # Summary metrics
    event_count_a: int
    event_count_b: int
    technique_stability: float
    signal_stability: float
    overall_stability: float
    coverage_delta: int
    seed_dependent: bool

    def to_dict(self) -> dict:
        return {
            "artifact_a": self.artifact_a,
            "artifact_b": self.artifact_b,
            "generated_at": self.generated_at,
            "event_count_a": self.event_count_a,
            "event_count_b": self.event_count_b,
            "technique_stability": self.technique_stability,
            "signal_stability": self.signal_stability,
            "overall_stability": self.overall_stability,
            "coverage_delta": self.coverage_delta,
            "seed_dependent": self.seed_dependent,
            "techniques_only_a": self.techniques_only_a,
            "techniques_only_b": self.techniques_only_b,
            "techniques_common": self.techniques_common,
            "phases_only_a": self.phases_only_a,
            "phases_only_b": self.phases_only_b,
            "signals_only_a": self.signals_only_a,
            "signals_only_b": self.signals_only_b,
            "layers_only_a": self.layers_only_a,
            "layers_only_b": self.layers_only_b,
            "phase_density": [
                {
                    "phase": pd.phase,
                    "count_a": pd.count_a,
                    "count_b": pd.count_b,
                    "delta": pd.delta,
                    "delta_pct": pd.delta_pct,
                }
                for pd in self.phase_density
            ],
        }

    def to_markdown(self) -> str:
        stability_label = "STABLE" if self.overall_stability >= 0.8 else (
            "PARTIALLY STABLE" if self.overall_stability >= 0.5 else "UNSTABLE"
        )
        seed_label = "YES — coverage varies by seed" if self.seed_dependent else "NO — coverage is seed-stable"

        lines = [
            "# SHENRON Campaign Diff Report",
            "",
            f"**Run A:** `{self.artifact_a}`  ",
            f"**Run B:** `{self.artifact_b}`  ",
            f"**Generated:** {self.generated_at}  ",
            f"**Events A:** {self.event_count_a} | **Events B:** {self.event_count_b}  ",
            "",
            "## Stability Summary",
            "",
            f"| Metric | Score | Verdict |",
            f"|--------|-------|---------|",
            f"| Technique Stability | {self.technique_stability:.3f} | {'STABLE' if self.technique_stability >= 0.8 else 'UNSTABLE'} |",
            f"| Signal Stability | {self.signal_stability:.3f} | {'STABLE' if self.signal_stability >= 0.8 else 'UNSTABLE'} |",
            f"| Overall Stability | {self.overall_stability:.3f} | {stability_label} |",
            f"| Seed-Dependent Coverage | — | {seed_label} |",
            f"| Coverage Delta | {self.coverage_delta:+d} signals | — |",
            "",
            "## Technique Diff",
            "",
        ]

        if self.techniques_common:
            lines.append(f"**Common ({len(self.techniques_common)}):** {', '.join(self.techniques_common)}")
        if self.techniques_only_a:
            lines.append(f"**Only in A ({len(self.techniques_only_a)}):** {', '.join(self.techniques_only_a)}")
        if self.techniques_only_b:
            lines.append(f"**Only in B ({len(self.techniques_only_b)}):** {', '.join(self.techniques_only_b)}")
        if not self.techniques_only_a and not self.techniques_only_b:
            lines.append("*Technique coverage identical across both runs.*")

        lines += [
            "",
            "## Signal Diff",
            "",
        ]
        if self.signals_only_a:
            lines.append(f"**Only in A ({len(self.signals_only_a)}):**")
            for s in self.signals_only_a[:10]:
                lines.append(f"  - {s}")
            if len(self.signals_only_a) > 10:
                lines.append(f"  - *(+{len(self.signals_only_a)-10} more)*")
        if self.signals_only_b:
            lines.append(f"**Only in B ({len(self.signals_only_b)}):**")
            for s in self.signals_only_b[:10]:
                lines.append(f"  - {s}")
            if len(self.signals_only_b) > 10:
                lines.append(f"  - *(+{len(self.signals_only_b)-10} more)*")
        if not self.signals_only_a and not self.signals_only_b:
            lines.append("*Signal coverage identical across both runs.*")

        lines += [
            "",
            "## Phase Density",
            "",
            "| Phase | Count A | Count B | Delta | Delta % |",
            "|-------|---------|---------|-------|---------|",
        ]
        for pd in sorted(self.phase_density, key=lambda x: abs(x.delta), reverse=True):
            lines.append(
                f"| {pd.phase} | {pd.count_a} | {pd.count_b} | "
                f"{pd.delta:+d} | {pd.delta_pct:+.1f}% |"
            )

        if self.layers_only_a or self.layers_only_b:
            lines += ["", "## Layer Diff", ""]
            if self.layers_only_a:
                lines.append(f"**Only in A:** {', '.join(self.layers_only_a)}")
            if self.layers_only_b:
                lines.append(f"**Only in B:** {', '.join(self.layers_only_b)}")

        lines += [
            "",
            "## Detection Engineering Recommendation",
            "",
        ]
        if self.seed_dependent:
            lines.append(
                "⚠️ **Coverage is seed-dependent.** "
                f"{len(self.techniques_only_a) + len(self.techniques_only_b)} technique(s) "
                "appear in only one run. Detection rules that rely on these techniques "
                "will not fire consistently across adversary variations. "
                "Consider broadening detection logic to cover the full technique union."
            )
        else:
            lines.append(
                "✓ **Coverage is seed-stable.** "
                "Technique and signal coverage is consistent across both runs. "
                "Detection rules validated against one run should generalize."
            )

        return "\n".join(lines)

    def print_summary(self) -> None:
        stability_label = "STABLE" if self.overall_stability >= 0.8 else (
            "PARTIALLY STABLE" if self.overall_stability >= 0.5 else "UNSTABLE"
        )
        print(f"\n  [DIFF] A: {self.artifact_a}")
        print(f"  [DIFF] B: {self.artifact_b}")
        print(f"  [DIFF] Events          : A={self.event_count_a} B={self.event_count_b}")
        print(f"  [DIFF] Technique stab  : {self.technique_stability:.3f}")
        print(f"  [DIFF] Signal stab     : {self.signal_stability:.3f}")
        print(f"  [DIFF] Overall stab    : {self.overall_stability:.3f} ({stability_label})")
        print(f"  [DIFF] Seed-dependent  : {self.seed_dependent}")
        print(f"  [DIFF] Coverage delta  : {self.coverage_delta:+d} signals")
        if self.techniques_only_a:
            print(f"  [DIFF] Only in A       : {self.techniques_only_a}")
        if self.techniques_only_b:
            print(f"  [DIFF] Only in B       : {self.techniques_only_b}")
        if self.signals_only_a:
            print(f"  [DIFF] Signals only A  : {len(self.signals_only_a)}")
        if self.signals_only_b:
            print(f"  [DIFF] Signals only B  : {len(self.signals_only_b)}")
        print()


# ── Artifact loader ────────────────────────────────────────────────────────────

def _load_events(path: str) -> List[dict]:
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events


def _extract_techniques(events: List[dict]) -> Set[str]:
    techs = set()
    for ev in events:
        techs.update(ev.get("mitre_techniques", []))
        t = ev.get("mitre_technique")
        if t:
            techs.add(t)
    return techs


def _extract_signals(events: List[dict]) -> Set[str]:
    signals = set()
    for ev in events:
        opps = ev.get("detection_opportunities", [])
        if isinstance(opps, list):
            signals.update(opps)
        sig = ev.get("signal")
        if sig:
            signals.add(sig)
        bc = ev.get("behavior_class")
        if bc:
            signals.add(bc)
    return signals


def _extract_phases(events: List[dict]) -> Set[str]:
    return {ev.get("phase", "") for ev in events if ev.get("phase")}


def _extract_layers(events: List[dict]) -> Set[str]:
    return {ev.get("layer", "") for ev in events if ev.get("layer")}


def _phase_density(events: List[dict]) -> Dict[str, int]:
    density: Dict[str, int] = {}
    for ev in events:
        phase = ev.get("phase", "UNKNOWN")
        density[phase] = density.get(phase, 0) + 1
    return density


def _jaccard(a: Set, b: Set) -> float:
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 1.0
    return len(a & b) / len(union)


# ── Main diff engine ───────────────────────────────────────────────────────────

def diff_campaigns(
    artifact_a: str,
    artifact_b: str,
    seed_dependent_threshold: float = 0.9,
    verbose: bool = True,
) -> CampaignDiffReport:
    """
    Diff two SHENRON campaign artifacts.

    Args:
        artifact_a:                 Path to first SHENRON JSONL artifact
        artifact_b:                 Path to second SHENRON JSONL artifact
        seed_dependent_threshold:   Stability score below which coverage
                                    is considered seed-dependent (default 0.9)
        verbose:                    Print summary to stdout

    Returns:
        CampaignDiffReport with full diff and stability metrics
    """
    now = datetime.now(timezone.utc).isoformat()

    events_a = _load_events(artifact_a)
    events_b = _load_events(artifact_b)

    techs_a = _extract_techniques(events_a)
    techs_b = _extract_techniques(events_b)
    phases_a = _extract_phases(events_a)
    phases_b = _extract_phases(events_b)
    signals_a = _extract_signals(events_a)
    signals_b = _extract_signals(events_b)
    layers_a = _extract_layers(events_a)
    layers_b = _extract_layers(events_b)

    density_a = _phase_density(events_a)
    density_b = _phase_density(events_b)
    all_phases = sorted(set(density_a) | set(density_b))
    phase_density_list = []
    for phase in all_phases:
        ca = density_a.get(phase, 0)
        cb = density_b.get(phase, 0)
        delta = cb - ca
        base = ca if ca > 0 else 1
        delta_pct = (delta / base) * 100
        phase_density_list.append(PhaseDensity(
            phase=phase, count_a=ca, count_b=cb,
            delta=delta, delta_pct=round(delta_pct, 1)
        ))

    tech_stability = _jaccard(techs_a, techs_b)
    signal_stability = _jaccard(signals_a, signals_b)
    overall_stability = (tech_stability * 0.6 + signal_stability * 0.4)
    coverage_delta = len(signals_b) - len(signals_a)
    seed_dependent = overall_stability < seed_dependent_threshold

    report = CampaignDiffReport(
        artifact_a=artifact_a,
        artifact_b=artifact_b,
        generated_at=now,
        techniques_a=sorted(techs_a),
        techniques_b=sorted(techs_b),
        techniques_common=sorted(techs_a & techs_b),
        techniques_only_a=sorted(techs_a - techs_b),
        techniques_only_b=sorted(techs_b - techs_a),
        phases_a=sorted(phases_a),
        phases_b=sorted(phases_b),
        phases_common=sorted(phases_a & phases_b),
        phases_only_a=sorted(phases_a - phases_b),
        phases_only_b=sorted(phases_b - phases_a),
        signals_a=sorted(signals_a),
        signals_b=sorted(signals_b),
        signals_common=sorted(signals_a & signals_b),
        signals_only_a=sorted(signals_a - signals_b),
        signals_only_b=sorted(signals_b - signals_a),
        layers_a=sorted(layers_a),
        layers_b=sorted(layers_b),
        layers_common=sorted(layers_a & layers_b),
        layers_only_a=sorted(layers_a - layers_b),
        layers_only_b=sorted(layers_b - layers_a),
        phase_density=phase_density_list,
        event_count_a=len(events_a),
        event_count_b=len(events_b),
        technique_stability=round(tech_stability, 3),
        signal_stability=round(signal_stability, 3),
        overall_stability=round(overall_stability, 3),
        coverage_delta=coverage_delta,
        seed_dependent=seed_dependent,
    )

    if verbose:
        report.print_summary()

    return report


def diff_scenario_seeds(
    scenario_name: str,
    seed_a: int = 42,
    seed_b: int = 99,
    output_dir: str = "artifacts/diffs",
    verbose: bool = True,
) -> CampaignDiffReport:
    """
    Run the same scenario with two different seeds and diff the results.
    Convenience wrapper that builds campaigns, writes artifacts, and diffs.

    Args:
        scenario_name:  SHENRON scenario name (e.g. apt29-style)
        seed_a:         First seed
        seed_b:         Second seed
        output_dir:     Directory for temporary artifacts
        verbose:        Print progress

    Returns:
        CampaignDiffReport
    """
    import random
    from pathlib import Path as _Path

    _Path(output_dir).mkdir(parents=True, exist_ok=True)

    from core.campaign.builder import CampaignBuilder

    if verbose:
        print(f"\n  [DIFF] Building scenario: {scenario_name}")
        print(f"  [DIFF] Seed A: {seed_a} | Seed B: {seed_b}")

    # Build run A
    random.seed(seed_a)
    builder_a = CampaignBuilder.from_scenario(scenario_name)
    campaign_a = builder_a.build()
    path_a = str(_Path(output_dir) / f"{scenario_name}_seed{seed_a}.jsonl")
    with open(path_a, "w") as f:
        for ev in builder_a.to_jsonl():
            f.write(json.dumps(ev) + "\n")

    # Build run B
    random.seed(seed_b)
    builder_b = CampaignBuilder.from_scenario(scenario_name)
    campaign_b = builder_b.build()
    path_b = str(_Path(output_dir) / f"{scenario_name}_seed{seed_b}.jsonl")
    with open(path_b, "w") as f:
        for ev in builder_b.to_jsonl():
            f.write(json.dumps(ev) + "\n")

    if verbose:
        print(f"  [DIFF] Run A: {len(campaign_a.events)} events -> {path_a}")
        print(f"  [DIFF] Run B: {len(campaign_b.events)} events -> {path_b}")

    return diff_campaigns(path_a, path_b, verbose=verbose)
