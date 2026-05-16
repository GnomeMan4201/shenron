#!/usr/bin/env python3
# SHENRON: Run comparison engine
# PURPOSE: Diff two validation runs — coverage delta, MITRE delta, signal changes
# PRINCIPLE: No execution, no network, pure report analysis

from dataclasses import dataclass, field
from typing import List, Optional
from core.validation.coverage import DetectionCoverageReport, DetectionStatus


@dataclass
class SignalDelta:
    name: str
    status_a: str
    status_b: str
    direction: str  # "gained", "lost", "improved", "degraded", "unchanged"


@dataclass
class CompareReport:
    run_id_a:        str
    run_id_b:        str
    campaign_a:      str
    campaign_b:      str
    coverage_a:      float
    coverage_b:      float
    coverage_delta:  float
    verdict_a:       str
    verdict_b:       str
    mitre_a:         List[str] = field(default_factory=list)
    mitre_b:         List[str] = field(default_factory=list)
    mitre_gained:    List[str] = field(default_factory=list)
    mitre_lost:      List[str] = field(default_factory=list)
    mitre_retained:  List[str] = field(default_factory=list)
    signals:         List[SignalDelta] = field(default_factory=list)
    gained:          List[str] = field(default_factory=list)  # MISS→PASS
    lost:            List[str] = field(default_factory=list)  # PASS→MISS
    improved:        List[str] = field(default_factory=list)  # PARTIAL→PASS
    degraded:        List[str] = field(default_factory=list)  # PASS→PARTIAL
    safety_a:        int = 0
    safety_b:        int = 0


def compare_runs(
    cov_a: DetectionCoverageReport,
    cov_b: DetectionCoverageReport,
    mitre_a: Optional[List[str]] = None,
    mitre_b: Optional[List[str]] = None,
) -> CompareReport:
    """
    Diff two DetectionCoverageReport objects.
    mitre_a / mitre_b are optional lists of technique IDs from the run records.
    """
    set_a = {r.expectation.name: r.status for r in cov_a.results}
    set_b = {r.expectation.name: r.status for r in cov_b.results}
    all_signals = sorted(set(set_a) | set(set_b))

    signals = []
    gained, lost, improved, degraded = [], [], [], []

    for sig in all_signals:
        sa = set_a.get(sig, DetectionStatus.MISS).value if sig in set_a else "ABSENT"
        sb = set_b.get(sig, DetectionStatus.MISS).value if sig in set_b else "ABSENT"

        if sa == sb:
            direction = "unchanged"
        elif sa in ("MISS", "ABSENT") and sb == "PASS":
            direction = "gained"
            gained.append(sig)
        elif sa == "PASS" and sb in ("MISS", "ABSENT"):
            direction = "lost"
            lost.append(sig)
        elif sa == "PARTIAL" and sb == "PASS":
            direction = "improved"
            improved.append(sig)
        elif sa == "PASS" and sb == "PARTIAL":
            direction = "degraded"
            degraded.append(sig)
        else:
            direction = "unchanged"

        signals.append(SignalDelta(name=sig, status_a=sa, status_b=sb, direction=direction))

    # MITRE delta
    set_ma = set(mitre_a or [])
    set_mb = set(mitre_b or [])
    mitre_gained   = sorted(set_mb - set_ma)
    mitre_lost     = sorted(set_ma - set_mb)
    mitre_retained = sorted(set_ma & set_mb)

    delta = round(cov_b.coverage_percent - cov_a.coverage_percent, 1)

    return CompareReport(
        run_id_a       = cov_a.run_id,
        run_id_b       = cov_b.run_id,
        campaign_a     = cov_a.campaign_name,
        campaign_b     = cov_b.campaign_name,
        coverage_a     = cov_a.coverage_percent,
        coverage_b     = cov_b.coverage_percent,
        coverage_delta = delta,
        verdict_a      = cov_a.verdict,
        verdict_b      = cov_b.verdict,
        mitre_a        = sorted(set_ma),
        mitre_b        = sorted(set_mb),
        mitre_gained   = mitre_gained,
        mitre_lost     = mitre_lost,
        mitre_retained = mitre_retained,
        signals        = signals,
        gained         = gained,
        lost           = lost,
        improved       = improved,
        degraded       = degraded,
        safety_a       = cov_a.safety_failure_count,
        safety_b       = cov_b.safety_failure_count,
    )


def print_compare(r: CompareReport):
    arrow = "▲" if r.coverage_delta >= 0 else "▼"
    sign  = "+" if r.coverage_delta >= 0 else ""

    print()
    print(f"  [COMPARE]")
    print(f"  {'RUN A':<12}  {r.run_id_a[:8]}  {r.campaign_a}  {r.coverage_a}%  {r.verdict_a}")
    print(f"  {'RUN B':<12}  {r.run_id_b[:8]}  {r.campaign_b}  {r.coverage_b}%  {r.verdict_b}")
    print(f"  {'DELTA':<12}  {arrow} {sign}{r.coverage_delta}%")
    print()

    if r.gained:
        print(f"  [GAINED  +{len(r.gained)}]")
        for s in r.gained:
            print(f"    ✓  {s}")
        print()

    if r.lost:
        print(f"  [LOST    -{len(r.lost)}]")
        for s in r.lost:
            print(f"    ✗  {s}")
        print()

    if r.improved:
        print(f"  [IMPROVED  {len(r.improved)}]")
        for s in r.improved:
            print(f"    ~  {s}")
        print()

    if r.degraded:
        print(f"  [DEGRADED  {len(r.degraded)}]")
        for s in r.degraded:
            print(f"    ~  {s}")
        print()

    unchanged = [s for s in r.signals if s.direction == "unchanged"]
    print(f"  [UNCHANGED  {len(unchanged)}]")
    print()

    if r.mitre_gained:
        print(f"  [MITRE GAINED]   {', '.join(r.mitre_gained)}")
    if r.mitre_lost:
        print(f"  [MITRE LOST]     {', '.join(r.mitre_lost)}")
    if r.mitre_retained:
        print(f"  [MITRE RETAINED] {len(r.mitre_retained)} techniques")
    print()

    if r.safety_a > 0 or r.safety_b > 0:
        print(f"  [SAFETY]  A: {r.safety_a} violations  B: {r.safety_b} violations")
    else:
        print(f"  [SAFETY]  A: 0 violations  B: 0 violations  ✓")
    print()


def compare_report_to_markdown(r: CompareReport) -> str:
    arrow = "▲" if r.coverage_delta >= 0 else "▼"
    sign  = "+" if r.coverage_delta >= 0 else ""

    # Count unchanged
    unchanged = [s for s in r.signals if s.direction == "unchanged"]

    lines = [
        "# SHENRON Compare Report",
        "",
        "> **SYNTHETIC TELEMETRY** — This report compares two SHENRON simulation runs.",
        "> Coverage figures represent detection signal vocabulary coverage, not real",
        "> adversarial execution or confirmed detector efficacy.",
        "",
        "---",
        "",
        "## Summary",
        "",
        f"| Metric | Run A | Run B | Delta |",
        f"|--------|------:|------:|------:|",
        f"| Run ID | `{r.run_id_a[:8]}` | `{r.run_id_b[:8]}` | — |",
        f"| Campaign | {r.campaign_a} | {r.campaign_b} | — |",
        f"| Coverage | {r.coverage_a}% | {r.coverage_b}% | {arrow} {sign}{r.coverage_delta}% |",
        f"| Verdict | {r.verdict_a} | {r.verdict_b} | — |",
        f"| Signals total | {len(r.mitre_a) + len(r.mitre_b)} | — | — |",
        f"| MITRE descriptors | {len(r.mitre_a)} | {len(r.mitre_b)} | {len(r.mitre_b) - len(r.mitre_a):+d} |",
        f"| Signals gained | — | +{len(r.gained)} | — |",
        f"| Signals lost | -{len(r.lost)} | — | — |",
        f"| Safety failures | {r.safety_a} | {r.safety_b} | — |",
        "",
        "---",
        "",
    ]

    if r.gained:
        lines += [
            f"## Signals Gained in Run B (+{len(r.gained)})",
            "",
            "Run B expresses detection signals not present in Run A.",
            "",
        ]
        for s in r.gained:
            lines.append(f"- `{s}`")
        lines.append("")

    if r.lost:
        lines += [
            f"## Signals Lost in Run B (-{len(r.lost)})",
            "",
            "Run A expressed these signals. Run B does not — these are coverage gaps",
            "if Run B is intended to replace or extend Run A.",
            "",
        ]
        for s in r.lost:
            lines.append(f"- `{s}`")
        lines.append("")

    if r.improved:
        lines += [f"## Improved: PARTIAL → PASS ({len(r.improved)})", ""]
        for s in r.improved:
            lines.append(f"- `{s}`")
        lines.append("")

    if r.degraded:
        lines += [f"## Degraded: PASS → PARTIAL ({len(r.degraded)})", ""]
        for s in r.degraded:
            lines.append(f"- `{s}`")
        lines.append("")

    if unchanged:
        lines += [f"## Unchanged ({len(unchanged)} signals)", ""]
        lines.append("Signals present and passing in both runs.")
        lines.append("")

    lines += [
        "---",
        "",
        "## MITRE ATT&CK Descriptor Delta (Synthetic)",
        "",
        "> These are MITRE-style technique descriptors from synthetic telemetry.",
        "> They are not real ATT&CK validation or confirmed detector coverage.",
        "",
        f"| Change | Techniques |",
        f"|--------|-----------|",
        f"| Gained in B | {', '.join(r.mitre_gained) if r.mitre_gained else '—'} |",
        f"| Lost in B   | {', '.join(r.mitre_lost) if r.mitre_lost else '—'} |",
        f"| Retained    | {', '.join(r.mitre_retained) if r.mitre_retained else '—'} |",
        "",
        "---",
        "",
        "## Defensive Interpretation",
        "",
    ]

    # Auto-generate interpretation based on what was lost
    if r.mitre_lost:
        lost_str = ", ".join(r.mitre_lost[:6])
        if len(r.mitre_lost) > 6:
            lost_str += f", and {len(r.mitre_lost) - 6} more"
        lines += [
            f"Run B does not express telemetry shapes for: {lost_str}.",
            "",
            "A detection stack validated only against Run B has no coverage signal for",
            "the technique descriptors present in Run A. This is not a failure — it is",
            "a scope boundary. If Run A represents a broader threat profile (e.g. a full",
            "APT kill chain) and Run B a narrower one (e.g. persistence only), the gap",
            "is expected and should be documented.",
            "",
        ]
    else:
        lines += [
            "Run B covers all MITRE-style descriptor techniques present in Run A.",
            "No descriptor gap detected between these two runs.",
            "",
        ]

    lines += [
        "---",
        "",
        "## What this does not prove",
        "",
        "- That real adversarial techniques were executed in either run",
        "- That real detection rules fired on any of these signals",
        "- That a SIEM or EDR would catch the techniques described",
        "- That coverage in SHENRON equals coverage in production",
        "",
        "---",
        "",
        "*SHENRON — Observable adversarial behavior, not portable adversarial procedure.*",
    ]
    return "\n".join(lines)
