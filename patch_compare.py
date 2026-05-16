#!/usr/bin/env python3
"""
Patch core/compare.py — replace compare_report_to_markdown with richer version.
Run: python3 patch_compare.py
"""
from pathlib import Path

src = Path("core/compare.py").read_text()

OLD = '''def compare_report_to_markdown(r: CompareReport) -> str:
    arrow = "▲" if r.coverage_delta >= 0 else "▼"
    sign  = "+" if r.coverage_delta >= 0 else ""
    lines = [
        f"# SHENRON Run Comparison",
        f"",
        f"| | Run A | Run B |",
        f"|---|---|---|",
        f"| Run ID | `{r.run_id_a[:8]}` | `{r.run_id_b[:8]}` |",
        f"| Campaign | {r.campaign_a} | {r.campaign_b} |",
        f"| Coverage | {r.coverage_a}% | {r.coverage_b}% |",
        f"| Verdict | {r.verdict_a} | {r.verdict_b} |",
        f"| Safety failures | {r.safety_a} | {r.safety_b} |",
        f"",
        f"**Coverage delta:** {arrow} {sign}{r.coverage_delta}%",
        f"",
        f"---",
        f"",
    ]

    if r.gained:
        lines += [f"## Signals Gained (+{len(r.gained)})", ""]
        for s in r.gained:
            lines.append(f"- `{s}`")
        lines.append("")

    if r.lost:
        lines += [f"## Signals Lost (-{len(r.lost)})", ""]
        for s in r.lost:
            lines.append(f"- `{s}`")
        lines.append("")

    if r.improved:
        lines += [f"## Improved (PARTIAL → PASS, {len(r.improved)})", ""]
        for s in r.improved:
            lines.append(f"- `{s}`")
        lines.append("")

    if r.degraded:
        lines += [f"## Degraded (PASS → PARTIAL, {len(r.degraded)})", ""]
        for s in r.degraded:
            lines.append(f"- `{s}`")
        lines.append("")

    lines += [
        f"## MITRE ATT&CK Descriptor Delta (Synthetic)",
        f"",
        f"| Change | Techniques |",
        f"|--------|-----------|",
        f"| Gained | {', '.join(r.mitre_gained) if r.mitre_gained else '—'} |",
        f"| Lost   | {', '.join(r.mitre_lost) if r.mitre_lost else '—'} |",
        f"| Retained | {len(r.mitre_retained)} techniques |",
        f"",
        f"---",
        f"",
        f"*SHENRON — Observable adversarial behavior, not portable adversarial procedure.*",
    ]
    return "\\n".join(lines)'''

NEW = '''def compare_report_to_markdown(r: CompareReport) -> str:
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
    return "\\n".join(lines)'''

if OLD in src:
    src = src.replace(OLD, NEW, 1)
    print("compare_report_to_markdown: enhanced")
    Path("core/compare.py").write_text(src)
else:
    print("FAILED — function not found verbatim")
    print("Showing current function signature:")
    for i, line in enumerate(src.splitlines()):
        if "def compare_report_to_markdown" in line:
            print(f"  {i+1}: {line}")
