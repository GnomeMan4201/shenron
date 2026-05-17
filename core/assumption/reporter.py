#!/usr/bin/env python3
# SHENRON: Assumption report writer
# Produces markdown and JSON assumption audit reports.

import json
from datetime import datetime, timezone
from typing import Optional

from core.assumption.evaluator import AssumptionAuditResult


def _verdict_label(verdict: str) -> str:
    return {
        "PASS":    "✅ PASS",
        "PARTIAL": "⚠️  PARTIAL",
        "FAIL":    "❌ FAIL",
        "UNSAFE":  "🚨 UNSAFE",
        "UNKNOWN": "❓ UNKNOWN",
    }.get(verdict, verdict)


def _status_label(status: str) -> str:
    return {"OBSERVED": "✅", "MISSING": "❌", "PARTIAL": "⚠️"}.get(status, status)


def _claim_label(verdict: str) -> str:
    return {
        "SUPPORTED":   "✅ SUPPORTED",
        "PARTIAL":     "⚠️  PARTIAL",
        "UNSUPPORTED": "❌ UNSUPPORTED",
        "UNTESTED":    "—  UNTESTED",
    }.get(verdict, verdict)


def to_markdown(result: AssumptionAuditResult) -> str:
    now = datetime.now(timezone.utc).isoformat()

    lines = [
        f"# SHENRON Assumption Audit",
        f"",
        f"> **SYNTHETIC TELEMETRY** — This report audits defensive coverage assumptions",
        f"> against synthetic SHENRON telemetry. It does not prove real detection efficacy.",
        f"",
        f"---",
        f"",
        f"## Assumption Summary",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Name | {result.assumption_name} |",
        f"| Description | {result.assumption_description or '—'} |",
        f"| Source | `{result.source_path or 'inline'}` |",
        f"| Records checked | {result.records_checked} |",
        f"| Safety violations | {result.safety_violations} |",
        f"| Generated | {now[:19]} UTC |",
        f"",
        f"---",
        f"",
        f"## Coverage Summary",
        f"",
        f"| Dimension | Claimed | Observed | Missing | Coverage |",
        f"|-----------|--------:|---------:|--------:|---------:|",
    ]

    def _row(label, claimed, observed, missing):
        pct = round(observed / claimed * 100, 1) if claimed > 0 else 0.0
        return f"| {label} | {claimed} | {observed} | {missing} | {pct}% |"

    lines += [
        _row("Claims",     len(result.claim_results),
             result.claims_supported, result.claims_unsupported),
        _row("Techniques", len(result.technique_results),
             len(result.techniques_observed), len(result.techniques_missing)),
        _row("Signals",    len(result.signal_results),
             len(result.signals_observed), len(result.signals_missing)),
        _row("Phases",     len(result.phase_results),
             len(result.phases_observed), len(result.phases_missing)),
        f"",
        f"**Overall coverage:** {result.coverage_percent}%  ",
        f"**Verdict:** {_verdict_label(result.verdict)}",
        f"",
        f"---",
        f"",
        f"## Claimed Coverage",
        f"",
        f"What this assumption claims to validate:",
        f"",
    ]

    for cr in result.claim_results:
        lines.append(f"### {_claim_label(cr.verdict)}: {cr.claim}")
        lines.append(f"")
        if cr.evidence:
            lines.append(f"**Supporting evidence:**")
            for e in cr.evidence:
                lines.append(f"- `{e}`")
        if cr.note:
            lines.append(f"")
            lines.append(f"*{cr.note}*")
        lines.append(f"")

    lines += [
        f"---",
        f"",
        f"## Technique Coverage",
        f"",
        f"| Technique | Status |",
        f"|-----------|--------|",
    ]
    for tr in result.technique_results:
        lines.append(f"| `{tr.technique}` | {_status_label(tr.status)} |")

    lines += [
        f"",
        f"---",
        f"",
        f"## Signal Coverage",
        f"",
        f"| Expected Signal | Status | Matched |",
        f"|-----------------|--------|---------|",
    ]
    for sr in result.signal_results:
        matched = f"`{sr.matched_field}`" if sr.matched_field else "—"
        lines.append(f"| `{sr.signal}` | {_status_label(sr.status)} | {matched} |")

    if result.phase_results:
        lines += [
            f"",
            f"---",
            f"",
            f"## Phase Coverage",
            f"",
            f"| Phase | Status | Events |",
            f"|-------|--------|-------:|",
        ]
        for pr in result.phase_results:
            lines.append(
                f"| {pr.phase} | {_status_label(pr.status)} | {pr.event_count} |"
            )

    # Defensive interpretation
    lines += [
        f"",
        f"---",
        f"",
        f"## Defensive Interpretation",
        f"",
    ]

    if result.verdict == "PASS":
        lines += [
            f"All claimed coverage dimensions were observed in the synthetic telemetry.",
            f"",
            f"This assumption's claims are supported by the artifact records checked.",
            f"",
        ]
    else:
        if result.techniques_missing:
            tech_str = ", ".join(result.techniques_missing)
            lines += [
                f"The following technique descriptors were claimed but not observed in",
                f"the synthetic telemetry: **{tech_str}**.",
                f"",
                f"A detection stack validated against this artifact has no coverage signal",
                f"for these technique shapes.",
                f"",
            ]
        if result.signals_missing:
            sig_str = ", ".join(f"`{s}`" for s in result.signals_missing[:6])
            if len(result.signals_missing) > 6:
                sig_str += f", and {len(result.signals_missing) - 6} more"
            lines += [
                f"The following expected signals were not found: {sig_str}.",
                f"",
            ]
        if result.claims_unsupported > 0:
            lines += [
                f"{result.claims_unsupported} of {len(result.claim_results)} claims "
                f"had no supporting evidence in the artifact records.",
                f"",
            ]

    lines += [
        f"---",
        f"",
        f"## What this proves",
        f"",
        f"- Which expected signals appear in the synthetic telemetry",
        f"- Which claimed technique descriptors are present in the artifact records",
        f"- Which claims have supporting synthetic evidence",
        f"- Whether the assumption's expected phases were exercised",
        f"",
        f"## What this does not prove",
        f"",
        f"- That real adversarial techniques were executed",
        f"- That real detection rules fired on these signals",
        f"- That a SIEM or EDR would catch the described behaviors",
        f"- That coverage in SHENRON equals coverage in production",
        f"- That unsupported claims are definitively undetectable",
        f"",
        f"---",
        f"",
        f"*SHENRON — Observable adversarial behavior, not portable adversarial procedure.*",
    ]

    return "\n".join(lines)


def to_json(result: AssumptionAuditResult) -> str:
    now = datetime.now(timezone.utc).isoformat()
    data = {
        "generated":            now,
        "assumption_name":      result.assumption_name,
        "assumption_description": result.assumption_description,
        "source_path":          result.source_path,
        "records_checked":      result.records_checked,
        "safety_violations":    result.safety_violations,
        "verdict":              result.verdict,
        "coverage_percent":     result.coverage_percent,
        "claims": [
            {"claim": cr.claim, "verdict": cr.verdict,
             "evidence_count": len(cr.evidence), "note": cr.note}
            for cr in result.claim_results
        ],
        "techniques": {
            "observed": result.techniques_observed,
            "missing":  result.techniques_missing,
        },
        "signals": {
            "observed": result.signals_observed,
            "missing":  result.signals_missing,
        },
        "phases": {
            "observed": result.phases_observed,
            "missing":  result.phases_missing,
        },
        "simulation_only": True,
        "portable_adversarial_procedure": False,
    }
    return json.dumps(data, indent=2)


def print_summary(result: AssumptionAuditResult):
    print()
    print(f"  [ASSUMPTION]  {result.assumption_name}")
    print(f"  [RECORDS]     {result.records_checked}")
    print()
    print(f"  Claims        {result.claims_supported} supported  "
          f"{result.claims_partial} partial  "
          f"{result.claims_unsupported} unsupported")
    print(f"  Techniques    "
          f"{len(result.techniques_observed)} observed  "
          f"{len(result.techniques_missing)} missing")
    print(f"  Signals       "
          f"{len(result.signals_observed)} observed  "
          f"{len(result.signals_missing)} missing")
    if result.phase_results:
        print(f"  Phases        "
              f"{len(result.phases_observed)} observed  "
              f"{len(result.phases_missing)} missing")
    print()
    print(f"  [COVERAGE]    {result.coverage_percent}%")
    print(f"  [VERDICT]     {result.verdict}")
    if result.techniques_missing:
        print(f"  [MISSING T]   {', '.join(result.techniques_missing)}")
    if result.signals_missing:
        print(f"  [MISSING S]   {', '.join(result.signals_missing[:5])}"
              + (f"  (+{len(result.signals_missing)-5} more)"
                 if len(result.signals_missing) > 5 else ""))
    print()
