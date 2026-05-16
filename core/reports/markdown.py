#!/usr/bin/env python3
# SHENRON: Markdown report renderer
from pathlib import Path
from core.reports.model import ShenronReport
from core.bananatree.cycle import Phase
from core.bananatree.taxonomy import PHASE_INTENT


PHASE_ORDER = [Phase.OBSERVE, Phase.SIMULATE, Phase.EXECUTE, Phase.ADAPT]

REQUIRED_SECTIONS = [
    "Executive Summary",
    "bananaTREE Cycle",
    "Scenario Metadata",
    "Layer Execution Summary",
    "MITRE Coverage",
    "Synthetic Telemetry Timeline",
    "Detection Opportunities",
    "Defensive Runbook",
    "Safety Contract Verification",
    "Evidence Appendix",
]


def _safe_badge(passed: bool) -> str:
    return "✅ PASS" if passed else "❌ FAIL"


def render_markdown(report: ShenronReport, validation=None) -> str:
    lines = []
    a = lines.append

    # Header
    a(f"# SHENRON Detection Coverage Report")
    a(f"")
    a(f"> **Campaign:** {report.campaign_name}  ")
    a(f"> **Run ID:** `{report.run_id}`  ")
    a(f"> **Generated:** {report.generated_at[:19]} UTC  ")
    a(f"> **Mode:** {'DRY RUN' if report.dry_run else 'SIMULATION'}  ")
    a(f"> **Safety Contract:** {_safe_badge(report.safety.all_passed)}  ")
    a(f"")
    a("---")
    a("")

    # ── Executive Summary ────────────────────────────────────────────────────
    a("## Executive Summary")
    a("")
    a(
        f"This report documents a defensive adversarial simulation campaign run against "
        f"the SHENRON telemetry platform. **{len(report.layers_run)} simulation layers** "
        f"were executed across **{len(report.phases_run)} bananaTREE phases**, emitting "
        f"**{report.total_events} synthetic telemetry events**. "
        f"**{len(set(report.mitre.techniques))} MITRE ATT&CK techniques** were represented."
    )
    a("")
    a(f"No real network calls, process spawning, file writes, or executable payloads "
      f"were produced. All output is synthetic JSONL telemetry for detector training.")
    a("")
    safety_status = "**All safety contract checks passed.**" if report.safety.all_passed         else f"**⚠ {len(report.safety.violations)} safety violation(s) detected.**"
    a(safety_status)
    a("")
    a("---")
    a("")

    # ── bananaTREE Cycle ─────────────────────────────────────────────────────
    a("## bananaTREE Cycle")
    a("")
    a("| Phase | Intent | Layers |")
    a("|-------|--------|--------|")
    phase_layer_map = {}
    for finding in report.findings:
        phase_layer_map.setdefault(finding.phase, []).append(finding.layer)
    for phase in PHASE_ORDER:
        if phase.value in report.phases_run:
            intent = PHASE_INTENT.get(phase, "")[:80]
            layers = phase_layer_map.get(phase.value, [])
            a(f"| **{phase.value}** | {intent} | {len(layers)} |")
    a("")
    a("---")
    a("")

    # ── Scenario Metadata ────────────────────────────────────────────────────
    a("## Scenario Metadata")
    a("")
    a(f"| Field | Value |")
    a(f"|-------|-------|")
    a(f"| Scenario | `{report.scenario_path or 'N/A'}` |")
    a(f"| Campaign | {report.campaign_name} |")
    a(f"| Run ID | `{report.run_id}` |")
    a(f"| Phases | {', '.join(report.phases_run)} |")
    a(f"| Total Layers | {len(report.layers_run)} |")
    a(f"| Total Events | {report.total_events} |")
    a(f"| MITRE Techniques | {len(set(report.mitre.techniques))} |")
    a(f"| Dry Run | {report.dry_run} |")
    a("")
    a("---")
    a("")

    # ── Layer Execution Summary ───────────────────────────────────────────────
    a("## Layer Execution Summary")
    a("")
    a("| Phase | Layer | MITRE Techniques | Events |")
    a("|-------|-------|-----------------|--------|")
    for finding in report.findings:
        techs = ", ".join(f"`{t}`" for t in finding.mitre) or "—"
        n_events = len(finding.evidence)
        a(f"| {finding.phase} | `{finding.layer}` | {techs} | {n_events} |")
    a("")
    a("---")
    a("")

    # ── MITRE Coverage ───────────────────────────────────────────────────────
    a("## MITRE Coverage")
    a("")
    unique_techniques = sorted(set(report.mitre.techniques))
    a(f"**{len(unique_techniques)} unique techniques** across "
      f"**{len(set(report.mitre.tactics))} tactics**.")
    a("")
    if unique_techniques:
        a("| Technique | Layers |")
        a("|-----------|--------|")
        tech_to_layers: dict = {}
        for finding in report.findings:
            for t in finding.mitre:
                tech_to_layers.setdefault(t, []).append(finding.layer)
        for t in unique_techniques:
            layers = ", ".join(f"`{l}`" for l in tech_to_layers.get(t, []))
            a(f"| `{t}` | {layers} |")
    a("")
    a("---")
    a("")

    # ── Synthetic Telemetry Timeline ─────────────────────────────────────────
    a("## Synthetic Telemetry Timeline")
    a("")
    a("Chronological sequence of simulation events emitted during campaign execution.")
    a("All events are JSONL artifacts. No executable content is present.")
    a("")
    a("| Timestamp | Layer | Phase | Behavior |")
    a("|-----------|-------|-------|----------|")
    all_evidence = sorted(
        [e for f in report.findings for e in f.evidence],
        key=lambda e: e.timestamp
    )
    for ev in all_evidence[:50]:  # cap timeline display at 50
        ts = ev.timestamp[:19] if ev.timestamp else "—"
        behavior = (ev.behavior or "—")[:60]
        a(f"| `{ts}` | `{ev.layer}` | {ev.phase} | {behavior} |")
    if len(all_evidence) > 50:
        a(f"| … | … | … | +{len(all_evidence)-50} more events |")
    a("")
    a("---")
    a("")

    # ── Detection Opportunities ───────────────────────────────────────────────
    a("## Detection Opportunities")
    a("")
    a("The following detection opportunities were identified from simulation telemetry. "
      "Each represents a defender-observable signal that detection rules should cover.")
    a("")
    a("| Phase | Layer | Detection Opportunity | MITRE |")
    a("|-------|-------|----------------------|-------|")
    for det in report.detections:
        techs = ", ".join(f"`{t}`" for t in det.mitre) or "—"
        opp = det.opportunity.replace("_", " ")
        a(f"| {det.phase} | `{det.layer}` | {opp} | {techs} |")
    a("")
    a("---")
    a("")

    # ── Defensive Runbook ─────────────────────────────────────────────────────
    a("## Defensive Runbook")
    a("")
    a("Expected alert signatures produced by this simulation campaign. "
      "Use these to validate or create detection rules in your SIEM.")
    a("")
    for phase in PHASE_ORDER:
        phase_sigs = [
            s for s in report.alert_signatures
            if s.get("phase") == phase.value
        ]
        if phase_sigs:
            a(f"### {phase.value}")
            a("")
            for sig in phase_sigs:
                a(f"- **[`{sig['layer']}`]** {sig['signature']}")
            a("")
    a("---")
    a("")

    # ── Safety Contract Verification ──────────────────────────────────────────
    a("## Safety Contract Verification")
    a("")
    a("Every simulation artifact was verified against the SHENRON safety contract.")
    a("")
    a("| Check | Result |")
    a("|-------|--------|")
    a(f"| `simulation_only: true` | {_safe_badge(report.safety.simulation_only)} |")
    a(f"| `executable: false` | {_safe_badge(report.safety.executable_false)} |")
    a(f"| `no_payload_present: true` | {_safe_badge(report.safety.no_payload_present)} |")
    a(f"| `network_calls_made: false` | {_safe_badge(report.safety.network_calls_false)} |")
    a(f"| `processes_spawned: false` | {_safe_badge(report.safety.processes_spawned_false)} |")
    a(f"| **Overall** | {_safe_badge(report.safety.all_passed)} |")
    a("")
    if report.safety.violations:
        a("### Violations")
        a("")
        for v in report.safety.violations:
            a(f"- ⚠ {v}")
        a("")
    else:
        a("No violations detected. All simulation artifacts conform to the safety contract.")
        a("")
    a("---")
    a("")

    # ── Detector Validation (optional) ────────────────────────────────────────
    if validation is not None:
        lines.extend(render_validation_section(validation).splitlines())
        lines.append("")

    # ── Evidence Appendix ─────────────────────────────────────────────────────
    a("## Evidence Appendix")
    a("")
    a("Sample artifact references from the simulation JSONL log. "
      "Full artifacts available at `~/SHENRON/logs/simulation_artifacts.jsonl`.")
    a("")
    a("| Artifact ID | Layer | Phase | Behavior | Safe |")
    a("|-------------|-------|-------|----------|------|")
    for ev in report.artifacts[:30]:
        art_id = ev.artifact_id[:16] + "..." if ev.artifact_id else "—"
        behavior = (ev.behavior or "—")[:50]
        a(f"| `{art_id}` | `{ev.layer}` | {ev.phase} | {behavior} | {_safe_badge(ev.safe)} |")
    a("")
    a("---")
    a("")
    a(f"*Report generated by SHENRON v2 — gnomeman4201 / badBANANA Research Collective*  ")
    a(f"*Principle: Observable adversarial behavior, not portable adversarial procedure.*")
    a("")

    return "\n".join(lines)


def write_report(report: ShenronReport, output_dir: str = "reports", validation=None) -> str:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    filename = f"report_{report.run_id[:8]}_{report.campaign_name}.md"
    filename = filename.replace(" ", "_").replace("/", "_")
    path = out / filename
    path.write_text(render_markdown(report, validation=validation))
    return str(path)


def render_validation_section(cov: "DetectionCoverageReport") -> str:
    from core.validation.coverage import DetectionStatus
    lines = []
    a = lines.append

    verdict_badge = {
        "PASS":    "✅ PASS",
        "PARTIAL": "⚠️ PARTIAL",
        "FAIL":    "❌ FAIL",
        "UNSAFE":  "🚨 UNSAFE",
        "UNKNOWN": "❓ UNKNOWN",
    }.get(cov.verdict, cov.verdict)

    a("## Detector Validation")
    a("")
    a(f"**Verdict: {verdict_badge}**")
    a("")
    a("| Metric | Value |")
    a("|--------|-------|")
    a(f"| Expected Detections | {cov.expected_count} |")
    a(f"| Observed (PASS) | {cov.observed_count} |")
    a(f"| Partial Matches | {cov.partial_count} |")
    a(f"| Missing (MISS) | {cov.missing_count} |")
    a(f"| Coverage | **{cov.coverage_percent}%** |")
    a(f"| High-Signal Events | {cov.high_signal_count} |")
    a(f"| Safety Failures | {cov.safety_failure_count} |")
    a("")

    if cov.results:
        a("### Coverage Table")
        a("")
        a("| Status | Detection | Layer | Reason |")
        a("|--------|-----------|-------|--------|")
        for r in cov.results:
            badge = {"PASS": "✅", "MISS": "❌", "PARTIAL": "⚠️"}.get(r.status.value, "?")
            layer = f"`{r.matched_layer}`" if r.matched_layer else "—"
            reason = r.match_reason[:60] if r.match_reason else "—"
            a(f"| {badge} {r.status.value} | `{r.expectation.name}` | {layer} | {reason} |")
        a("")

    missing = [r for r in cov.results if r.status == DetectionStatus.MISS]
    if missing:
        a("### Missing Detections")
        a("")
        a("These expected detections had no matching synthetic artifact or manifest signal:")
        a("")
        for r in missing:
            mitre = f" `{r.expectation.mitre_technique}`" if r.expectation.mitre_technique else ""
            a(f"- **`{r.expectation.name}`**{mitre} — {r.match_reason}")
        a("")

    if cov.safety_failure_count > 0:
        a("> ⚠️ Safety failures detected — verdict degraded to UNSAFE regardless of coverage score.")
        a("")

    a("---")
    a("")
    return "\n".join(lines)
