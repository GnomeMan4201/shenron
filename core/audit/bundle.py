# core/audit/bundle.py
# SHENRON Audit Bundle — produces a complete, defensible evidence package.
# No external deps — stdlib only.

from __future__ import annotations
import json
import hashlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def _ts():
    return datetime.now(timezone.utc).isoformat()[:19]


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_events(path: str) -> list:
    events = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events


def run_audit_bundle(
    events_path: str,
    rules_dir: str,
    assumptions_dir: str,
    out_dir: str,
    verbose: bool = True,
) -> dict:
    from core.schema.validator import validate_events_file
    from core.sigma.evaluator import evaluate_sigma_rule
    from core.assumptions.validator import validate_assumption
    from core.reports.html_report import generate_html_report
    from core.assumptions.loader import load_artifacts

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    ts = _ts()
    results = {}

    def _p(msg):
        if verbose:
            print(f"  {msg}")

    _p(f"SHENRON Audit Bundle — {ts} UTC")
    _p(f"Artifact : {events_path}")
    _p(f"Rules    : {rules_dir}")
    _p(f"Assumptions: {assumptions_dir}")
    _p(f"Output   : {out_dir}")
    _p("")

    # ── Step 1: Schema + safety validation (gate) ────────────────────────────
    _p("[ 1/6 ] Schema validation...")
    schema_result = validate_events_file(events_path)
    if not schema_result["ok"]:
        _p(f"  FAIL — {len(schema_result['failures'])} schema violation(s):")
        for f in schema_result["failures"][:10]:
            _p(f"    {f}")
        _p("  Audit bundle aborted — fix schema violations first.")
        _p("  Run: shenron schema validate --events <jsonl>")
        return {"ok": False, "error": "schema_validation_failed", "failures": schema_result["failures"]}
    _p(f"  OK — {schema_result['events']} events pass schema validation")

    # Safety contract check
    events = _load_events(events_path)
    safety_violations = []
    for i, e in enumerate(events, 1):
        if e.get("simulation_only") is not True:
            safety_violations.append(f"line {i}: simulation_only is not true")
        if e.get("executable") is True:
            safety_violations.append(f"line {i}: executable is true")

    safety_verdict = "PASS" if not safety_violations else "FAIL"
    safety_data = {
        "verdict":       safety_verdict,
        "events_checked": len(events),
        "violations":    safety_violations,
        "timestamp":     ts,
        "artifact":      events_path,
    }
    safety_path = out / "safety_verification.json"
    safety_path.write_text(json.dumps(safety_data, indent=2))
    _p(f"  Safety: {safety_verdict} ({len(safety_violations)} violations)")
    _p(f"   -> {safety_path}")
    _p("")

    # ── Step 2: Sigma validation ─────────────────────────────────────────────
    _p("[ 2/6 ] Sigma rule validation...")
    sigma_results = []
    rules_path = Path(rules_dir)
    if rules_path.exists():
        for rp in sorted(rules_path.rglob("*.yml")):
            r = evaluate_sigma_rule(str(rp), events_path)
            sigma_results.append(r.to_dict())
            mark = {"TRIGGERED": "+", "PARTIAL": "~", "NOT_TRIGGERED": "-", "UNSUPPORTED": "?"}.get(r.verdict.value, " ")
            _p(f"   [{mark}] {r.verdict.value:15s}  {r.rule_title}")

    sigma_path = out / "sigma_results.json"
    sigma_path.write_text(json.dumps(sigma_results, indent=2))
    triggered = sum(1 for r in sigma_results if r.get("verdict") == "TRIGGERED")
    partial   = sum(1 for r in sigma_results if r.get("verdict") == "PARTIAL")
    _p(f"   -> {sigma_path} ({triggered} TRIGGERED, {partial} PARTIAL)")
    _p("")
    results["sigma"] = sigma_results

    # ── Step 3: Assumption validation ────────────────────────────────────────
    _p("[ 3/6 ] Assumption validation...")
    assumption_results = []
    assumptions_path = Path(assumptions_dir)
    overclaims = []
    if assumptions_path.exists():
        for ap in sorted(assumptions_path.glob("*.yaml")):
            r = validate_assumption(str(ap), events_path)
            assumption_results.append(r.to_dict())
            oos = f" OOS:{r.out_of_scope_violations}" if r.out_of_scope_violations else ""
            _p(f"   {r.assumption_id:<40} {r.status.value}{oos}")
            if r.out_of_scope_violations:
                overclaims.append({
                    "assumption_id": r.assumption_id,
                    "status":        r.status.value,
                    "violations":    r.out_of_scope_violations,
                    "conclusion":    r.safe_conclusion,
                })

    assumption_path = out / "assumption_results.json"
    assumption_path.write_text(json.dumps(assumption_results, indent=2))
    supported = sum(1 for r in assumption_results if r.get("status") == "SUPPORTED")
    _p(f"   -> {assumption_path} ({supported}/{len(assumption_results)} SUPPORTED)")
    _p("")
    results["assumptions"] = assumption_results

    # ── Step 4: ATT&CK Navigator layer ───────────────────────────────────────
    _p("[ 4/6 ] ATT&CK Navigator layer...")
    arts  = load_artifacts(events_path)
    mitre = Counter()
    for a in arts:
        techs = a.get("mitre_techniques", [])
        if isinstance(techs, str):
            techs = [techs]
        for t in techs:
            mitre[t] += 1

    sigma_verdict_map = {}
    for r in sigma_results:
        for det in r.get("detections", []):
            for fm in det.get("field_matches", []):
                if fm.get("field") == "mitre_technique" and fm.get("matched"):
                    tech = fm.get("expected", "").upper()
                    if tech:
                        sigma_verdict_map[tech] = r.get("verdict", "UNKNOWN")

    COLOR_MAP = {
        "TRIGGERED":     "#22c55e",
        "PARTIAL":       "#f59e0b",
        "NOT_TRIGGERED": "#ef4444",
        "UNSUPPORTED":   "#94a3b8",
    }

    navigator_techniques = []
    for tech, count in mitre.items():
        verdict = sigma_verdict_map.get(tech.upper(), "NOT_TRIGGERED")
        navigator_techniques.append({
            "techniqueID": tech,
            "score":       count,
            "color":       COLOR_MAP.get(verdict, "#94a3b8"),
            "comment":     f"SHENRON: {count} artifact(s) | Sigma: {verdict}",
            "enabled":     True,
        })

    navigator_layer = {
        "name":        "SHENRON Audit Coverage",
        "versions":    {"attack": "14", "navigator": "4.9"},
        "domain":      "enterprise-attack",
        "description": f"Generated by SHENRON audit bundle — {ts} UTC",
        "techniques":  navigator_techniques,
        "gradient":    {"colors": ["#ffffff", "#22c55e"], "minValue": 0, "maxValue": 10},
        "legendItems": [
            {"label": "TRIGGERED",     "color": "#22c55e"},
            {"label": "PARTIAL",       "color": "#f59e0b"},
            {"label": "NOT_TRIGGERED", "color": "#ef4444"},
        ],
        "metadata":               [],
        "showTacticRowBackground": True,
        "tacticRowBackground":     "#1e293b",
    }

    navigator_path = out / "attack_navigator_layer.json"
    navigator_path.write_text(json.dumps(navigator_layer, indent=2))
    _p(f"   {len(navigator_techniques)} techniques mapped")
    _p(f"   -> {navigator_path}")
    _p("")
    results["navigator"] = str(navigator_path)

    # ── Step 5: Overclaim risk report ────────────────────────────────────────
    _p("[ 5/6 ] Overclaim risk report...")
    overclaim_lines = ["# Overclaim Risk Report", "", f"Generated: {ts} UTC", f"Artifact: {events_path}", ""]

    if not overclaims:
        overclaim_lines += ["## Result: NO OVERCLAIM VIOLATIONS DETECTED", "",
                           "All assumption claims are within the supported scope of this artifact."]
    else:
        overclaim_lines += [f"## Result: {len(overclaims)} OVERCLAIM VIOLATION(S) DETECTED", "",
                           "The following assumptions make claims this artifact cannot honestly support.", ""]
        for oc in overclaims:
            overclaim_lines += [
                f"### {oc['assumption_id']}",
                f"- Status: `{oc['status']}`",
                f"- Out-of-scope claims: {', '.join(oc['violations'])}",
                f"- Conclusion: {oc['conclusion']}",
                "",
            ]
        overclaim_lines += [
            "## What this means",
            "",
            "An `OUT_OF_SCOPE_VIOLATION` means the artifact is being used to support",
            "a detection claim it cannot honestly back. Review the out-of-scope claims",
            "listed above and remove or narrow them before using this artifact as evidence.",
        ]

    unsupported_sigma = [r for r in sigma_results if r.get("verdict") == "UNSUPPORTED"]
    if unsupported_sigma:
        overclaim_lines += ["", f"## {len(unsupported_sigma)} Sigma rule(s) returned UNSUPPORTED", "",
                           "These rules depend on fields not present in SHENRON artifacts.",
                           "They cannot be used to validate detection coverage.", ""]
        for r in unsupported_sigma:
            overclaim_lines.append(f"- `{r.get('rule_id', 'unknown')}` — {r.get('rule_title', '')}")

    overclaim_path = out / "overclaim_risk.md"
    overclaim_path.write_text("\n".join(overclaim_lines))
    _p(f"   {len(overclaims)} overclaim violation(s), {len(unsupported_sigma)} unsupported rule(s)")
    _p(f"   -> {overclaim_path}")
    _p("")

    # ── Step 6: Reproducibility manifest ─────────────────────────────────────
    _p("[ 6/6 ] Reproducibility manifest...")
    repro_data = {
        "generated_at":     ts,
        "shenron_version":  "0.4.0",
        "inputs": {
            "events_path":      events_path,
            "events_sha256":    _sha256(events_path),
            "events_count":     len(events),
            "rules_dir":        rules_dir,
            "rules_count":      len(sigma_results),
            "assumptions_dir":  assumptions_dir,
            "assumptions_count":len(assumption_results),
        },
        "outputs": {
            "safety_verification": str(safety_path),
            "sigma_results":       str(sigma_path),
            "assumption_results":  str(assumption_path),
            "navigator_layer":     str(navigator_path),
            "overclaim_risk":      str(overclaim_path),
        },
        "summary": {
            "schema_valid":         schema_result["ok"],
            "safety_verdict":       safety_verdict,
            "sigma_triggered":      triggered,
            "sigma_partial":        partial,
            "sigma_unsupported":    len(unsupported_sigma),
            "assumptions_supported":supported,
            "assumptions_total":    len(assumption_results),
            "overclaim_violations": len(overclaims),
            "mitre_techniques":     len(navigator_techniques),
        },
    }

    repro_path = out / "reproducibility.json"
    repro_path.write_text(json.dumps(repro_data, indent=2))

    repro_md_lines = [
        "# Reproducibility Statement",
        "",
        f"Generated: {ts} UTC",
        f"SHENRON version: 0.4.0",
        "",
        "## Inputs",
        "",
        f"| Input | Value |",
        f"|---|---|",
        f"| Events file | `{events_path}` |",
        f"| Events SHA-256 | `{repro_data['inputs']['events_sha256'][:16]}...` |",
        f"| Events count | {len(events)} |",
        f"| Sigma rules | {len(sigma_results)} rules from `{rules_dir}` |",
        f"| Assumptions | {len(assumption_results)} YAMLs from `{assumptions_dir}` |",
        "",
        "## To reproduce this bundle",
        "",
        "```bash",
        "python3 shenron.py audit bundle \\",
        f"  --events {events_path} \\",
        f"  --rules {rules_dir} \\",
        f"  --assumptions {assumptions_dir} \\",
        f"  --out {out_dir}",
        "```",
        "",
        "## Summary",
        "",
        f"| Check | Result |",
        f"|---|---|",
        f"| Schema valid | {schema_result['ok']} |",
        f"| Safety verdict | {safety_verdict} |",
        f"| Sigma TRIGGERED | {triggered} |",
        f"| Sigma UNSUPPORTED | {len(unsupported_sigma)} |",
        f"| Assumptions SUPPORTED | {supported}/{len(assumption_results)} |",
        f"| Overclaim violations | {len(overclaims)} |",
        f"| MITRE techniques | {len(navigator_techniques)} |",
    ]

    repro_md_path = out / "reproducibility.md"
    repro_md_path.write_text("\n".join(repro_md_lines))
    _p(f"   -> {repro_path}")
    _p(f"   -> {repro_md_path}")
    _p("")

    # ── Index HTML ────────────────────────────────────────────────────────────
    report_data = {
        "run_id":        "audit_bundle",
        "campaign_name": "audit",
        "timestamp":     ts,
        "safety":        {"verdict": safety_verdict, "violations": safety_violations},
        "coverage":      {"score": 0.0, "verdict": "AUDIT"},
        "findings":      [a for a in arts if a.get("detection_opportunities")][:50],
        "mitre_coverage":{t: {"count": n} for t, n in mitre.items()},
    }

    html_path = generate_html_report(
        report_data,
        output_path       = str(out / "index.html"),
        sigma_results     = sigma_results,
        assumption_results= assumption_results,
    )
    results["html"] = html_path
    _p(f"   -> {html_path}")
    _p("")

    # ── Final summary ─────────────────────────────────────────────────────────
    _p("=" * 60)
    _p("Audit bundle complete.")
    _p("")
    _p(f"  Schema valid          : {schema_result['ok']}")
    _p(f"  Safety verdict        : {safety_verdict}")
    _p(f"  Sigma TRIGGERED       : {triggered}/{len(sigma_results)}")
    _p(f"  Assumptions SUPPORTED : {supported}/{len(assumption_results)}")
    _p(f"  Overclaim violations  : {len(overclaims)}")
    _p(f"  MITRE techniques      : {len(navigator_techniques)}")
    _p("")
    _p(f"  Output: {out_dir}/")
    _p("")
    _p("  Observable adversarial behavior, not portable adversarial procedure.")
    _p("=" * 60)

    results["ok"]   = True
    results["repro"] = repro_data
    return results
