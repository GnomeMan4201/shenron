"""core/cli/commands/report.py"""


def register(subparsers):
    p = subparsers.add_parser("report", help="report generation")
    sub = p.add_subparsers(dest="report_cmd", metavar="SUBCMD", required=True)

    # report html [--events <jsonl>]
    html = sub.add_parser("html", help="generate standalone HTML report from latest run")
    html.add_argument("--events", type=str, default=None, metavar="JSONL",
                      help="JSONL events file (default: latest demo run)")
    html.set_defaults(func=_handle_html)


def _handle_html(args):
    import json
    from pathlib import Path
    from datetime import datetime, timezone
    from collections import Counter

    from core.reports.html_report import generate_html_report
    from core.sigma.evaluator import evaluate_sigma_rule
    from core.assumptions.validator import validate_assumption
    from core.assumptions.loader import load_artifacts
    from core.config import artifact_log_path, timeline_log_path

    events_path = getattr(args, "events", None) or str(artifact_log_path())

    timeline_p = timeline_log_path()
    run_id   = "manual"
    campaign = "manual"
    ts       = datetime.now(timezone.utc).isoformat()
    if timeline_p.exists():
        raw_lines = [l for l in timeline_p.read_text().splitlines() if l.strip()]
        if raw_lines:
            last     = json.loads(raw_lines[-1])
            run_id   = last.get("run_id", run_id)
            campaign = last.get("campaign_name", campaign)
            ts       = last.get("timestamp", ts)

    report_data = {
        "run_id":         run_id,
        "campaign_name":  campaign,
        "timestamp":      ts,
        "safety":         {"verdict": "PASS", "violations": []},
        "coverage":       {"score": 0.0, "verdict": "UNKNOWN"},
        "findings":       [],
        "mitre_coverage": {},
    }

    arts    = load_artifacts(events_path)
    mitre   = Counter()
    findings = []
    for a in arts:
        techs = a.get("mitre_techniques", [])
        if isinstance(techs, str):
            techs = [techs]
        for t in techs:
            mitre[t] += 1
        if a.get("detection_opportunities"):
            findings.append(a)
    report_data["mitre_coverage"] = {t: {"count": n} for t, n in mitre.items()}
    report_data["findings"]       = findings[:50]

    sigma_results = []
    sigma_dir = Path("sigma/rules")
    if sigma_dir.exists() and Path(events_path).exists():
        for rp in sorted(sigma_dir.rglob("*.yml")):
            r = evaluate_sigma_rule(str(rp), events_path)
            sigma_results.append(r.to_dict())

    assumption_results = []
    assumption_dir = Path("assumptions/examples")
    if assumption_dir.exists() and Path(events_path).exists():
        for ap in sorted(assumption_dir.glob("*.yaml")):
            r = validate_assumption(str(ap), events_path)
            assumption_results.append(r.to_dict())

    out = generate_html_report(
        report_data,
        sigma_results=sigma_results,
        assumption_results=assumption_results,
    )
    print(f"  [+] HTML report: {out}")
