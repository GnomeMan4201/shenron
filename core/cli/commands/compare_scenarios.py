"""core/cli/commands/compare_scenarios.py"""
import sys
import os
import json
from pathlib import Path
from datetime import datetime, timezone


def register(subparsers):
    p = subparsers.add_parser(
        "compare-scenarios",
        help="compare brittleness profiles across multiple campaign scenarios",
    )
    p.add_argument(
        "--scenarios", nargs="+", default=None,
        help="specific scenarios to compare (default: all)",
    )
    p.add_argument(
        "--out", type=str, default="artifacts/brittleness",
        help="output directory for reports",
    )
    p.set_defaults(func=handle)


def handle(args):
    from core.campaign.comparator import ScenarioComparator
    from core.campaign.builder import SCENARIOS

    sigma_dir = "sigma/rules"
    if not os.path.exists(sigma_dir):
        print(f"\n  [!] Sigma rules directory not found: {sigma_dir}")
        sys.exit(1)

    comparator = ScenarioComparator(sigma_dir)

    if getattr(args, "scenarios", None):
        valid = [s for s in args.scenarios if s in SCENARIOS]
        if not valid:
            print(f"\n  [!] No valid scenarios. Available: {list(SCENARIOS.keys())}")
            sys.exit(1)
        report = comparator.run_selected(valid)
    else:
        report = comparator.run_all()

    print(f"\n  [COMPARISON] {len(report.scenarios)} scenarios evaluated against {report.rules_evaluated} rules")
    print()
    print(f"  {'SCENARIO':<23} {'BRITTLENESS':<12} {'TRIGGERED':<10} {'MOST BRITTLE STAGE'}")
    print(f"  {'-'*22} {'-'*11} {'-'*9} {'-'*20}")
    for res in report.scenarios:
        trig = f"{res.triggered_count}/{res.total_stages}"
        score = "n/a" if res.overall_brittleness is None else f"{res.overall_brittleness:.2f}"
        print(f"  {res.scenario_name:<23} {score:<12} {trig:<10} {res.most_brittle_stage}")
        if res.undetected_stages:
            print(f"  {'':<23} undetected at baseline (not scored): {', '.join(res.undetected_stages)}")

    print()
    if report.universally_brittle_stages:
        print(f"  [UNIVERSAL] Stages brittle across all scenarios: {', '.join(report.universally_brittle_stages)}")
    if report.universally_detected_stages:
        print(f"  [ROBUST]    Stages detected in all scenarios: {', '.join(report.universally_detected_stages)}")
    if report.strategy_effectiveness:
        top = max(report.strategy_effectiveness.values())
        if top <= 0:
            print("  [STRATEGY]  No strategy evaded any detected stage")
        else:
            best = [s for s, v in report.strategy_effectiveness.items() if v == top]
            label = "Most effective evasion" if len(best) == 1 else "Most effective evasion (tied)"
            print(f"  [STRATEGY]  {label}: {', '.join(best)} (evaded {top:.0%} of detected stages)")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    json_path = out_dir / f"comparison_{ts}.json"
    json_path.write_text(json.dumps(report.report_to_dict(), indent=2))

    md_path = out_dir / f"comparison_{ts}.md"
    md_path.write_text(report.report_to_markdown())

    print(f"\n  [REPORT]    {json_path}")
    print(f"  [MD REPORT] {md_path}\n")
