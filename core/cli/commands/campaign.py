"""core/cli/commands/campaign.py — campaign generation subcommand"""
import sys
import os
import json
from pathlib import Path


def register(subparsers):
    p = subparsers.add_parser(
        "campaign",
        help="generate causally-linked campaign telemetry",
    )
    p.add_argument(
        "--scenario", type=str, default="apt29-style",
        help="scenario name (apt29-style, ransomware-precursor, insider-threat)",
    )
    p.add_argument(
        "--length", type=int, default=72,
        help="duration in hours",
    )
    p.add_argument(
        "--output", type=str, default=None,
        help="output JSONL path (default: artifacts/campaigns/<id>.jsonl)",
    )
    p.add_argument(
        "--list-scenarios", action="store_true",
        help="list available scenarios",
    )
    p.add_argument(
        "--stress-test", action="store_true",
        help="run brittleness scoring against campaign artifacts",
    )
    p.set_defaults(func=handle)


def handle(args):
    from core.campaign.builder import CampaignBuilder, SCENARIOS

    if getattr(args, "list_scenarios", False):
        print("\n  Available Campaign Scenarios:")
        for s in SCENARIOS.keys():
            print(f"    - {s}")
        print()
        return

    builder = CampaignBuilder.from_scenario(args.scenario, args.length)
    campaign = builder.build()
    artifacts = builder.to_jsonl()

    out_path = args.output or f"artifacts/campaigns/{campaign.campaign_id}.jsonl"
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        for a in artifacts:
            f.write(json.dumps(a) + "\n")

    print(f"\n  [CAMPAIGN] Generated {len(artifacts)} events for scenario '{args.scenario}'")
    print(f"  [OUTPUT]   {out_path}")

    if getattr(args, "stress_test", False):
        from core.brittleness.scorer import BrittlenessScorer

        sigma_dir = "sigma"
        if not os.path.exists(sigma_dir):
            print("  [!] Sigma rules directory not found for stress test. Skipping.")
            return

        scorer = BrittlenessScorer(sigma_dir)
        report = scorer.score_campaign(campaign)

        print("\n  [STRESS TEST] Brittleness Report:")
        print(f"  {'STAGE':<30} {'BRITTLENESS':<15} {'MOST EVADING':<25}")
        print(f"  {'-'*29} {'-'*14} {'-'*24}")
        for ab in report.per_artifact:
            most_evaded = ab.variants_that_evade[0] if ab.variants_that_evade else "none"
            print(f"  {ab.stage:<30} {ab.evasion_rate:<15.2f} {most_evaded:<25}")

        report_path = Path("artifacts/brittleness") / f"{campaign.campaign_id}_report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report.report_to_dict(), indent=2))
        print(f"\n  [REPORT]   {report_path}")
