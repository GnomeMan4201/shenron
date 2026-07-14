#!/usr/bin/env python3
"""
core/cli/commands/validate.py

shenron validate -- Score your Sigma rules against synthetic campaigns.

The primary detection engineer workflow:
  shenron validate --rules /path/to/your/sigma/rules/

What it does:
  1. Loads all Sigma rules from the specified directory
  2. Evaluates each rule against SHENRON synthetic campaign artifacts
  3. Scores brittleness: which rules break under adversarial mutations
  4. Reports which rules are robust, brittle, or have no coverage

Exit codes:
  0  All triggered rules are robust (brittleness below threshold)
  1  No rules triggered (coverage gap)
  2  One or more brittle rules detected
"""

import sys
import json
import tempfile
import os
from pathlib import Path
from typing import List


def register(subparsers):
    p = subparsers.add_parser(
        "validate",
        help="score your Sigma rules against synthetic adversary campaigns",
        description="Score detection rules for coverage and brittleness.",
    )
    p.add_argument("--rules", required=True, metavar="DIR_OR_FILE",
                   help="Sigma rules directory or single .yml file")
    p.add_argument("--artifact", default=None, metavar="JSONL",
                   help="evaluate against a specific SHENRON JSONL artifact")
    p.add_argument("--scenario", default="apt29-style", metavar="NAME",
                   help="adversary scenario (default: apt29-style)")
    p.add_argument("--no-mutations", action="store_false", dest="mutations",
                   help="skip brittleness scoring, check coverage only")
    p.add_argument("--out", default=None, metavar="PATH",
                   help="write markdown report to this path")
    p.add_argument("--format", choices=["table", "json", "markdown"], default="table",
                   help="output format (default: table)")
    p.add_argument("--threshold", type=float, default=0.5, metavar="FLOAT",
                   help="brittleness threshold for warnings (default: 0.5)")
    p.set_defaults(func=run, mutations=True)
    return p


def _load_rule_paths(rules_arg):
    p = Path(rules_arg)
    if p.is_file():
        return [p]
    if p.is_dir():
        paths = sorted(p.rglob("*.yml")) + sorted(p.rglob("*.yaml"))
        return [x for x in paths if not x.name.startswith(".")]
    print(f"  [ERROR] Rules path not found: {rules_arg}")
    sys.exit(1)


def _evaluate_rules(rule_paths, artifact_path):
    from core.sigma.evaluator import evaluate_sigma_rule
    from core.sigma.model import RuleVerdict
    results = {}
    for rp in rule_paths:
        try:
            r = evaluate_sigma_rule(str(rp), artifact_path, match_mode="tolerant")
            results[str(rp)] = {
                "rule_id":        r.rule_id,
                "rule_title":     r.rule_title,
                "verdict":        r.verdict.value,
                "triggered":      r.verdict == RuleVerdict.TRIGGERED,
                "triggered_count": r.triggered_count,
            }
        except Exception as e:
            results[str(rp)] = {
                "rule_id":        Path(rp).stem,
                "rule_title":     Path(rp).stem,
                "verdict":        "ERROR",
                "triggered":      False,
                "triggered_count": 0,
                "error":          str(e),
            }
    return results


def _score_brittleness(rule_path, artifact_path):
    try:
        from core.sigma.evaluator import evaluate_sigma_rule
        from core.sigma.model import RuleVerdict
        from core.mutation.engine import (
            mutate_field_drop, mutate_timing_jitter,
            mutate_label_ambiguity, mutate_signal_density_low,
        )
        from core.mutation.sigma_aware import SigmaAwareMutator

        with open(artifact_path) as f:
            events = [json.loads(l) for l in f if l.strip()]

        baseline = evaluate_sigma_rule(rule_path, artifact_path, match_mode="tolerant")
        if baseline.verdict != RuleVerdict.TRIGGERED:
            return 0.0

        rules_dir = str(Path(rule_path).parent)
        try:
            mutator = SigmaAwareMutator(rules_dir)
        except Exception:
            mutator = None

        strategies = [
            lambda e: mutate_field_drop(e, run_id="v", seed=42).records,
            lambda e: mutate_timing_jitter(e, run_id="v", seed=42).records,
            lambda e: mutate_label_ambiguity(e, run_id="v", seed=42).records,
            lambda e: mutate_signal_density_low(e, run_id="v", seed=42).records,
        ]
        if mutator:
            for strat in ["case_flip", "value_swap", "field_omit"]:
                s = strat
                strategies.append(lambda e, s=s: [mutator.mutate_targeted(ev, s, seed=42) for ev in e])

        evaded = 0
        total = 0
        for fn in strategies:
            try:
                mutated = fn(events)
                tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
                for ev in mutated:
                    tmp.write(json.dumps(ev) + "\n")
                tmp.close()
                r = evaluate_sigma_rule(rule_path, tmp.name, match_mode="tolerant")
                os.unlink(tmp.name)
                total += 1
                if r.verdict != RuleVerdict.TRIGGERED:
                    evaded += 1
            except Exception:
                pass

        return round(evaded / total, 3) if total > 0 else 0.0
    except Exception:
        return 0.0


def _format_table(results, threshold):
    lines = ["", "  SHENRON Rule Validation Results", "  " + "=" * 72]
    lines.append(f"  {'Rule':<44} {'Coverage':<11} {'Brittleness':<13} Status")
    lines.append("  " + "-" * 72)
    for r in sorted(results, key=lambda x: x["brittleness"], reverse=True):
        title = r["rule_title"][:42]
        cov = "TRIGGERED" if r["triggered"] else "no coverage"
        brit = f"{r['brittleness']:.2f}" if r["triggered"] else "  --"
        if not r["triggered"]:
            status = "no coverage"
        elif r["brittleness"] >= threshold:
            status = "!! BRITTLE"
        elif r["brittleness"] >= 0.3:
            status = "moderate"
        else:
            status = "robust"
        lines.append(f"  {title:<44} {cov:<11} {brit:<13} {status}")
    lines.append("  " + "-" * 72)
    triggered = sum(1 for r in results if r["triggered"])
    brittle   = sum(1 for r in results if r["triggered"] and r["brittleness"] >= threshold)
    no_cov    = sum(1 for r in results if not r["triggered"])
    lines += [
        f"",
        f"  Rules evaluated : {len(results)}",
        f"  Coverage        : {triggered}/{len(results)} rules triggered",
        f"  Brittle rules   : {brittle} (brittleness >= {threshold})",
        f"  No coverage     : {no_cov} rules never fired on this scenario",
    ]
    if brittle > 0:
        lines.append(f"")
        lines.append(f"  WARNING: {brittle} rule(s) are brittle.")
        lines.append(f"  Trivial adversarial mutations cause these rules to stop firing.")
        lines.append(f"  Broaden detection logic beyond exact field value matching.")
    if no_cov > 0:
        lines.append(f"")
        lines.append(f"  INFO: {no_cov} rule(s) had no coverage on this scenario.")
        lines.append(f"  These rules may target techniques not present in this campaign.")
    lines.append("")
    return "\n".join(lines)


def _format_markdown(results, threshold, scenario, artifact):
    triggered = sum(1 for r in results if r["triggered"])
    brittle   = [r for r in results if r["triggered"] and r["brittleness"] >= threshold]
    robust    = [r for r in results if r["triggered"] and r["brittleness"] < threshold]
    no_cov    = [r for r in results if not r["triggered"]]
    lines = [
        "# SHENRON Rule Validation Report", "",
        f"**Scenario:** {scenario}  ",
        f"**Artifact:** {artifact}  ",
        f"**Rules evaluated:** {len(results)}  ",
        f"**Coverage:** {triggered}/{len(results)} triggered  ",
        f"**Brittleness threshold:** {threshold}  ", "",
        "## Summary", "",
        "| Category | Count |", "|---|---|",
        f"| Triggered | {triggered} |",
        f"| Brittle (>= {threshold}) | {len(brittle)} |",
        f"| Robust (< {threshold}) | {len(robust)} |",
        f"| No coverage | {len(no_cov)} |", "",
        "## Brittle Rules (fix these first)", "",
    ]
    if brittle:
        lines += ["| Rule | Brittleness |", "|---|---|"]
        for r in sorted(brittle, key=lambda x: x["brittleness"], reverse=True):
            lines.append(f"| {r['rule_title']} | {r['brittleness']:.2f} |")
    else:
        lines.append("*No brittle rules detected.*")
    lines += ["", "## Robust Rules", ""]
    for r in robust:
        lines.append(f"- **{r['rule_title']}** ({r['brittleness']:.2f})")
    if not robust:
        lines.append("*No robust rules.*")
    lines += ["", "## No Coverage", ""]
    for r in no_cov:
        lines.append(f"- {r['rule_title']}")
    if not no_cov:
        lines.append("*All rules had coverage.*")
    return "\n".join(lines)


def run(args):
    rule_paths = _load_rule_paths(args.rules)
    if not rule_paths:
        print(f"  [ERROR] No .yml rules found in: {args.rules}")
        sys.exit(1)

    print(f"\n  [VALIDATE] Rules        : {len(rule_paths)}")

    if args.artifact:
        artifact_path = args.artifact
        scenario_name = "custom"
    else:
        artifact_path = str(
            Path(__file__).parent.parent.parent.parent
            / "artifacts" / "demo" / "shenron_demo_run.jsonl"
        )
        scenario_name = args.scenario
        if not Path(artifact_path).exists():
            print(f"  [ERROR] Demo artifact not found: {artifact_path}")
            sys.exit(1)

    print(f"  [VALIDATE] Scenario     : {scenario_name}")
    print(f"  [VALIDATE] Artifact     : {artifact_path}")
    print(f"  [VALIDATE] Brittleness  : {'on' if args.mutations else 'off'}")
    print()

    eval_results = _evaluate_rules(rule_paths, artifact_path)

    final = []
    for rp, er in eval_results.items():
        brit = 0.0
        if args.mutations and er["triggered"]:
            print(f"  [SCORING] {Path(rp).name}...")
            brit = _score_brittleness(rp, artifact_path)
        final.append({
            "rule_path":       rp,
            "rule_id":         er["rule_id"],
            "rule_title":      er["rule_title"],
            "triggered":       er["triggered"],
            "triggered_count": er["triggered_count"],
            "brittleness":     brit,
            "verdict":         er["verdict"],
        })

    if args.format == "json":
        print(json.dumps(final, indent=2))
    elif args.format == "markdown":
        print(_format_markdown(final, args.threshold, scenario_name, artifact_path))
    else:
        print(_format_table(final, args.threshold))

    if args.out:
        md = _format_markdown(final, args.threshold, scenario_name, artifact_path)
        Path(args.out).write_text(md, encoding="utf-8")
        print(f"  [VALIDATE] Report       : {args.out}")

    brittle_count = sum(1 for r in final if r["triggered"] and r["brittleness"] >= args.threshold)
    no_cov_count  = sum(1 for r in final if not r["triggered"])
    if brittle_count > 0:
        sys.exit(2)
    elif no_cov_count == len(final):
        sys.exit(1)
    sys.exit(0)
