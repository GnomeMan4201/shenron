import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.engine import payload_registry
from core.engine.scenario_engine import run_scenario, list_scenarios, BUILTIN_SCENARIOS
from core.reports.evidence import load_latest_report, load_report_by_run_id
from core.validation.scorer import score_latest, score_by_run_id
from core.assumptions.validator import validate_assumption, print_result as print_assumption_result
from core.assumptions.scope import generate_scope_report, update_assumption_index
from core.assumptions.loader import load_artifacts as load_artifact_jsonl
from core.sigma.evaluator import evaluate_sigma_rule, print_result as print_sigma_result
from core.assumptions.validator import validate_assumption, print_result as print_assumption_result
from core.assumptions.scope import generate_scope_report, update_assumption_index
from core.assumptions.loader import load_artifacts as load_artifact_jsonl
from core.sigma.evaluator import evaluate_sigma_rule, print_result as print_sigma_result
from core.reports.markdown import write_report, render_markdown
from core.engine.layer_loader import (
    load_all, load_layer, discover_canonical,
    get_by_category, CATEGORIES, _TYPE_TO_CAT
)

BANNER = "  SHENRON // polymorphic framework // LANimals collective // gnomeman4201"
DIVIDER = "  " + "=" * 70

def banner():
    print()
    print(BANNER)
    print()

def cmd_list(args):
    canonical = discover_canonical()
    print()
    print("  " + "LAYER".ljust(45) + "CATEGORY".ljust(15) + "FILE")
    print("  " + "-"*44 + " " + "-"*14 + " " + "-"*30)
    for lt, p in sorted(canonical.items()):
        cat = _TYPE_TO_CAT.get(lt, "unknown")
        print("  " + lt.ljust(45) + cat.ljust(15) + p.name)
    print()
    print(f"  {len(canonical)} canonical layers across {len(CATEGORIES)} categories")
    print()

def cmd_categories(args):
    print()
    print("  " + "CATEGORY".ljust(15) + "LAYERS")
    print("  " + "-"*14 + " " + "-"*50)
    for cat, layers in CATEGORIES.items():
        print("  " + cat.ljust(15) + ", ".join(layers))
    print()

def _run_layer(lt, dry_run=False):
    """Load and optionally run a single layer. Returns (ok, status_str)."""
    canonical = discover_canonical()
    if lt not in canonical:
        return False, f"not found — try --list"
    ok, err = load_layer(lt, canonical[lt])
    if not ok:
        return False, f"load failed: {err}"
    registered = payload_registry.list_registered()
    if lt not in registered:
        return False, "no @register_payload entry point"
    if dry_run:
        return True, "dry-run ok"
    result = payload_registry.run(lt)
    return (True, "executed") if result else (False, "exec failed")

def cmd_run(args):
    """--run <layer|all> [--dry-run]"""
    canonical = discover_canonical()
    target = args.run

    # Build target list
    if target == "all":
        targets = sorted(canonical.keys())
    elif target in CATEGORIES:
        targets = [lt for lt in get_by_category(target) if lt in canonical]
    elif target in canonical:
        targets = [target]
    else:
        print(f"\n  [!] Unknown target: '{target}'")
        print(f"  Valid: a layer name, a category name, or 'all'")
        print(f"  Categories: {', '.join(CATEGORIES.keys())}")
        print(f"  Layers: shenron --list\n")
        sys.exit(1)

    mode = "DRY RUN" if args.dry_run else "EXECUTE"
    print(f"\n  [{mode}] {len(targets)} layer(s)\n")
    print(f"  {'LAYER':<45} {'STATUS'}")
    print(f"  {'-'*44} {'-'*20}")

    ok_count = fail_count = 0
    for lt in targets:
        payload_registry.clear()
        ok, status = _run_layer(lt, dry_run=args.dry_run)
        marker = "✓" if ok else "✗"
        print(f"  [{marker}] {lt:<43} {status}")
        if ok:
            ok_count += 1
        else:
            fail_count += 1

    print()
    print(f"  {ok_count} ok  |  {fail_count} failed")
    print()

def cmd_layer(args):
    """--layer <name> [--dry-run] (legacy single-layer interface)"""
    ok, status = _run_layer(args.layer, dry_run=args.dry_run)
    marker = "✓" if ok else "✗"
    print(f"  [{marker}] {args.layer}: {status}")
    if not ok:
        sys.exit(1)

def cmd_stats(args):
    """--stats: run polymorph_chain_stats dashboard directly"""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "polymorph_chain_stats",
        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "core/layers/polymorph_chain_stats.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.main()

def main():
    banner()
    p = argparse.ArgumentParser(prog="shenron", add_help=True)
    p.add_argument("--list",       action="store_true",  help="list all canonical layers")
    p.add_argument("--cats",       action="store_true",  help="list categories")
    p.add_argument("--categories", type=str,             help="run layers by category (legacy)")
    p.add_argument("--run",        type=str, metavar="TARGET",
                   help="run a layer, category, or 'all'")
    p.add_argument("--layer",      type=str,             help="run a single layer (legacy)")
    p.add_argument("--dry-run",    action="store_true",  help="validate without executing")
    p.add_argument("--compare", nargs=2, metavar=("RUN_A", "RUN_B"),
                help="diff two validation runs by run ID prefix")
    p.add_argument("--navigator", type=str, nargs="?", const="latest", metavar="RUN_ID",
                help="export ATT&CK Navigator layer for a run (default: latest)")
    p.add_argument("--navigator-out", type=str, default=None, metavar="PATH",
                help="output path for Navigator JSON")
    p.add_argument("--coverage-history", action="store_true",
                help="build coverage trend report from all timeline runs")
    p.add_argument("--history-campaign", type=str, default=None, metavar="NAME",
                help="filter --coverage-history to a specific campaign name")
    p.add_argument("--mutate",           action="store_true",
                help="generate safe telemetry mutation variants from --events")
    p.add_argument("--mutation-types",   type=str, default=None, metavar="TYPES",
                help="comma-separated mutation types (default: all safe types)")
    p.add_argument("--narrate",       action="store_true",
                help="generate analyst narrative from --compare output")
    p.add_argument("--export-format", type=str, metavar="FORMAT",
                choices=["ecs", "splunk"],
                help="export events as ECS or Splunk HEC (ecs|splunk)")
    p.add_argument("--assumption",    type=str, metavar="YAML_PATH",
                help="audit a coverage assumption file against JSONL events")
    p.add_argument("--events",        type=str, default=None, metavar="JSONL_PATH",
                help="JSONL events file for --assumption (default: latest demo run)")
    p.add_argument("--release-demo",  action="store_true",
                help="build complete release artifact bundle")
    p.add_argument("--demo",          action="store_true",
                help="run safe 40-event demo pipeline (JSONL + report + charts)")
    p.add_argument("--charts",        action="store_true",
                help="generate charts from demo JSONL (use with --demo)")
    p.add_argument("--verify-safety", type=str, nargs="?", const="latest",
                metavar="JSONL_PATH",
                help="verify safety contract on a JSONL file or 'latest' artifact")
    p.add_argument("--out-dir",       type=str, default="artifacts/demo",
                metavar="DIR",
                help="output directory for --demo (default: artifacts/demo)")
    p.add_argument("--stats",      action="store_true",  help="show operational dashboard")
    p.add_argument("--scenario",   type=str, metavar="NAME", help="run a scenario")
    p.add_argument("--scenarios",  action="store_true",      help="list available scenarios")
    p.add_argument("--report",     action="store_true",      help="generate detection coverage report (legacy)")
    p.add_argument("--report-v2",  type=str, nargs="?", const="latest", metavar="RUN_ID",
                   help="generate v2 report: latest or <run_id>")
    p.add_argument("--format",     type=str, default="markdown", help="report format (markdown)")
    p.add_argument("--validate",   type=str, nargs="?", const="latest", metavar="RUN_ID",
                   help="run detector validation: latest or <run_id>")
    p.add_argument("--include-validation", action="store_true",
                   help="include detector validation in report-v2 output")
    p.add_argument("--validate-assumption", type=str, metavar="YAML",
                   help="validate assumption YAML against artifact JSONL")
    p.add_argument("--scope-report", action="store_true",
                   help="generate scope report after assumption validation")
    p.add_argument("--assumption-index", action="store_true",
                   help="show assumption audit index")
    p.add_argument("--compare-assumptions", type=str, nargs="+", metavar="YAML",
                   help="compare multiple assumption YAMLs against same artifact")
    p.add_argument("--validate-sigma", type=str, metavar="RULE_YML",
                   help="validate a Sigma rule against artifact JSONL")
    p.add_argument("--validate-sigma-dir", type=str, metavar="DIR",
                   help="validate all Sigma rules in a directory against artifact JSONL")
