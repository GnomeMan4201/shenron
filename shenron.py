import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.engine import payload_registry
from core.engine.scenario_engine import run_scenario, list_scenarios, BUILTIN_SCENARIOS
from core.reports.evidence import load_latest_report, load_report_by_run_id
from core.validation.scorer import score_latest, score_by_run_id
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
    args = p.parse_args()

    if args.list:           cmd_list(args)
    elif args.cats:         cmd_categories(args)
    elif args.run:          cmd_run(args)
    elif args.categories:   cmd_run(type('A', (), {
                                'run': args.categories,
                                'dry_run': args.dry_run
                            })())
    elif args.layer:        cmd_layer(args)
    elif args.stats:        cmd_stats(args)
    elif args.scenario:     run_scenario(args.scenario, dry_run=args.dry_run)
    elif args.scenarios:    list_scenarios()
    elif args.validate is not None:
        run_id = args.validate
        cov = score_by_run_id(run_id) if run_id != 'latest' else score_latest()
        if cov is None:
            print(f'  [!] No campaign run found for: {run_id}')
        else:
            print(f'\n  [VALIDATION]  {cov.campaign_name}')
            print(f'  [RUN_ID]      {cov.run_id}')
            print(f'  [EXPECTED]    {cov.expected_count}')
            print(f'  [OBSERVED]    {cov.observed_count}')
            print(f'  [PARTIAL]     {cov.partial_count}')
            print(f'  [MISSING]     {cov.missing_count}')
            print(f'  [COVERAGE]    {cov.coverage_percent}%')
            print(f'  [SAFETY FAIL] {cov.safety_failure_count}')
            print(f'  [VERDICT]     {cov.verdict}')
            print()
    elif args.report_v2 is not None:
        run_id = args.report_v2
        rpt = load_report_by_run_id(run_id) if run_id != 'latest' else load_latest_report()
        if rpt is None:
            print(f'  [!] No report found for: {run_id}')
        else:
            from pathlib import Path as _P
            cov = None
            if getattr(args, 'include_validation', False):
                cov = score_by_run_id(run_id) if run_id != 'latest' else score_latest()
            path_out = write_report(rpt, output_dir='reports', validation=cov)
            print(f'  [+] Report written: {path_out}')
            print(f'  [+] Safety contract: {"PASS" if rpt.safety.all_passed else "FAIL"}')
    elif getattr(args, 'report', False):
        import importlib.util, os
        spec = importlib.util.spec_from_file_location("generate_report",
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "scripts/generate_report.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.generate_report()
    else:                   p.print_help()

if __name__ == "__main__":
    main()
