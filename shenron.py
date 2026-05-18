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
from core.reports.html_report import generate_html_report
from core.assumptions.scope import generate_scope_report, update_assumption_index
from core.assumptions.loader import load_artifacts as load_artifact_jsonl
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
    p.add_argument("--report-html", action="store_true",
                   help="generate standalone HTML report from latest run")
    p.add_argument("--validate-sigma", type=str, metavar="RULE_YML",
                   help="validate a Sigma rule against artifact JSONL")
    p.add_argument("--validate-sigma-dir", type=str, metavar="DIR",
                   help="validate all Sigma rules in a directory against artifact JSONL")
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
    elif getattr(args, 'report_html', False):
        from core.reports.evidence import build_report_from_run, get_campaign_runs
        from core.validation.scorer import score_latest
        from core.assumptions.validator import validate_assumption
        runs = get_campaign_runs()
        if not runs:
            print("  [!] No runs found. Run a campaign first.")
        else:
            latest_run = runs[-1]
            run_id = latest_run.get("run_id", "unknown")
            campaign = latest_run.get("campaign_name", "unknown")
            # Build base report data
            report_data = {
                "run_id":        run_id,
                "campaign_name": campaign,
                "timestamp":     latest_run.get("timestamp", ""),
                "safety":        {"verdict": "PASS", "violations": []},
                "coverage":      {"score": 0.0, "verdict": "UNKNOWN"},
                "findings":      [],
                "mitre_coverage": {},
            }
            # Add sigma results if rules exist
            sigma_results = []
            sigma_dir = Path("sigma/rules")
            events_path = getattr(args, 'events', None)
            if not events_path:
                from core.config import artifact_log_path
                events_path = str(artifact_log_path())
            if sigma_dir.exists() and Path(events_path).exists():
                for rp in sorted(sigma_dir.rglob("*.yml")):
                    r = evaluate_sigma_rule(str(rp), events_path)
                    sigma_results.append(r.to_dict())
            # Add assumption results if examples exist
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
    elif getattr(args, 'validate_sigma', None):
        rule_path   = args.validate_sigma
        events_path = getattr(args, 'events', None)
        if not events_path:
            print("  [!] --validate-sigma requires --events <jsonl>")
        else:
            result = evaluate_sigma_rule(rule_path, events_path)
            print_sigma_result(result)
    elif getattr(args, 'validate_sigma_dir', None):
        events_path = getattr(args, 'events', None)
        if not events_path:
            print("  [!] --validate-sigma-dir requires --events <jsonl>")
        else:
            from pathlib import Path as _P
            rules = sorted(_P(args.validate_sigma_dir).rglob('*.yml'))
            if not rules:
                print(f"  [!] No .yml files in {args.validate_sigma_dir}")
            else:
                print(f"\n  Evaluating {len(rules)} rule(s)\n")
                counts = {}
                for rp in rules:
                    r = evaluate_sigma_rule(str(rp), events_path)
                    v = r.verdict.value
                    counts[v] = counts.get(v, 0) + 1
                    mark = {"TRIGGERED":"+","PARTIAL":"~","NOT_TRIGGERED":"-","UNSUPPORTED":"?"}.get(v," ")
                    print(f"  [{mark}] {v:15s}  {r.rule_title}")
                print(f"\n  Summary: {counts}\n")
    elif getattr(args, 'compare_assumptions', None):
        events_path = getattr(args, 'events', None)
        yamls = args.compare_assumptions
        if not events_path:
            print("  [!] --compare-assumptions requires --events <jsonl>")
        else:
            print(f"\n  Artifact: {events_path}\n")
            for yaml_path in yamls:
                result = validate_assumption(yaml_path, events_path)
                name = result.assumption_id
                status = result.status.value
                sup = result.supported_count
                uns = result.unsupported_count
                print(f"  {name}:")
                print(f"    status:    {status}")
                print(f"    supported: {sup}")
                print(f"    unsupported: {uns}")
                if result.out_of_scope_violations:
                    print(f"    oos_violations: {result.out_of_scope_violations}")
                print()
            print(f"  Conclusion:")
            for yaml_path in yamls:
                result = validate_assumption(yaml_path, events_path)
                for line in result.safe_conclusion.split(". "):
                    if line.strip():
                        print(f"    {line.strip()}.")
            print()
    elif getattr(args, 'assumption_index', False):
        from core.config import get_report_dir
        idx = get_report_dir() / "assumptions" / "index.md"
        if idx.exists():
            print(idx.read_text())
        else:
            print("  [!] No assumption index found. Run --validate-assumption first.")
    elif getattr(args, 'validate_assumption', None):
        yaml_path  = args.validate_assumption
        events_path = getattr(args, 'events', None)
        if not events_path:
            print("  [!] --validate-assumption requires --events <jsonl>")
        else:
            result = validate_assumption(yaml_path, events_path)
            print_assumption_result(result)
            idx = update_assumption_index(result)
            print(f"  [+] Index updated: {idx}")
            if getattr(args, 'scope_report', False):
                arts = load_artifact_jsonl(events_path)
                scope_path = generate_scope_report(result, arts)
                print(f"  [+] Scope report: {scope_path}")
    elif getattr(args, 'compare_assumptions', None):
        events_path = getattr(args, 'events', None)
        if not events_path:
            print("  [!] --compare-assumptions requires --events <jsonl>")
        else:
            print(f"\n  Artifact: {events_path}\n")
            for yaml_path in args.compare_assumptions:
                r = validate_assumption(yaml_path, events_path)
                print(f"  {r.assumption_id}:")
                print(f"    status:      {r.status.value}")
                print(f"    supported:   {r.supported_count}")
                print(f"    unsupported: {r.unsupported_count}")
                if r.out_of_scope_violations:
                    print(f"    oos:         {r.out_of_scope_violations}")
                print()
            print("  Conclusion:")
            for yaml_path in args.compare_assumptions:
                r = validate_assumption(yaml_path, events_path)
                for line in r.safe_conclusion.split(". "):
                    if line.strip():
                        print(f"    {line.strip()}.")
            print()
    elif getattr(args, 'assumption_index', False):
        from core.config import get_report_dir
        idx = get_report_dir() / "assumptions" / "index.md"
        if idx.exists():
            print(idx.read_text())
        else:
            print("  [!] No assumption index. Run --validate-assumption first.")
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

    elif args.coverage_history:
        from core.reports.evidence import load_timeline, get_campaign_runs
        from core.history.tracker import build_history, to_markdown, to_json
        from core.history.tracker import print_history_summary, generate_history_chart
        from pathlib import Path as _Path
        import os as _os

        timeline = load_timeline()
        all_runs = get_campaign_runs(timeline)

        # Optional campaign filter
        filter_name = getattr(args, "history_campaign", None)
        if filter_name:
            all_runs = [r for r in all_runs
                        if filter_name.lower() in r.get("campaign_name","").lower()]
            print(f"  [HISTORY]     Filtered to campaign: {filter_name}")

        if not all_runs:
            print("  [!] No runs found in timeline")
            sys.exit(1)

        report = build_history(all_runs)
        print_history_summary(report)

        out_dir = getattr(args, "out_dir", None) or "reports/history"
        _os.makedirs(out_dir, exist_ok=True)

        md_path   = _Path(out_dir) / "coverage_history.md"
        json_path = _Path(out_dir) / "coverage_history.json"
        chart_path = _Path(out_dir) / "coverage_history_trend.png"

        md_path.write_text(to_markdown(report), encoding="utf-8")
        json_path.write_text(to_json(report), encoding="utf-8")

        chart_ok = generate_history_chart(report, str(chart_path))

        print(f"  [MD]          {md_path}")
        print(f"  [JSON]        {json_path}")
        if chart_ok:
            print(f"  [CHART]       {chart_path}")
        print()

    elif args.mutate:
        import json as _json
        from pathlib import Path as _Path
        from core.mutation.engine import run_mutations, print_mutation_summary, MUTATION_TYPES
        import os as _os

        # Resolve events source
        events_path = getattr(args, "events", None)
        if not events_path:
            candidates = [
                "artifacts/demo/shenron_demo_run.jsonl",
                "artifacts/shenron_demo_run.jsonl",
            ]
            for c in candidates:
                if _Path(c).exists():
                    events_path = c
                    break
        if not events_path or not _Path(events_path).exists():
            print("  [!] No events file found. Run --demo first or pass --events PATH")
            sys.exit(1)

        records = []
        with open(events_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(_json.loads(line))
                    except _json.JSONDecodeError:
                        pass

        out_dir = getattr(args, "out_dir", None) or "artifacts/mutations"

        mutation_types_str = getattr(args, "mutation_types", None)
        if mutation_types_str:
            mut_types = [t.strip() for t in mutation_types_str.split(",")]
        else:
            mut_types = None  # run all safe types

        print()
        print(f"  [MUTATE]      {len(records)} records from {events_path}")
        print(f"  [OUTPUT]      {out_dir}/")
        print()

        results = run_mutations(records, mutation_types=mut_types,
                                out_dir=out_dir, verbose=True)
        print_mutation_summary(results)
        print(f"  Run --verify-safety on any mutation file to check safety contract:")
        print(f"    python3 shenron.py --verify-safety {out_dir}/mutation_field_drop.jsonl")
        print()

    elif args.export_format:
        import json as _json
        from pathlib import Path as _Path
        from core.formats.adapter import (
            write_ecs_array, write_ecs_bulk, write_splunk_hec, print_format_summary
        )
        import os as _os

        # Resolve events source
        events_path = getattr(args, "events", None)
        if not events_path:
            candidates = [
                "artifacts/demo/shenron_demo_run.jsonl",
                "artifacts/shenron_demo_run.jsonl",
            ]
            for c in candidates:
                if _Path(c).exists():
                    events_path = c
                    break
        if not events_path or not _Path(events_path).exists():
            print("  [!] No events file found. Run --demo first or pass --events PATH")
            sys.exit(1)

        records = []
        with open(events_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(_json.loads(line))
                    except _json.JSONDecodeError:
                        pass

        out_dir = getattr(args, "out_dir", None) or "artifacts/demo"
        _os.makedirs(out_dir, exist_ok=True)

        stem = _Path(events_path).stem
        out_paths = {}

        if args.export_format == "ecs":
            ecs_array_path = str(_Path(out_dir) / f"{stem}_ecs.json")
            ecs_bulk_path  = str(_Path(out_dir) / f"{stem}_ecs_bulk.ndjson")
            write_ecs_array(records, ecs_array_path)
            write_ecs_bulk(records,  ecs_bulk_path)
            out_paths["ecs_array"] = ecs_array_path
            out_paths["ecs_bulk"]  = ecs_bulk_path

        elif args.export_format == "splunk":
            splunk_path = str(_Path(out_dir) / f"{stem}_splunk_hec.json")
            write_splunk_hec(records, splunk_path)
            out_paths["splunk_hec"] = splunk_path

        print_format_summary(records, out_paths)

    elif args.assumption:
        import json as _json
        from pathlib import Path as _Path
        from core.assumption.parser import load_assumption
        from core.assumption.evaluator import evaluate
        from core.assumption.reporter import to_markdown, to_json, print_summary

        # Load assumption
        try:
            assumption = load_assumption(args.assumption)
        except (FileNotFoundError, ValueError) as e:
            print(f"  [!] {e}")
            sys.exit(1)

        # Load events
        events_path = args.events
        if not events_path:
            # Default to latest demo run
            candidates = [
                "artifacts/demo/shenron_demo_run.jsonl",
                "artifacts/shenron_demo_run.jsonl",
            ]
            for c in candidates:
                if _Path(c).exists():
                    events_path = c
                    break
        if not events_path or not _Path(events_path).exists():
            print(f"  [!] No events file found. Run --demo first or pass --events PATH")
            sys.exit(1)

        records = []
        with open(events_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(_json.loads(line))
                    except _json.JSONDecodeError:
                        pass

        result = evaluate(assumption, records)
        print_summary(result)

        # Write reports
        import os as _os
        out_dir = getattr(args, "out_dir", None) or "reports/assumptions"
        _os.makedirs(out_dir, exist_ok=True)

        safe_name = assumption.name.replace(" ", "_").replace("/", "_")
        md_path   = _Path(out_dir) / f"assumption_{safe_name}.md"
        json_path = _Path(out_dir) / f"assumption_{safe_name}.json"

        md_path.write_text(to_markdown(result), encoding="utf-8")
        json_path.write_text(to_json(result), encoding="utf-8")

        print(f"  [MD]          {md_path}")
        print(f"  [JSON]        {json_path}")
        print()

    elif args.release_demo:
        from scripts.release_demo import run_release_demo
        version = "v0.2.0"
        out_dir = args.out_dir if hasattr(args, "out_dir") and args.out_dir != "artifacts/demo" else f"release/shenron-{version}-demo"
        run_release_demo(out_dir, version)

    elif args.demo:
        import os
        out_dir = args.out_dir
        os.makedirs(out_dir, exist_ok=True)
        os.makedirs("docs/assets/shenron-demo", exist_ok=True)

        # Run demo generator
        import subprocess as _sp
        result = _sp.run(
            [sys.executable, "scripts/generate_demo_artifacts.py",
             "--out-dir", out_dir],
            capture_output=False
        )
        if result.returncode != 0:
            print("  [!] Demo generator failed")
            sys.exit(1)

        # Optionally generate charts
        if args.charts:
            jsonl_path = os.path.join(out_dir, "shenron_demo_run.jsonl")
            chart_result = _sp.run(
                [sys.executable, "scripts/generate_charts.py",
                 "--jsonl", jsonl_path,
                 "--out-dir", "docs/assets/shenron-demo"],
                capture_output=False
            )
            if chart_result.returncode != 0:
                print("  [!] Chart generation failed")

        # Auto verify-safety on generated JSONL
        import json
        from core.safety.contract import verify_records, print_verification
        jsonl_path = os.path.join(out_dir, "shenron_demo_run.jsonl")
        records = []
        with open(jsonl_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        result = verify_records(records)
        print_verification(result, source=jsonl_path)

        # Write safety verification markdown
        from core.safety.contract import verification_to_markdown
        safety_md = os.path.join(out_dir, "safety_verification.md")
        open(safety_md, "w").write(verification_to_markdown(result, source=jsonl_path))
        print(f"  [SAFETY MD]   {safety_md}")
        print()
        print(f"  [DEMO DONE]")
        print(f"  {out_dir}/shenron_demo_run.jsonl")
        print(f"  {out_dir}/shenron_demo_report.md")
        print(f"  {out_dir}/safety_verification.md")
        if args.charts:
            print(f"  docs/assets/shenron-demo/*.png")

    elif args.verify_safety is not None:
        import json
        from core.safety.contract import verify_records, print_verification, verification_to_markdown
        from pathlib import Path as _Path
        from core.config import artifact_log_path as _artifact_log_path

        if args.verify_safety == "latest":
            jsonl_path = str(_artifact_log_path())
        else:
            jsonl_path = args.verify_safety

        if not _Path(jsonl_path).exists():
            print(f"  [!] File not found: {jsonl_path}")
            sys.exit(1)

        records = []
        with open(jsonl_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        result = verify_records(records)
        print_verification(result, source=jsonl_path)

        # Write report
        reports_dir = _Path("reports")
        reports_dir.mkdir(exist_ok=True)
        out_md = reports_dir / f"safety_verification_{_Path(jsonl_path).stem}.md"
        out_md.write_text(verification_to_markdown(result, source=jsonl_path))
        print(f"  [REPORT]      {out_md}")

    elif args.compare:
        from core.validation.scorer import score_by_run_id
        from core.reports.evidence import load_timeline, get_campaign_runs
        from core.compare import compare_runs, print_compare, compare_report_to_markdown
        from pathlib import Path as _Path

        id_a, id_b = args.compare
        timeline = load_timeline()
        all_runs = get_campaign_runs(timeline)

        def _find_run(prefix, runs):
            matches = [r for r in runs if r.get("run_id", "").startswith(prefix)]
            return matches[-1] if matches else None

        run_a = _find_run(id_a, all_runs)
        run_b = _find_run(id_b, all_runs)
        if not run_a:
            print(f"  [!] Run A not found: {id_a}"); sys.exit(1)
        if not run_b:
            print(f"  [!] Run B not found: {id_b}"); sys.exit(1)

        cov_a = score_by_run_id(run_a["run_id"])
        cov_b = score_by_run_id(run_b["run_id"])
        if not cov_a or not cov_b:
            print("  [!] Could not score one or both runs"); sys.exit(1)

        result = compare_runs(
            cov_a, cov_b,
            mitre_a=run_a.get("all_mitre", []),
            mitre_b=run_b.get("all_mitre", []),
        )
        print_compare(result)
        reports_dir = _Path("reports")
        reports_dir.mkdir(exist_ok=True)
        out_path = reports_dir / f"compare_{id_a[:8]}_{id_b[:8]}.md"
        out_path.write_text(compare_report_to_markdown(result))
        print(f"  [REPORT]      {out_path}")

        # If --narrate is passed, generate analyst narrative
        if getattr(args, "narrate", False):
            from core.narration.engine import narrate, print_narrative_summary
            from pathlib import Path as _NPath

            narrative_md = narrate(result)
            print_narrative_summary(result)

            narr_path = _NPath("reports") / f"narrative_{id_a[:8]}_{id_b[:8]}.md"
            narr_path.write_text(narrative_md, encoding="utf-8")
            print(f"  [NARRATIVE]   {narr_path}")

        # If --navigator-out is also passed, export gap Navigator layer
        if args.navigator_out:
            from core.navigator import export_navigator_layer, print_navigator_summary
            mitre_a = set(result.mitre_a)
            mitre_b = set(result.mitre_b)
            gap_techniques = sorted(mitre_a - mitre_b)  # in A but not B = coverage gap
            if gap_techniques:
                export_navigator_layer(
                    techniques=gap_techniques,
                    output_path=args.navigator_out,
                    run_id=f"{id_a[:8]}_vs_{id_b[:8]}",
                    campaign_name=f"gap: {result.campaign_a} vs {result.campaign_b}",
                )
                print_navigator_summary(gap_techniques,
                                        f"{id_a[:8]}_vs_{id_b[:8]}",
                                        "coverage gap layer")
                print(f"  [GAP LAYER]   {args.navigator_out}")
                print(f"  [IMPORT]      https://mitre-attack.github.io/attack-navigator/")
            else:
                print(f"  [GAP LAYER]   no gap techniques — Run B covers all of Run A")

    elif args.navigator is not None:
        from core.reports.evidence import load_timeline, get_campaign_runs
        from core.navigator import export_navigator_layer, print_navigator_summary
        from pathlib import Path as _Path

        timeline = load_timeline()
        all_runs = get_campaign_runs(timeline)
        if not all_runs:
            print("  [!] No runs found in timeline"); sys.exit(1)

        if args.navigator == "latest":
            run = all_runs[-1]
        else:
            matches = [r for r in all_runs if r.get("run_id","").startswith(args.navigator)]
            if not matches:
                print(f"  [!] Run not found: {args.navigator}"); sys.exit(1)
            run = matches[-1]

        techniques = run.get("all_mitre", [])
        run_id     = run.get("run_id", "")
        campaign   = run.get("campaign_name", "unknown")
        if not techniques:
            print("  [!] No MITRE techniques for this run")
            print("  Tip: run a full bananaTREE campaign, not --run all --dry-run")
            sys.exit(1)

        reports_dir = _Path("reports")
        reports_dir.mkdir(exist_ok=True)
        out_path = args.navigator_out or str(
            reports_dir / f"navigator_{run_id[:8]}_{campaign}.json"
        )
        export_navigator_layer(techniques=techniques, output_path=out_path,
                               run_id=run_id, campaign_name=campaign)
        print_navigator_summary(techniques, run_id, campaign)
        print(f"  [OUTPUT]      {out_path}")
        print(f"  [IMPORT]      https://mitre-attack.github.io/attack-navigator/")
        print(f"                Open Navigator -> Open Existing Layer -> Upload File")
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
