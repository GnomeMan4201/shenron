#!/usr/bin/env python3
"""
apply_abc_patch.py
Wires --coverage-history and --mutate into shenron.py.
Also updates --release-demo version string.
Run: python3 apply_abc_patch.py
"""
from pathlib import Path
import sys

src = Path("shenron.py").read_text()


# ── PATCH 1: Add --coverage-history and --mutate to argparse ─────────────────
OLD_ARG = '    p.add_argument("--narrate",       action="store_true",'
NEW_ARG = '''    p.add_argument("--coverage-history", action="store_true",
                help="build coverage trend report from all timeline runs")
    p.add_argument("--history-campaign", type=str, default=None, metavar="NAME",
                help="filter --coverage-history to a specific campaign name")
    p.add_argument("--mutate",           action="store_true",
                help="generate safe telemetry mutation variants from --events")
    p.add_argument("--mutation-types",   type=str, default=None, metavar="TYPES",
                help="comma-separated mutation types (default: all safe types)")
    p.add_argument("--narrate",       action="store_true",'''

if OLD_ARG in src:
    src = src.replace(OLD_ARG, NEW_ARG, 1)
    print("PATCH 1 OK: --coverage-history and --mutate added to argparse")
else:
    print("PATCH 1 FAILED")
    sys.exit(1)


# ── PATCH 2: Add --coverage-history dispatch ──────────────────────────────────
OLD_DISPATCH = "    elif args.export_format:"
NEW_DISPATCH = '''    elif args.coverage_history:
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

    elif args.export_format:'''

if OLD_DISPATCH in src:
    src = src.replace(OLD_DISPATCH, NEW_DISPATCH, 1)
    print("PATCH 2 OK: --coverage-history and --mutate dispatch added")
else:
    print("PATCH 2 FAILED")
    for i, line in enumerate(src.splitlines()):
        if "export_format" in line and "elif" in line:
            print(f"  {i+1}: {repr(line)}")
    sys.exit(1)

Path("shenron.py").write_text(src)
print()
print("Done. Verify:")
print('  python3 -c "import ast; ast.parse(open(\'shenron.py\').read()); print(\'syntax OK\')"')
