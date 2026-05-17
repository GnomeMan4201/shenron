#!/usr/bin/env python3
"""
apply_assumption_patch.py
Wires --assumption into shenron.py argparse and dispatch.
Run: python3 apply_assumption_patch.py
"""
from pathlib import Path
import sys

src = Path("shenron.py").read_text()


# ── PATCH 1: argparse ─────────────────────────────────────────────────────────
OLD_ARG = '    p.add_argument("--release-demo",  action="store_true",'
NEW_ARG = '''    p.add_argument("--assumption",    type=str, metavar="YAML_PATH",
                help="audit a coverage assumption file against JSONL events")
    p.add_argument("--events",        type=str, default=None, metavar="JSONL_PATH",
                help="JSONL events file for --assumption (default: latest demo run)")
    p.add_argument("--release-demo",  action="store_true",'''

if OLD_ARG in src:
    src = src.replace(OLD_ARG, NEW_ARG, 1)
    print("PATCH 1 OK: --assumption and --events args added")
else:
    print("PATCH 1 FAILED")
    sys.exit(1)


# ── PATCH 2: dispatch ─────────────────────────────────────────────────────────
OLD_DISPATCH = "    elif args.release_demo:"
NEW_DISPATCH = '''    elif args.assumption:
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

    elif args.release_demo:'''

if OLD_DISPATCH in src:
    src = src.replace(OLD_DISPATCH, NEW_DISPATCH, 1)
    print("PATCH 2 OK: --assumption dispatch added")
else:
    print("PATCH 2 FAILED")
    sys.exit(1)

Path("shenron.py").write_text(src)
print()
print("Done. Verify with:")
print('  python3 -c "import ast; ast.parse(open(\'shenron.py\').read()); print(\'syntax OK\')"')
