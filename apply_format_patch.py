#!/usr/bin/env python3
"""
apply_format_patch.py
Wires --format into shenron.py argparse and dispatch.
Run: python3 apply_format_patch.py
"""
from pathlib import Path
import sys

src = Path("shenron.py").read_text()


# ── PATCH 1: argparse ─────────────────────────────────────────────────────────
OLD_ARG = '    p.add_argument("--assumption",    type=str, metavar="YAML_PATH",'
NEW_ARG = '''    p.add_argument("--format",        type=str, metavar="FORMAT",
                choices=["ecs", "splunk"],
                help="export events in ECS or Splunk HEC format")
    p.add_argument("--assumption",    type=str, metavar="YAML_PATH",'''

if OLD_ARG in src:
    src = src.replace(OLD_ARG, NEW_ARG, 1)
    print("PATCH 1 OK: --format arg added")
else:
    print("PATCH 1 FAILED")
    for i, line in enumerate(src.splitlines()):
        if "--assumption" in line and "add_argument" in line:
            print(f"  {i+1}: {repr(line)}")
    sys.exit(1)


# ── PATCH 2: dispatch ─────────────────────────────────────────────────────────
OLD_DISPATCH = "    elif args.assumption:"
NEW_DISPATCH = '''    elif args.format:
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

        if args.format == "ecs":
            ecs_array_path = str(_Path(out_dir) / f"{stem}_ecs.json")
            ecs_bulk_path  = str(_Path(out_dir) / f"{stem}_ecs_bulk.ndjson")
            write_ecs_array(records, ecs_array_path)
            write_ecs_bulk(records,  ecs_bulk_path)
            out_paths["ecs_array"] = ecs_array_path
            out_paths["ecs_bulk"]  = ecs_bulk_path

        elif args.format == "splunk":
            splunk_path = str(_Path(out_dir) / f"{stem}_splunk_hec.json")
            write_splunk_hec(records, splunk_path)
            out_paths["splunk_hec"] = splunk_path

        print_format_summary(records, out_paths)

    elif args.assumption:'''

if OLD_DISPATCH in src:
    src = src.replace(OLD_DISPATCH, NEW_DISPATCH, 1)
    print("PATCH 2 OK: --format dispatch added")
else:
    print("PATCH 2 FAILED")
    for i, line in enumerate(src.splitlines()):
        if "args.assumption" in line:
            print(f"  {i+1}: {repr(line)}")
    sys.exit(1)

Path("shenron.py").write_text(src)
print()
print("Done. Verify:")
print('  python3 -c "import ast; ast.parse(open(\'shenron.py\').read()); print(\'syntax OK\')"')
