#!/usr/bin/env python3
"""
SHENRON shenron.py PATCH SCRIPT
Run: python3 apply_patch.py
Applies all v0.2.0 additions to shenron.py in one shot.
"""
from pathlib import Path
import sys

src = Path("shenron.py").read_text()
original = src


# ── PATCH 1: Add --demo, --verify-safety to argparse ─────────────────────────
# Insert after the --navigator-out argument

OLD_ARGS = '''    p.add_argument("--navigator-out", type=str, default=None, metavar="PATH",
                help="output path for Navigator JSON")'''

NEW_ARGS = '''    p.add_argument("--navigator-out", type=str, default=None, metavar="PATH",
                help="output path for Navigator JSON")
    p.add_argument("--demo",          action="store_true",
                help="run safe 40-event demo pipeline (JSONL + report + charts)")
    p.add_argument("--charts",        action="store_true",
                help="generate charts from demo JSONL (use with --demo)")
    p.add_argument("--verify-safety", type=str, nargs="?", const="latest",
                metavar="JSONL_PATH",
                help="verify safety contract on a JSONL file or 'latest' artifact")
    p.add_argument("--out-dir",       type=str, default="artifacts/demo",
                metavar="DIR",
                help="output directory for --demo (default: artifacts/demo)")'''

if OLD_ARGS in src:
    src = src.replace(OLD_ARGS, NEW_ARGS, 1)
    print("PATCH 1 OK: --demo, --charts, --verify-safety, --out-dir added to argparse")
else:
    print("PATCH 1 FAILED: --navigator-out block not found")
    print("Showing navigator-out context:")
    for i, line in enumerate(src.splitlines()):
        if "navigator-out" in line or "navigator_out" in line:
            print(f"  {i+1}: {repr(line)}")
    sys.exit(1)


# ── PATCH 2: Add dispatch for --demo, --verify-safety ────────────────────────
# Insert before the elif args.compare block

OLD_DISPATCH = "    elif args.compare:"

NEW_DISPATCH = '''    elif args.demo:
        import os
        out_dir = args.out_dir
        os.makedirs(out_dir, exist_ok=True)
        os.makedirs("docs/assets/shenron-demo", exist_ok=True)

        # Run demo generator
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "generate_demo_artifacts",
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "scripts/generate_demo_artifacts.py")
        )
        mod = importlib.util.module_from_spec(spec)

        class _Args:
            out_dir = out_dir

        mod_args = _Args()
        # Run directly
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
        Path(safety_md).write_text(verification_to_markdown(result, source=jsonl_path))
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

    elif args.compare:'''

if OLD_DISPATCH in src:
    src = src.replace(OLD_DISPATCH, NEW_DISPATCH, 1)
    print("PATCH 2 OK: --demo and --verify-safety dispatch added")
else:
    print("PATCH 2 FAILED: 'elif args.compare:' not found")
    for i, line in enumerate(src.splitlines()):
        if "args.compare" in line:
            print(f"  {i+1}: {repr(line)}")
    sys.exit(1)


# ── PATCH 3: Enhance compare output with richer markdown report ───────────────
# The compare_report_to_markdown in core/compare.py already writes a report.
# We enhance the dispatch to also export a Navigator layer when --navigator-out
# is passed alongside --compare.

OLD_COMPARE_END = '''        print(f"  [REPORT]      {out_path}")

    elif args.navigator is not None:'''

NEW_COMPARE_END = '''        print(f"  [REPORT]      {out_path}")

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

    elif args.navigator is not None:'''

if OLD_COMPARE_END in src:
    src = src.replace(OLD_COMPARE_END, NEW_COMPARE_END, 1)
    print("PATCH 3 OK: Navigator gap export wired into --compare")
else:
    print("PATCH 3 SKIPPED: compare end block not found (may already be patched)")
    for i, line in enumerate(src.splitlines()):
        if "GAP LAYER" in line or "navigator_out" in line:
            print(f"  {i+1}: {repr(line)}")


# ── Write result ──────────────────────────────────────────────────────────────
Path("shenron.py").write_text(src)
print()
print("All patches applied. Run:")
print("  python3 -c \"import ast; ast.parse(open('shenron.py').read()); print('syntax OK')\"")
