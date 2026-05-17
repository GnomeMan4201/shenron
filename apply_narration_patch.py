#!/usr/bin/env python3
"""
apply_narration_patch.py
Wires --narrate flag into the --compare dispatch in shenron.py.
Run: python3 apply_narration_patch.py
"""
from pathlib import Path
import sys

src = Path("shenron.py").read_text()


# ── PATCH 1: Add --narrate to argparse ────────────────────────────────────────
OLD_ARG = '    p.add_argument("--export-format", type=str, metavar="FORMAT",'
NEW_ARG = '''    p.add_argument("--narrate",       action="store_true",
                help="generate analyst narrative from --compare output")
    p.add_argument("--export-format", type=str, metavar="FORMAT",'''

if OLD_ARG in src:
    src = src.replace(OLD_ARG, NEW_ARG, 1)
    print("PATCH 1 OK: --narrate added to argparse")
else:
    print("PATCH 1 FAILED — showing export-format context:")
    for i, line in enumerate(src.splitlines()):
        if "export.format" in line and "add_argument" in line:
            print(f"  {i+1}: {repr(line)}")
    sys.exit(1)


# ── PATCH 2: Wire --narrate into --compare dispatch ──────────────────────────
# After the existing compare dispatch writes the report, add narrate logic.
# Find the line that prints the report path and add after it.

OLD_COMPARE_TAIL = '''        print(f"  [REPORT]      {out_path}")

        # If --navigator-out is also passed'''

NEW_COMPARE_TAIL = '''        print(f"  [REPORT]      {out_path}")

        # If --narrate is passed, generate analyst narrative
        if getattr(args, "narrate", False):
            from core.narration.engine import narrate, print_narrative_summary
            from pathlib import Path as _NPath

            narrative_md = narrate(result)
            print_narrative_summary(result)

            narr_path = _NPath("reports") / f"narrative_{id_a[:8]}_{id_b[:8]}.md"
            narr_path.write_text(narrative_md, encoding="utf-8")
            print(f"  [NARRATIVE]   {narr_path}")

        # If --navigator-out is also passed'''

if OLD_COMPARE_TAIL in src:
    src = src.replace(OLD_COMPARE_TAIL, NEW_COMPARE_TAIL, 1)
    print("PATCH 2 OK: --narrate dispatch wired into --compare")
else:
    print("PATCH 2 FAILED — showing compare tail context:")
    for i, line in enumerate(src.splitlines()):
        if "navigator-out is also" in line or "REPORT" in line and "out_path" in line:
            print(f"  {i+1}: {repr(line)}")
    sys.exit(1)

Path("shenron.py").write_text(src)
print()
print("Done. Verify:")
print('  python3 -c "import ast; ast.parse(open(\'shenron.py\').read()); print(\'syntax OK\')"')
print()
print("Test:")
print("  python3 shenron.py --compare 1972a90e 32491bae --narrate")
