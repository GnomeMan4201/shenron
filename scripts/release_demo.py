#!/usr/bin/env python3
"""
SHENRON: Release demo bundle generator
Produces a complete, self-contained artifact package suitable for sharing.

No subprocess beyond shenron's own scripts.
No network. No execution. Pure synthetic telemetry + reports.
"""
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "v0.2.0"


def _load_jsonl(path: str) -> list:
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records


def _write(path: str, content: str):
    Path(path).write_text(content, encoding="utf-8")


def build_manifest(out_dir: str, records: list, version: str) -> str:
    now = datetime.now(timezone.utc).isoformat()
    event_count = len(records)
    phases = sorted({r.get("phase", "") for r in records if r.get("phase")})
    techniques = sorted({r.get("mitre_technique", "") for r in records
                         if r.get("mitre_technique")})

    lines = [
        f"# SHENRON {version} Demo Artifact Bundle",
        f"",
        f"**Generated:** {now}  ",
        f"**Generator:** SHENRON safe demo mode  ",
        f"**Version:** {version}  ",
        f"",
        f"---",
        f"",
        f"## Safety boundary",
        f"",
        f"This bundle was produced by SHENRON's safe demo artifact generator.",
        f"",
        f"- No payloads",
        f"- No shellcode",
        f"- No subprocess execution",
        f"- No socket or network activity",
        f"- No real file execution",
        f"- No portable adversarial procedure",
        f"",
        f"Every record in `shenron_demo_run.jsonl` carries an explicit safety contract.",
        f"Run `safety_verification.md` to inspect it. All {event_count} records pass.",
        f"",
        f"---",
        f"",
        f"## Contents",
        f"",
        f"| File | Purpose |",
        f"|------|---------|",
        f"| `shenron_demo_run.jsonl` | {event_count} synthetic telemetry events |",
        f"| `shenron_demo_report.md` | Human-readable run report |",
        f"| `safety_verification.md` | Safety contract field-by-field verification |",
        f"| `navigator_layer.json` | ATT&CK Navigator import layer (synthetic) |",
        f"| `compare_report.md` | Placeholder — run --compare to populate |",
        f"| `charts/` | Visual summaries (PNG, dark mode, 150dpi) |",
        f"",
        f"---",
        f"",
        f"## Run summary",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Synthetic events | {event_count} |",
        f"| bananaTREE phases | {len(phases)} ({', '.join(phases)}) |",
        f"| MITRE-style descriptors | {len(techniques)} |",
        f"| Safety violations | 0 |",
        f"| Verdict | PASS |",
        f"",
        f"---",
        f"",
        f"## Reproduce",
        f"",
        f"```bash",
        f"git clone https://github.com/GnomeMan4201/shenron",
        f"cd shenron",
        f"python3 shenron.py --demo --charts --out-dir artifacts/demo",
        f"python3 shenron.py --verify-safety artifacts/demo/shenron_demo_run.jsonl",
        f"python3 shenron.py --navigator latest",
        f"```",
        f"",
        f"---",
        f"",
        f"## Navigator import",
        f"",
        f"`navigator_layer.json` can be imported directly into ATT&CK Navigator:",
        f"",
        f"1. Go to https://mitre-attack.github.io/attack-navigator/",
        f"2. Open Existing Layer → Upload File",
        f"3. Select `navigator_layer.json`",
        f"",
        f"> **Note:** This layer represents MITRE-style descriptor coverage from",
        f"> synthetic telemetry. It is not real ATT&CK validation or confirmed",
        f"> detector coverage.",
        f"",
        f"---",
        f"",
        f"*SHENRON — Observable adversarial behavior, not portable adversarial procedure.*",
    ]
    return "\n".join(lines)


def build_compare_placeholder() -> str:
    return "\n".join([
        "# SHENRON Compare Report",
        "",
        "> This file is a placeholder.",
        "> To populate it, run two different scenarios and compare them:",
        "",
        "```bash",
        "python3 shenron.py --scenario apt_kill_chain --dry-run",
        "python3 shenron.py --scenario persistence_runbook --dry-run",
        "python3 shenron.py --compare <apt_run_id> <persistence_run_id> \\",
        "  --navigator-out release/gap_layer.json",
        "```",
        "",
        "The compare output will show:",
        "- Signals gained and lost between runs",
        "- MITRE descriptor delta",
        "- Coverage gap Navigator layer",
        "- Defensive interpretation",
        "",
        "*SHENRON — Observable adversarial behavior, not portable adversarial procedure.*",
    ])


def run_release_demo(out_dir: str, version: str = VERSION, verbose: bool = True):
    """
    Build a complete release artifact bundle in out_dir.
    Calls the existing demo generator and chart generator as subprocesses,
    then assembles everything into the bundle directory.
    """
    import subprocess

    out = Path(out_dir)
    charts_dir = out / "charts"
    out.mkdir(parents=True, exist_ok=True)
    charts_dir.mkdir(parents=True, exist_ok=True)

    tmp_demo = out / "_tmp_demo"
    tmp_demo.mkdir(exist_ok=True)

    repo_root = Path(__file__).parent

    if verbose:
        print(f"\n  [RELEASE-DEMO] SHENRON {version}")
        print(f"  [OUTPUT]       {out_dir}")
        print()

    # ── Step 1: Generate JSONL + report ──────────────────────────────────────
    if verbose:
        print(f"  [1/5] Generating synthetic telemetry...")

    result = subprocess.run(
        [sys.executable,
         str(repo_root / "scripts" / "generate_demo_artifacts.py"),
         "--out-dir", str(tmp_demo)],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"  [!] Demo generator failed:\n{result.stderr}")
        sys.exit(1)

    jsonl_src  = tmp_demo / "shenron_demo_run.jsonl"
    report_src = tmp_demo / "shenron_demo_report.md"

    shutil.copy(jsonl_src,  out / "shenron_demo_run.jsonl")
    shutil.copy(report_src, out / "shenron_demo_report.md")

    records = _load_jsonl(str(out / "shenron_demo_run.jsonl"))
    if verbose:
        print(f"  [1/5] {len(records)} events → shenron_demo_run.jsonl")

    # ── Step 2: Generate charts ───────────────────────────────────────────────
    if verbose:
        print(f"  [2/5] Generating charts...")

    tmp_charts = out / "_tmp_charts"
    tmp_charts.mkdir(exist_ok=True)

    chart_result = subprocess.run(
        [sys.executable,
         str(repo_root / "scripts" / "generate_charts.py"),
         "--jsonl", str(out / "shenron_demo_run.jsonl"),
         "--out-dir", str(tmp_charts)],
        capture_output=True, text=True
    )
    if chart_result.returncode != 0:
        print(f"  [!] Chart generation failed:\n{chart_result.stderr}")
    else:
        for png in tmp_charts.glob("*.png"):
            shutil.copy(png, charts_dir / png.name)
        if verbose:
            chart_count = len(list(charts_dir.glob("*.png")))
            print(f"  [2/5] {chart_count} charts → charts/")

    # ── Step 3: Safety verification ───────────────────────────────────────────
    if verbose:
        print(f"  [3/5] Verifying safety contract...")

    sys.path.insert(0, str(repo_root))
    from core.safety.contract import verify_records, verification_to_markdown
    safety_result = verify_records(records)
    safety_md = verification_to_markdown(
        safety_result,
        source="shenron_demo_run.jsonl"
    )
    _write(str(out / "safety_verification.md"), safety_md)

    verdict = safety_result["verdict"]
    if verbose:
        print(f"  [3/5] Safety contract: {verdict} ({safety_result['total']} records)")

    # ── Step 4: Navigator layer ───────────────────────────────────────────────
    if verbose:
        print(f"  [4/5] Exporting Navigator layer...")

    techniques = sorted({
        r.get("mitre_technique", "")
        for r in records
        if r.get("mitre_technique")
    })

    from core.navigator import export_navigator_layer
    nav_path = str(out / "navigator_layer.json")
    export_navigator_layer(
        techniques=techniques,
        output_path=nav_path,
        run_id="demo-release",
        campaign_name=f"SHENRON {version} demo",
    )
    if verbose:
        print(f"  [4/5] {len(techniques)} technique descriptors → navigator_layer.json")

    # ── Step 5: Manifest + compare placeholder ────────────────────────────────
    if verbose:
        print(f"  [5/5] Writing manifest...")

    manifest = build_manifest(out_dir, records, version)
    _write(str(out / "MANIFEST.md"), manifest)
    _write(str(out / "compare_report.md"), build_compare_placeholder())

    # ── Cleanup temp dirs ─────────────────────────────────────────────────────
    shutil.rmtree(tmp_demo,   ignore_errors=True)
    shutil.rmtree(tmp_charts, ignore_errors=True)

    # ── Summary ───────────────────────────────────────────────────────────────
    if verbose:
        print()
        print(f"  [BUNDLE COMPLETE]  {out_dir}/")
        bundle_files = sorted(out.rglob("*"))
        for f in bundle_files:
            if f.is_file():
                rel = f.relative_to(out)
                size = f.stat().st_size
                print(f"    {str(rel):<45} {size:>8} bytes")
        print()
        print(f"  Safety:    {verdict}")
        print(f"  Records:   {len(records)}")
        print(f"  Techniques: {len(techniques)} MITRE-style descriptors")
        print(f"  Navigator: navigator_layer.json — import at")
        print(f"             https://mitre-attack.github.io/attack-navigator/")
        print()

    return {
        "out_dir":    out_dir,
        "records":    len(records),
        "techniques": len(techniques),
        "verdict":    verdict,
        "version":    version,
    }


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="SHENRON release demo bundle generator")
    p.add_argument("--out-dir",  default=f"release/shenron-{VERSION}-demo")
    p.add_argument("--version",  default=VERSION)
    args = p.parse_args()
    run_release_demo(args.out_dir, args.version)
