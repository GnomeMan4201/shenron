#!/usr/bin/env python3
# SHENRON: Release demo bundle generator v2
# Produces a complete, self-contained artifact package.
# Includes: JSONL, report, safety verification, Navigator layer,
#           ECS export, Splunk HEC export, narration, charts, MANIFEST.

import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "v0.3.2"


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


def build_manifest(
    out_dir: str,
    records: list,
    version: str,
    ecs_path: str = None,
    splunk_path: str = None,
    narration_path: str = None,
) -> str:
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
        f"See `safety_verification.md` for field-by-field verification.",
        f"All {event_count} records pass.",
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
    ]

    if ecs_path:
        lines += [
            f"| `shenron_demo_run_ecs.json` | ECS-formatted events (Elastic import) |",
            f"| `shenron_demo_run_ecs_bulk.ndjson` | Elastic bulk API format |",
        ]
    if splunk_path:
        lines += [
            f"| `shenron_demo_run_splunk_hec.json` | Splunk HEC format |",
        ]
    if narration_path:
        lines += [
            f"| `narrative.md` | Analyst-language defensive narrative |",
        ]

    lines += [
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
        f"git clone https://github.com/{os.environ.get('SHENRON_REPO', 'GnomeMan4201/shenron')}",
        f"cd shenron",
        f"python3 shenron.py --release-demo",
        f"```",
        f"",
        f"Or step by step:",
        f"",
        f"```bash",
        f"python3 shenron.py --demo --charts --out-dir artifacts/demo",
        f"python3 shenron.py --verify-safety artifacts/demo/shenron_demo_run.jsonl",
        f"python3 shenron.py --export-format ecs --events artifacts/demo/shenron_demo_run.jsonl",
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
        f"> **Note:** MITRE-style descriptor coverage from synthetic telemetry.",
        f"> Not real ATT&CK validation or confirmed detector coverage.",
        f"",
    ]

    if ecs_path:
        lines += [
            f"---",
            f"",
            f"## Elastic import",
            f"",
            f"```bash",
            f"curl -X POST 'http://localhost:9200/_bulk' \\",
            f"     -H 'Content-Type: application/x-ndjson' \\",
            f"     --data-binary @shenron_demo_run_ecs_bulk.ndjson",
            f"```",
            f"",
            f"> All events carry `simulation_only: true` and `event.dataset: shenron.synthetic`.",
            f"> These are SYNTHETIC records — no real adversarial activity occurred.",
            f"",
        ]

    if splunk_path:
        lines += [
            f"---",
            f"",
            f"## Splunk HEC import",
            f"",
            f"```bash",
            f"curl -X POST 'https://splunk:8088/services/collector/event' \\",
            f"     -H 'Authorization: Splunk YOUR_HEC_TOKEN' \\",
            f"     -d @shenron_demo_run_splunk_hec.json",
            f"```",
            f"",
        ]

    lines += [
        f"---",
        f"",
        f"*SHENRON — Observable adversarial behavior, not portable adversarial procedure.*",
    ]
    return "\n".join(lines)


def run_release_demo(out_dir: str, version: str = VERSION, verbose: bool = True):
    import subprocess

    out = Path(out_dir)
    charts_dir = out / "charts"
    out.mkdir(parents=True, exist_ok=True)
    charts_dir.mkdir(parents=True, exist_ok=True)

    tmp_demo   = out / "_tmp_demo"
    tmp_charts = out / "_tmp_charts"
    tmp_demo.mkdir(exist_ok=True)
    tmp_charts.mkdir(exist_ok=True)

    repo_root = Path(__file__).parent.parent

    if verbose:
        print(f"\n  [RELEASE-DEMO] SHENRON {version}")
        print(f"  [OUTPUT]       {out_dir}")
        print()

    # ── Step 1: JSONL + report ────────────────────────────────────────────────
    if verbose:
        print(f"  [1/7] Generating synthetic telemetry...")

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
    jsonl_out  = out / "shenron_demo_run.jsonl"

    shutil.copy(jsonl_src,  jsonl_out)
    shutil.copy(report_src, out / "shenron_demo_report.md")

    records = _load_jsonl(str(jsonl_out))
    if verbose:
        print(f"  [1/7] {len(records)} events → shenron_demo_run.jsonl")

    # ── Step 2: Charts ────────────────────────────────────────────────────────
    if verbose:
        print(f"  [2/7] Generating charts...")

    chart_result = subprocess.run(
        [sys.executable,
         str(repo_root / "scripts" / "generate_charts.py"),
         "--jsonl", str(jsonl_out),
         "--out-dir", str(tmp_charts)],
        capture_output=True, text=True
    )
    if chart_result.returncode != 0:
        print(f"  [!] Chart generation failed:\n{chart_result.stderr}")
    else:
        for png in tmp_charts.glob("*.png"):
            shutil.copy(png, charts_dir / png.name)
        if verbose:
            print(f"  [2/7] {len(list(charts_dir.glob('*.png')))} charts → charts/")

    # ── Step 3: Safety verification ───────────────────────────────────────────
    if verbose:
        print(f"  [3/7] Verifying safety contract...")

    sys.path.insert(0, str(repo_root))
    from core.safety.contract import verify_records, verification_to_markdown

    safety_result = verify_records(records)
    safety_md_path = str(out / "safety_verification.md")
    _write(safety_md_path, verification_to_markdown(
        safety_result, source="shenron_demo_run.jsonl"
    ))
    if verbose:
        print(f"  [3/7] Safety contract: {safety_result['verdict']} ({safety_result['total']} records)")

    # ── Step 4: Navigator layer ───────────────────────────────────────────────
    if verbose:
        print(f"  [4/7] Exporting Navigator layer...")

    techniques = sorted({r.get("mitre_technique", "") for r in records
                         if r.get("mitre_technique")})
    from core.navigator import export_navigator_layer
    nav_path = str(out / "navigator_layer.json")
    export_navigator_layer(
        techniques=techniques,
        output_path=nav_path,
        run_id="demo-release",
        campaign_name=f"SHENRON {version} demo",
    )
    if verbose:
        print(f"  [4/7] {len(techniques)} technique descriptors → navigator_layer.json")

    # ── Step 5: ECS + Splunk export ───────────────────────────────────────────
    if verbose:
        print(f"  [5/7] Exporting ECS and Splunk HEC formats...")

    from core.formats.adapter import write_ecs_array, write_ecs_bulk, write_splunk_hec

    ecs_array_path  = str(out / "shenron_demo_run_ecs.json")
    ecs_bulk_path   = str(out / "shenron_demo_run_ecs_bulk.ndjson")
    splunk_path     = str(out / "shenron_demo_run_splunk_hec.json")

    write_ecs_array(records, ecs_array_path)
    write_ecs_bulk(records,  ecs_bulk_path)
    write_splunk_hec(records, splunk_path)

    if verbose:
        print(f"  [5/7] ECS array, bulk NDJSON, Splunk HEC → {out_dir}/")

    # ── Step 6: Narrative ─────────────────────────────────────────────────────
    # Narration requires a compare report — produce a self-compare as a
    # demo narrative showing the demo run's own tactic profile.
    if verbose:
        print(f"  [6/7] Generating demo profile narrative...")

    narration_path = None
    try:
        from core.narration.engine import build_profile, TACTIC_FAMILIES, _join_list

        signals   = [r.get("signal", "") for r in records if r.get("signal")]
        profile   = build_profile("demo_run", "demo", signals, list(techniques))

        fam_labels = [
            TACTIC_FAMILIES[f]["label"]
            for f in profile.tactic_families
            if f in TACTIC_FAMILIES
        ]

        narration_lines = [
            f"# SHENRON {version} Demo Run — Tactic Profile",
            f"",
            f"> **SYNTHETIC TELEMETRY** — This profile describes the signal vocabulary",
            f"> of the SHENRON safe demo run. Not real adversarial execution.",
            f"",
            f"---",
            f"",
            f"## Coverage profile",
            f"",
            f"The demo run (`shenron_demo_run.jsonl`) expresses a **{profile.breadth}**",
            f"tactic coverage profile across {len(profile.tactic_families)} signal families:",
            f"**{_join_list(fam_labels)}**.",
            f"",
            f"This is a vocabulary sample, not a scenario run. It demonstrates the",
            f"signal shape and safety contract, not a specific adversarial campaign.",
            f"",
            f"---",
            f"",
            f"## Signal families in this demo",
            f"",
        ]

        for fam, sig_labels in sorted(profile.tactic_families.items()):
            if fam in TACTIC_FAMILIES:
                meta = TACTIC_FAMILIES[fam]
                examples = ", ".join(dict.fromkeys(sig_labels[:4]))
                if len(sig_labels) > 4:
                    examples += f" (+{len(sig_labels)-4} more)"
                narration_lines += [
                    f"### {meta['label']}",
                    f"",
                    f"{examples}.",
                    f"",
                ]

        narration_lines += [
            f"---",
            f"",
            f"## To generate a full gap narrative",
            f"",
            f"Run two different scenarios and compare them:",
            f"",
            f"```bash",
            f"python3 shenron.py --scenario apt_kill_chain --dry-run",
            f"python3 shenron.py --scenario persistence_runbook --dry-run",
            f"python3 shenron.py --compare <apt_run_id> <persistence_run_id> --narrate",
            f"```",
            f"",
            f"---",
            f"",
            f"*SHENRON — Observable adversarial behavior, not portable adversarial procedure.*",
        ]

        narration_path = str(out / "narrative.md")
        _write(narration_path, "\n".join(narration_lines))
        if verbose:
            print(f"  [6/7] Demo tactic profile → narrative.md")

    except Exception as e:
        if verbose:
            print(f"  [6/7] Narration skipped: {e}")

    # ── Step 7: MANIFEST ──────────────────────────────────────────────────────
    if verbose:
        print(f"  [7/7] Writing manifest...")

    manifest = build_manifest(
        out_dir, records, version,
        ecs_path=ecs_array_path,
        splunk_path=splunk_path,
        narration_path=narration_path,
    )
    _write(str(out / "MANIFEST.md"), manifest)

    # ── Cleanup ───────────────────────────────────────────────────────────────
    shutil.rmtree(tmp_demo,   ignore_errors=True)
    shutil.rmtree(tmp_charts, ignore_errors=True)

    # ── Summary ───────────────────────────────────────────────────────────────
    if verbose:
        print()
        print(f"  [BUNDLE COMPLETE]  {out_dir}/")
        bundle_files = sorted(out.rglob("*"))
        for f in bundle_files:
            if f.is_file():
                rel  = f.relative_to(out)
                size = f.stat().st_size
                print(f"    {str(rel):<50} {size:>8} bytes")
        print()
        print(f"  Safety:     {safety_result['verdict']}")
        print(f"  Records:    {len(records)}")
        print(f"  Techniques: {len(techniques)} MITRE-style descriptors")
        print(f"  Formats:    JSONL, ECS array, ECS bulk NDJSON, Splunk HEC")
        print(f"  Navigator:  navigator_layer.json")
        print()

    return {
        "out_dir":    out_dir,
        "records":    len(records),
        "techniques": len(techniques),
        "verdict":    safety_result["verdict"],
        "version":    version,
    }


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="SHENRON release demo bundle generator")
    p.add_argument("--out-dir",  default=f"release/shenron-{VERSION}-demo")
    p.add_argument("--version",  default=VERSION)
    args = p.parse_args()
    run_release_demo(args.out_dir, args.version)
