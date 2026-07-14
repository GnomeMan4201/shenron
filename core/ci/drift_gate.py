import sys, json, argparse, traceback
from datetime import datetime, timezone
from pathlib import Path

EXIT_PASS  = 0
EXIT_ERROR = 1
EXIT_DRIFT = 2


def _build_gate_result(verdict, exit_code, drift_report=None,
                       error_message="", manifest_path="shenron_manifest.json",
                       report_path=""):
    result = {
        "gate": "shenron_drift_gate",
        "version": "0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "manifest_path": manifest_path,
        "verdict": verdict,
        "exit_code": exit_code,
        "error": error_message,
        "report_path": report_path,
    }
    if drift_report:
        result["drift_summary"] = {
            "attack_version": drift_report.attack_version,
            "checked_at": drift_report.checked_at,
            "total_layers": drift_report.total_layers,
            "total_techniques": drift_report.total_techniques,
            "ok_count": len(drift_report.ok),
            "stale_count": len(drift_report.stale),
            "renamed_count": len(drift_report.renamed),
            "unknown_count": len(drift_report.unknown),
            "drift_verdict": drift_report.verdict,
            "has_issues": drift_report.has_issues,
            "stale_techniques": [
                {"layer": r.layer_name, "technique": r.technique_id, "note": r.note}
                for r in drift_report.stale
            ],
            "renamed_techniques": [
                {"layer": r.layer_name, "old_id": r.technique_id,
                  "new_id": r.revoked_by or "", "name": r.current_name or ""}
                for r in drift_report.renamed
            ],
            "layers_with_issues": list(drift_report.layer_staleness.keys()),
        }
    return result


def _write_gate_result(result, report_dir, quiet=False):
    out_dir = Path(report_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "drift_gate_result.json"
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    if not quiet:
        print(f"  [DRIFT-GATE] Result: {out_path}")
    return str(out_path)


def _print_summary(result, quiet=False):
    if quiet:
        return
    v = result["verdict"]
    ds = result.get("drift_summary", {})
    mk = {"PASS": "[PASS]", "DRIFT": "[DRIFT]", "ERROR": "[ERROR]"}
    print()
    print("  SHENRON MITRE ATT&CK DRIFT GATE")
    print(f"  Verdict    : {mk.get(v, v)} {v}")
    print(f"  Exit code  : {result['exit_code']}")
    print(f"  Manifest   : {result['manifest_path']}")
    if ds:
        print(f"  ATT&CK ver : {ds.get('attack_version', 'unknown')}")
        print(f"  Techniques : {ds.get('total_techniques', 0)} checked")
        print(f"  OK/Stale/Renamed: {ds.get('ok_count',0)}/{ds.get('stale_count',0)}/{ds.get('renamed_count',0)}")
        for s in ds.get("stale_techniques", []):
            print(f"  [STALE]   [{s['layer']}] {s['technique']}")
        for r in ds.get("renamed_techniques", []):
            new = r['new_id'] or "no successor"
            print(f"  [RENAMED] [{r['layer']}] {r['old_id']} -> {new}")
    if result.get("error"):
        print(f"  ERROR: {result['error']}")
    print()
    msgs = {"PASS": "All techniques current.",
             "DRIFT": "Action required: update stale/renamed IDs.",
             "ERROR": "Gate could not complete."}
    print(f"  {msgs.get(v, v)}")
    print()


def run_drift_gate(manifest_path="shenron_manifest.json", report_dir="reports/ci",
                   offline=False, cache_path=None, fail_on_renamed=False, quiet=False):
    """Run the MITRE ATT&CK drift gate. Returns exit code (0/1/2)."""
    if not Path(manifest_path).exists():
        r = _build_gate_result("ERROR", EXIT_ERROR,
                                error_message=f"Manifest not found: {manifest_path}",
                                manifest_path=manifest_path)
        _write_gate_result(r, report_dir, quiet)
        _print_summary(r, quiet)
        return EXIT_ERROR
    try:
        from core.mitre.drift import check_drift, drift_report_to_markdown
        if not quiet:
            mode = "offline" if offline else "online"
            print(f"\n  [DRIFT-GATE] Running ATT&CK drift check ({mode})...")
        dr = check_drift(manifest_path=manifest_path, offline=offline,
                         cached_bundle_path=cache_path)
        if len(dr.stale) > 0 or (fail_on_renamed and len(dr.renamed) > 0):
            verdict, code = "DRIFT", EXIT_DRIFT
        elif len(dr.unknown) > 0 and not dr.stale and not dr.renamed:
            verdict, code = "ERROR", EXIT_ERROR
            if not quiet:
                print("  [DRIFT-GATE] WARNING: Could not reach ATT&CK bundle")
        else:
            verdict, code = "PASS", EXIT_PASS
        result = _build_gate_result(verdict, code, dr, manifest_path=manifest_path)
        rp = _write_gate_result(result, report_dir, quiet)
        result["report_path"] = rp
        md = Path(report_dir) / "drift_gate_report.md"
        md.write_text(drift_report_to_markdown(dr), encoding="utf-8")
        if not quiet:
            print(f"  [DRIFT-GATE] MD report: {md}")
        _print_summary(result, quiet)
        return code
    except Exception as e:
        r = _build_gate_result("ERROR", EXIT_ERROR,
                                error_message=f"{type(e).__name__}: {e}",
                                manifest_path=manifest_path)
        _write_gate_result(r, report_dir, quiet)
        if not quiet:
            traceback.print_exc()
        _print_summary(r, quiet)
        return EXIT_ERROR


def main(argv=None):
    p = argparse.ArgumentParser(prog="shenron-drift-gate",
        description="SHENRON MITRE ATT&CK drift CI gate")
    p.add_argument("--manifest", default="shenron_manifest.json")
    p.add_argument("--report-dir", default="reports/ci")
    p.add_argument("--offline", action="store_true")
    p.add_argument("--cache", default=None, metavar="PATH")
    p.add_argument("--fail-on-renamed", action="store_true")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)
    if args.offline and not args.cache:
        print("  ERROR: --offline requires --cache <path>")
        return EXIT_ERROR
    return run_drift_gate(args.manifest, args.report_dir, args.offline,
                          args.cache, args.fail_on_renamed, args.quiet)


if __name__ == "__main__":
    sys.exit(main())
