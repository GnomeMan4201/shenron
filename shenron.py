#!/usr/bin/env python3
"""
SHENRON — synthetic adversarial telemetry and detection validation pipeline.
Quick start:
    python3 shenron.py quickstart
Full CLI:
    python3 shenron.py --help
Legacy flags (--run, --validate-sigma-dir, etc.) are still supported.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.mitre.drift import check_drift, print_drift_report, drift_report_to_markdown

_SUBCOMMANDS = frozenset({
    "quickstart", "run", "sigma", "assumption",
    "report", "history", "artifact", "schema", "export", "audit", "doctor", "health",
    "campaign", "compare-scenarios", "validate",
})

def main():
    from core.cli import print_banner, build_parser
    print_banner()
    if "--check-mitre-drift" in sys.argv:
        from pathlib import Path as _Path
        offline = "--drift-offline" in sys.argv
        cache = None
        if "--drift-cache" in sys.argv:
            idx = sys.argv.index("--drift-cache")
            cache = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else None
        print()
        if offline and not cache:
            print("  [!] --drift-offline requires --drift-cache <path>")
            sys.exit(1)
        print("  [DRIFT] Offline mode..." if offline else "  [DRIFT] Fetching ATT&CK STIX bundle from mitre/cti ...")
        report = check_drift(manifest_path="shenron_manifest.json", offline=offline, cached_bundle_path=cache)
        print_drift_report(report, verbose=True)
        _Path("reports").mkdir(exist_ok=True)
        out_md = _Path("reports") / "mitre_drift_report.md"
        out_md.write_text(drift_report_to_markdown(report), encoding="utf-8")
        print(f"  [REPORT] {out_md}")
        sys.exit(2 if report.stale else 0)
    first = sys.argv[1] if len(sys.argv) > 1 else None

    # Bare invocation, --help, or unrecognized first arg → show new parser help
    if first is None or first in ("-h", "--help") or (first not in _SUBCOMMANDS and not first.startswith("-")):
        from core.cli import build_parser
        build_parser().print_help()
        print()
        sys.exit(0)

    if first in _SUBCOMMANDS:
        p = build_parser()
        p.add_argument("--check-mitre-drift", action="store_true", help="check manifest technique IDs against current ATT&CK")
        p.add_argument("--drift-offline", action="store_true", help="use cached bundle, no network")
        p.add_argument("--drift-cache", type=str, default=None, metavar="PATH", help="path to cache ATT&CK STIX bundle")
        args = p.parse_args()
        if getattr(args, "check_mitre_drift", False):
            from pathlib import Path as _Path
            offline = getattr(args, "drift_offline", False)
            cache = getattr(args, "drift_cache", None)
            print()
            if offline and not cache:
                print("  [!] --drift-offline requires --drift-cache <path>")
                sys.exit(1)
            print("  [DRIFT] Offline mode..." if offline else "  [DRIFT] Fetching ATT&CK STIX bundle from mitre/cti ...")
            report = check_drift(manifest_path="shenron_manifest.json", offline=offline, cached_bundle_path=cache)
            print_drift_report(report, verbose=True)
            _Path("reports").mkdir(exist_ok=True)
            out_md = _Path("reports") / "mitre_drift_report.md"
            out_md.write_text(drift_report_to_markdown(report), encoding="utf-8")
            print(f"  [REPORT] {out_md}")
            if report.stale:
                sys.exit(2)
        elif hasattr(args, "func"):
            args.func(args)
        else:
            p.print_help()
        return
    from core.cli.commands.legacy import _legacy_dispatch
    _legacy_dispatch()

if __name__ == "__main__":
    main()
