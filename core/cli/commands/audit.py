# core/cli/commands/audit.py
import sys


def register(subparsers):
    p = subparsers.add_parser(
        "audit",
        help="produce a complete defensible evidence bundle",
        description="Run schema validation, Sigma evaluation, assumption validation, and export in one command.",
    )
    sub = p.add_subparsers(dest="audit_cmd", metavar="COMMAND")

    bundle = sub.add_parser("bundle", help="produce a complete audit evidence bundle")
    bundle.add_argument("--events",      required=True,  metavar="JSONL",
                        help="path to SHENRON JSONL artifact")
    bundle.add_argument("--rules",       default="sigma/rules", metavar="DIR",
                        help="Sigma rules directory (default: sigma/rules)")
    bundle.add_argument("--assumptions", default="assumptions/examples", metavar="DIR",
                        help="assumption YAMLs directory (default: assumptions/examples)")
    bundle.add_argument("--out",         default="reports/audit_bundle", metavar="DIR",
                        help="output directory (default: reports/audit_bundle)")
    bundle.add_argument("--quiet",       action="store_true",
                        help="suppress progress output")

    p.set_defaults(func=run)
    return p


def run(args):
    if args.audit_cmd == "bundle":
        _run_bundle(args)
    else:
        print("Usage: shenron audit bundle --events <jsonl> [--rules DIR] [--assumptions DIR] [--out DIR]")
        sys.exit(1)


def _run_bundle(args):
    from core.audit.bundle import run_audit_bundle

    result = run_audit_bundle(
        events_path     = args.events,
        rules_dir       = args.rules,
        assumptions_dir = args.assumptions,
        out_dir         = args.out,
        verbose         = not args.quiet,
    )

    if not result.get("ok"):
        sys.exit(1)
