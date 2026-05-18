# core/cli/commands/schema.py
import sys


def register(subparsers):
    p = subparsers.add_parser(
        "schema",
        help="JSON schema validation",
        description="Validate SHENRON artifacts against JSON schemas (stdlib only).",
    )
    sub = p.add_subparsers(dest="schema_cmd", metavar="<command>")
    val = sub.add_parser("validate", help="Validate a JSONL events file")
    val.add_argument("--events", required=True, metavar="JSONL",
                     help="Path to SHENRON JSONL artifact")
    val.add_argument("--quiet", action="store_true",
                     help="Only print failures, suppress summary on success")
    p.set_defaults(func=run)
    return p


def run(args):
    if args.schema_cmd == "validate":
        _run_validate(args)
    else:
        print("Usage: shenron schema validate --events <jsonl>")
        sys.exit(1)


def _run_validate(args):
    from core.schema.validator import validate_events_file
    result = validate_events_file(args.events)
    if not args.quiet:
        print(f"SHENRON schema validation — {args.events}")
        print(f"  events parsed : {result['events']}")
    if result.get("error"):
        print(f"  ERROR: {result['error']}")
        sys.exit(1)
    if result["failures"]:
        print(f"  FAIL — {len(result['failures'])} violation(s):")
        for f in result["failures"]:
            print(f"    {f}")
        sys.exit(1)
    else:
        if not args.quiet:
            print(f"  OK — all {result['events']} events pass schema validation")
