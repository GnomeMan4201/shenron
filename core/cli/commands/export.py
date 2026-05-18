# core/cli/commands/export.py
import sys
import json
from pathlib import Path


def register(subparsers):
    p = subparsers.add_parser(
        "export",
        help="export SHENRON artifacts to ECS or Splunk HEC format",
        description="Convert SHENRON JSONL telemetry to Elastic ECS or Splunk HEC format.",
    )
    sub = p.add_subparsers(dest="export_fmt", metavar="FORMAT")

    ecs = sub.add_parser("ecs", help="export to Elastic Common Schema (ECS)")
    ecs.add_argument("--events", required=True, metavar="JSONL")
    ecs.add_argument("--out", required=True, metavar="PATH",
                     help="output path (.json for array, .ndjson for bulk)")
    ecs.add_argument("--bulk", action="store_true",
                     help="write Elastic bulk API format (ndjson)")

    hec = sub.add_parser("hec", help="export to Splunk HEC format")
    hec.add_argument("--events", required=True, metavar="JSONL")
    hec.add_argument("--out", required=True, metavar="PATH")

    p.set_defaults(func=run)
    return p


def run(args):
    if args.export_fmt == "ecs":
        _run_ecs(args)
    elif args.export_fmt == "hec":
        _run_hec(args)
    else:
        print("Usage: shenron export ecs|hec --events <jsonl> --out <path>")
        sys.exit(1)


def _load_events(path):
    events = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events


def _run_ecs(args):
    from core.formats.adapter import write_ecs_bulk, write_ecs_array
    events = _load_events(args.events)
    if args.bulk:
        write_ecs_bulk(events, args.out)
    else:
        write_ecs_array(events, args.out)
    print(f"  [ECS]    {len(events)} events -> {args.out}")
    print(f"  [SAFE]   simulation_only: true on all records")


def _run_hec(args):
    from core.formats.adapter import write_splunk_hec
    events = _load_events(args.events)
    write_splunk_hec(events, args.out)
    print(f"  [HEC]    {len(events)} events -> {args.out}")
    print(f"  [SAFE]   simulation_only: true on all records")
