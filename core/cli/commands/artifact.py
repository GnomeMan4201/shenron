"""core/cli/commands/artifact.py"""
import sys


def register(subparsers):
    p = subparsers.add_parser("artifact", help="artifact operations")
    sub = p.add_subparsers(dest="artifact_cmd", metavar="SUBCMD", required=True)

    # artifact verify <jsonl>
    ver = sub.add_parser("verify", help="verify safety contract on a JSONL artifact")
    ver.add_argument(
        "jsonl",
        type=str,
        metavar="JSONL_PATH",
        help="path to JSONL file, or 'latest'",
    )
    ver.set_defaults(func=_handle_verify)


def _handle_verify(args):
    import json
    from pathlib import Path
    from core.safety.contract import (
        verify_records, print_verification, verification_to_markdown,
    )
    from core.config import artifact_log_path

    jsonl_path = str(artifact_log_path()) if args.jsonl == "latest" else args.jsonl

    if not Path(jsonl_path).exists():
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

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    out_md = reports_dir / f"safety_verification_{Path(jsonl_path).stem}.md"
    out_md.write_text(verification_to_markdown(result, source=jsonl_path))
    print(f"  [REPORT]      {out_md}")
