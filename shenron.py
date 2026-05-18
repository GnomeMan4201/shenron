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

_SUBCOMMANDS = frozenset({
    "quickstart", "run", "sigma", "assumption",
    "report", "history", "artifact", "schema", "export", "audit",
})


def main():
    from core.cli import print_banner, build_parser
    print_banner()
    if len(sys.argv) > 1 and sys.argv[1] in _SUBCOMMANDS:
        p = build_parser()
        args = p.parse_args()
        if hasattr(args, "func"):
            args.func(args)
        else:
            p.print_help()
        return
    from core.cli.commands.legacy import _legacy_dispatch
    _legacy_dispatch()


if __name__ == "__main__":
    main()
