"""core/cli/commands/quickstart.py"""


def register(subparsers):
    p = subparsers.add_parser(
        "quickstart",
        help="run complete demo pipeline and generate evidence bundle",
    )
    p.add_argument(
        "--out",
        dest="out_dir",
        type=str,
        default=None,
        metavar="DIR",
        help="output directory (default: reports/demo)",
    )
    p.set_defaults(func=handle)


def handle(args):
    from core.quickstart import run_quickstart
    run_quickstart(out_dir=getattr(args, "out_dir", None))
