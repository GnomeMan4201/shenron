"""core/cli/commands/history.py"""


def register(subparsers):
    p = subparsers.add_parser("history", help="validation history")
    # default: show full history list
    p.set_defaults(func=_handle_list)

    sub = p.add_subparsers(dest="history_cmd", metavar="SUBCMD")

    # history compare <id>
    cmp = sub.add_parser("compare",
                         help="show history entries for a specific assumption/rule ID")
    cmp.add_argument("id", type=str, metavar="ID")
    cmp.set_defaults(func=_handle_compare)


def _handle_list(args):
    from core.validation.history import load_history, print_history

    entries = load_history()
    print_history(entries)


def _handle_compare(args):
    from core.validation.history import compare_history, print_comparison

    entries = compare_history(args.id)
    print_comparison(args.id, entries)
