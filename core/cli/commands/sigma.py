"""core/cli/commands/sigma.py"""
import sys


def register(subparsers):
    p = subparsers.add_parser("sigma", help="Sigma rule evaluation")
    sub = p.add_subparsers(dest="sigma_cmd", metavar="SUBCMD", required=True)

    # sigma validate <rule> --events <jsonl>
    val = sub.add_parser("validate", help="evaluate a single Sigma rule against events")
    val.add_argument("rule", type=str, metavar="RULE_YML", help="path to Sigma rule YAML")
    val.add_argument("--events", type=str, required=True, metavar="JSONL",
                     help="JSONL events file")
    val.add_argument("--match-mode", type=str, default="tolerant",
                     choices=["tolerant", "strict", "explain"],
                     help="matching mode: tolerant (default), strict (exact only), explain (show match reasoning)")
    val.set_defaults(func=_handle_validate)

    # sigma validate-dir <dir> --events <jsonl>
    vdir = sub.add_parser("validate-dir", help="evaluate all Sigma rules in a directory")
    vdir.add_argument("dir", type=str, metavar="DIR",
                      help="directory containing .yml rule files")
    vdir.add_argument("--events", type=str, required=True, metavar="JSONL",
                      help="JSONL events file")
    vdir.add_argument("--match-mode", type=str, default="tolerant",
                     choices=["tolerant", "strict", "explain"],
                     help="matching mode: tolerant (default), strict (exact only), explain (show match reasoning)")
    vdir.set_defaults(func=_handle_validate_dir)


def _handle_validate(args):
    from core.sigma.evaluator import evaluate_sigma_rule, print_result as print_sigma_result
    from core.validation.history import record_validation

    mode = getattr(args, "match_mode", "tolerant")
    result = evaluate_sigma_rule(args.rule, args.events, match_mode=mode)
    print_sigma_result(result, match_mode=mode)
    record_validation(result, "sigma")


def _handle_validate_dir(args):
    from pathlib import Path
    from core.sigma.evaluator import evaluate_sigma_rule

    rules = sorted(Path(args.dir).rglob("*.yml"))
    if not rules:
        print(f"  [!] No .yml files in {args.dir}")
        sys.exit(1)

    print(f"\n  Evaluating {len(rules)} rule(s)\n")
    counts: dict = {}
    mode = getattr(args, "match_mode", "tolerant")
    for rp in rules:
        r = evaluate_sigma_rule(str(rp), args.events, match_mode=mode)
        v = r.verdict.value
        counts[v] = counts.get(v, 0) + 1
        mark = {
            "TRIGGERED": "+", "PARTIAL": "~",
            "NOT_TRIGGERED": "-", "UNSUPPORTED": "?",
        }.get(v, " ")
        print(f"  [{mark}] {v:15s}  {r.rule_title}")
    print(f"\n  Summary: {counts}\n")
