"""core/cli/commands/assumption.py"""


def register(subparsers):
    p = subparsers.add_parser("assumption", help="assumption validation and indexing")
    sub = p.add_subparsers(dest="assumption_cmd", metavar="SUBCMD", required=True)

    # assumption validate <yaml> --events <jsonl> [--scope-report]
    val = sub.add_parser("validate", help="validate a coverage assumption against events")
    val.add_argument("yaml", type=str, metavar="YAML_PATH")
    val.add_argument("--events", type=str, required=True, metavar="ARTIFACT")
    val.add_argument("--scope-report", action="store_true",
                     help="generate scope report after validation")
    val.set_defaults(func=_handle_validate)

    # assumption compare <yaml>... --events <jsonl>
    cmp = sub.add_parser("compare",
                         help="compare multiple assumption YAMLs against same events")
    cmp.add_argument("yamls", nargs="+", metavar="YAML_PATH")
    cmp.add_argument("--events", type=str, required=True, metavar="JSONL")
    cmp.set_defaults(func=_handle_compare)

    # assumption diff <yaml> <yaml> --events <jsonl>
    dff = sub.add_parser('diff', help='diff two assumptions against the same artifact')
    dff.add_argument('yamls', nargs=2, metavar='YAML_PATH')
    dff.add_argument('--events', type=str, required=True, metavar='JSONL')
    dff.set_defaults(func=_handle_diff)
    # assumption index
    idx = sub.add_parser("index", help="show assumption audit index")
    idx.set_defaults(func=_handle_index)


def _handle_validate(args):
    from core.assumptions.validator import (
        validate_assumption, print_result as print_assumption_result,
    )
    from core.assumptions.scope import generate_scope_report, update_assumption_index
    from core.assumptions.loader import load_artifacts as load_artifact_jsonl
    from core.validation.history import record_validation

    result = validate_assumption(args.yaml, args.events)
    print_assumption_result(result)
    record_validation(result, "assumption")
    idx = update_assumption_index(result)
    print(f"  [+] Index updated: {idx}")
    if getattr(args, "scope_report", False):
        arts = load_artifact_jsonl(args.events)
        scope_path = generate_scope_report(result, arts)
        print(f"  [+] Scope report: {scope_path}")


def _handle_compare(args):
    from core.assumptions.validator import validate_assumption

    print(f"\n  Artifact: {args.events}\n")
    results = []
    for yaml_path in args.yamls:
        r = validate_assumption(yaml_path, args.events)
        results.append(r)
        print(f"  {r.assumption_id}:")
        print(f"    status:      {r.status.value}")
        print(f"    supported:   {r.supported_count}")
        print(f"    unsupported: {r.unsupported_count}")
        if r.out_of_scope_violations:
            print(f"    oos:         {r.out_of_scope_violations}")
        print()

    print("  Conclusion:")
    for r in results:
        for line in r.safe_conclusion.split(". "):
            if line.strip():
                print(f"    {line.strip()}.")
    print()


def _handle_index(args):
    from core.config import get_report_dir

    idx = get_report_dir() / "assumptions" / "index.md"
    if idx.exists():
        print(idx.read_text())
    else:
        print("  [!] No assumption index found. Run 'assumption validate' first.")


def _handle_diff(args):
    from core.assumptions.validator import validate_assumption

    ya, yb = args.yamls
    ra = validate_assumption(ya, args.events)
    rb = validate_assumption(yb, args.events)

    print()
    print(f'  SHENRON assumption diff')
    print(f'  artifact : {args.events}')
    print()
    print(f'  {"ASSUMPTION":<40} {"STATUS":<22} SUP  UNSUP  OOS')
    print(f'  {"-"*39} {"-"*21} {"---"} {"-----"} {"---"}')
    for r in (ra, rb):
        oos = len(r.out_of_scope_violations)
        print(f'  {r.assumption_id:<40} {r.status.value:<22} {r.supported_count:<4} {r.unsupported_count:<6} {oos}')
    print()

    # Claim-level diff
    claim_ids_a = {cr.claim.id: cr for cr in ra.claim_results}
    claim_ids_b = {cr.claim.id: cr for cr in rb.claim_results}
    all_ids = sorted(set(claim_ids_a) | set(claim_ids_b))

    if all_ids:
        print(f'  {"CLAIM":<40} {"A STATUS":<22} {"B STATUS"}')
        print(f'  {"-"*39} {"-"*21} {"-"*21}')
        for cid in all_ids:
            sa = claim_ids_a[cid].status.value if cid in claim_ids_a else "(absent)"
            sb = claim_ids_b[cid].status.value if cid in claim_ids_b else "(absent)"
            marker = "<<" if sa != sb else "  "
            print(f'  {cid:<40} {sa:<22} {sb}  {marker}')
        print()

    print(f'  Interpretation:')
    print(f'    A: {ra.safe_conclusion}')
    print(f'    B: {rb.safe_conclusion}')
    print()
