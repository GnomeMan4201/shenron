"""core/cli/commands/run.py"""
import sys


def register(subparsers):
    p = subparsers.add_parser(
        "run",
        help="run a layer, category, or 'all'",
    )
    p.add_argument(
        "target",
        type=str,
        help="layer name, category name, or 'all'",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="validate without executing",
    )
    p.set_defaults(func=handle)


def _run_layer(lt, canonical, dry_run=False):
    from core.engine import payload_registry
    from core.engine.layer_loader import load_layer

    ok, err = load_layer(lt, canonical[lt])
    if not ok:
        return False, f"load failed: {err}"
    registered = payload_registry.list_registered()
    if lt not in registered:
        return False, "no @register_payload entry point"
    if dry_run:
        return True, "dry-run ok"
    result = payload_registry.run(lt)
    return (True, "executed") if result else (False, "exec failed")


def handle(args):
    from core.engine import payload_registry
    from core.engine.layer_loader import discover_canonical, get_by_category, CATEGORIES

    canonical = discover_canonical()
    target = args.target
    dry_run = getattr(args, "dry_run", False)

    if target == "all":
        targets = sorted(canonical.keys())
    elif target in CATEGORIES:
        targets = [lt for lt in get_by_category(target) if lt in canonical]
    elif target in canonical:
        targets = [target]
    else:
        print(f"\n  [!] Unknown target: '{target}'")
        print(f"  Valid: a layer name, a category name, or 'all'")
        print(f"  Categories: {', '.join(CATEGORIES.keys())}")
        print(f"  Layers: shenron --list\n")
        sys.exit(1)

    mode = "DRY RUN" if dry_run else "EXECUTE"
    print(f"\n  [{mode}] {len(targets)} layer(s)\n")
    print(f"  {'LAYER':<45} {'STATUS'}")
    print(f"  {'-'*44} {'-'*20}")

    ok_count = fail_count = 0
    for lt in targets:
        payload_registry.clear()
        ok, status = _run_layer(lt, canonical, dry_run)
        marker = "✓" if ok else "✗"
        print(f"  [{marker}] {lt:<43} {status}")
        if ok:
            ok_count += 1
        else:
            fail_count += 1

    print()
    print(f"  {ok_count} ok  |  {fail_count} failed")
    print()
