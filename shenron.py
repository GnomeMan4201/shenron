import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.engine import payload_registry
from core.engine.layer_loader import load_all, discover_canonical, get_by_category, CATEGORIES, _TYPE_TO_CAT

def cmd_list(args):
    canonical = discover_canonical()
    print()
    print("  " + "LAYER".ljust(45) + "CATEGORY".ljust(15) + "FILE")
    print("  " + "-"*44 + " " + "-"*14 + " " + "-"*30)
    for lt, p in sorted(canonical.items()):
        cat = _TYPE_TO_CAT.get(lt, "unknown")
        print("  " + lt.ljust(45) + cat.ljust(15) + p.name)
    print()
    print("  " + str(len(canonical)) + " canonical layers across " + str(len(CATEGORIES)) + " categories")
    print()

def cmd_categories(args):
    print()
    print("  " + "CATEGORY".ljust(15) + "LAYERS")
    print("  " + "-"*14 + " " + "-"*50)
    for cat, layers in CATEGORIES.items():
        print("  " + cat.ljust(15) + ", ".join(layers))
    print()

def cmd_run(args):
    target_cats = list(CATEGORIES.keys()) if args.categories == "all" else [c.strip() for c in args.categories.split(",")]
    bad = [c for c in target_cats if c not in CATEGORIES]
    if bad:
        print("[!] Unknown: " + ", ".join(bad))
        print("    Valid: " + ", ".join(CATEGORIES.keys()))
        sys.exit(1)
    print("[*] Loading: " + ", ".join(target_cats))
    load_results = load_all(categories=target_cats)
    loaded = [lt for lt, ok in load_results.items() if ok]
    failed = [lt for lt, ok in load_results.items() if not ok]
    print("[+] Loaded: " + str(len(loaded)) + "  Failed: " + str(len(failed)))
    if failed:
        print("[!] Failed: " + ", ".join(failed))
    registered = payload_registry.list_registered()
    print("[+] Registered: " + str(len(registered)))
    if args.dry_run:
        print()
        print("[~] DRY RUN:")
        for cat in target_cats:
            for lt in get_by_category(cat):
                status = "ok" if lt in registered else "not registered"
                print("    [" + cat + "] " + lt + " " + status)
        print()
        return
    print()
    for cat in target_cats:
        print("  -- " + cat.upper() + " --")
        for lt in get_by_category(cat):
            if lt in registered:
                print("  [>] " + lt)
                result = payload_registry.run(lt)
                print("  [" + ("ok" if result else "fail") + "] " + lt)
            else:
                print("  [~] " + lt + " (skipping)")
        print()

def cmd_layer(args):
    canonical = discover_canonical()
    lt = args.layer
    if lt not in canonical:
        print("[!] Not found: " + lt + " -- try --list")
        sys.exit(1)
    from core.engine.layer_loader import load_layer
    ok, err = load_layer(lt, canonical[lt])
    if not ok:
        print("[!] " + str(err))
        sys.exit(1)
    registered = payload_registry.list_registered()
    if lt in registered:
        if args.dry_run:
            print("[~] DRY RUN: " + lt)
        else:
            print("[>] " + lt)
            payload_registry.run(lt)
    else:
        print("[~] No @register_payload found for " + lt)

def main():
    print()
    print("  SHENRON // polymorphic framework // LANimals collective // gnomeman4201")
    print()
    p = argparse.ArgumentParser(prog="shenron")
    p.add_argument("--list", action="store_true")
    p.add_argument("--cats", action="store_true")
    p.add_argument("--categories", type=str)
    p.add_argument("--layer", type=str)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()
    if args.list: cmd_list(args)
    elif args.cats: cmd_categories(args)
    elif args.categories: cmd_run(args)
    elif args.layer: cmd_layer(args)
    else: p.print_help()

if __name__ == "__main__":
    main()
