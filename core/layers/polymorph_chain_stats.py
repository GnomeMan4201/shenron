#!/usr/bin/env python3
# SHENRON: Polymorph Chain Stats — real-time operational dashboard
import os, json
from datetime import datetime
from pathlib import Path

MANIFEST_PATH = Path(__file__).parent.parent.parent / "shenron_manifest.json"
LOG_PATH = Path(os.path.expanduser("~/SHENRON/logs/mutation_history.json"))

def load_manifest():
    if not MANIFEST_PATH.exists():
        return None
    with open(MANIFEST_PATH) as f:
        return json.load(f)

def load_log():
    if not LOG_PATH.exists():
        return []
    with open(LOG_PATH) as f:
        return json.load(f)

def build_stats():
    manifest = load_manifest()
    log = load_log()

    if not manifest:
        print("[!] No manifest found. Run manifest builder first.")
        return

    # Index log by layer name
    log_by_layer = {}
    for entry in log:
        name = entry.get("payload", "")
        log_by_layer.setdefault(name, []).append(entry)

    # Compute per-layer stats
    layer_stats = []
    for layer in manifest["layers"]:
        name = layer["name"]
        entries = log_by_layer.get(name, [])
        total = len(entries)
        ok = sum(1 for e in entries if e.get("mutation") == "loaded")
        fails = total - ok
        last_seen = entries[-1]["timestamp"][:19] if entries else "never"
        layer_stats.append({
            "name": name,
            "category": layer["category"],
            "variants": layer["variant_count"],
            "loads": ok,
            "fails": fails,
            "last_seen": last_seen,
            "description": layer.get("description", "")[:50]
        })

    # Summary
    summary = manifest.get("summary", {})
    total_variants = summary.get("total_variants", 0)
    total_canonical = summary.get("total_canonical", 0)
    total_loads = sum(s["loads"] for s in layer_stats)
    total_fails = sum(s["fails"] for s in layer_stats)
    by_cat = summary.get("by_category", {})

    print()
    print("  SHENRON // polymorph chain stats")
    print(f"  generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("  " + "=" * 75)
    print(f"  canonical layers : {total_canonical}")
    print(f"  total variants   : {total_variants}")
    print(f"  total loads      : {total_loads}")
    print(f"  total failures   : {total_fails}")
    print()

    print("  BY CATEGORY:")
    for cat, count in by_cat.items():
        variant_total = sum(s["variants"] for s in layer_stats if s["category"] == cat)
        print(f"    {cat:<14} {count:2} layers   {variant_total:4} variants")

    print()
    print(f"  {'LAYER':<40} {'CAT':<12} {'VAR':>4}  {'LOADS':>5}  {'FAILS':>5}  LAST SEEN")
    print(f"  {'-'*40} {'-'*12} {'-'*4}  {'-'*5}  {'-'*5}  {'-'*19}")

    for s in sorted(layer_stats, key=lambda x: x["category"]):
        fail_flag = " !" if s["fails"] > 0 else ""
        print(f"  {s['name']:<40} {s['category']:<12} {s['variants']:>4}  {s['loads']:>5}  {s['fails']:>5}  {s['last_seen']}{fail_flag}")

    print()

    # Dead weight — never loaded, no variants
    dead = [s for s in layer_stats if s["loads"] == 0 and s["variants"] == 0]
    if dead:
        print("  DEAD WEIGHT (no variants, never loaded):")
        for s in dead:
            print(f"    {s['name']}")
        print()

def main():
    build_stats()

if __name__ == "__main__":
    main()
