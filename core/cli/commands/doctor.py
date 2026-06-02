"""core/cli/commands/doctor.py — field emission coverage diagnostics"""


KEY_FIELDS = {
    "behavior_class",
    "detection_opportunities",
    "mitre_techniques",
    "layer",
    "phase",
}

SIGMA_FIELDS = {
    "behavior_class",
    "command_sim",
    "deploy_path_sim",
    "detection_opportunities",
    "file_path_sim",
    "full_seed_path_sim",
    "layer",
    "mitre_techniques",
    "phase",
    "port_sim",
    "sandbox_path_sim",
    "simulation_only",
    "synthetic_path",
    "target_hostname",
    "target_ip_sim",
    "target_path_sim",
    "target_pid_sim",
    "token_type_sim",
}


def register(subparsers):
    p = subparsers.add_parser(
        "doctor",
        help="check field emission coverage across layers in the artifact log",
    )
    p.add_argument(
        "--events", type=str, default=None, metavar="JSONL",
        help="artifact log to inspect (default: ~/SHENRON/logs/simulation_artifacts.jsonl)",
    )
    p.add_argument(
        "--full", action="store_true",
        help="show all sigma-reachable fields, not just key fields",
    )
    p.add_argument(
        "--layer", type=str, default=None, metavar="NAME",
        help="inspect a single layer only",
    )
    p.add_argument(
        "--json", action="store_true",
        help="output results as JSON (for CI integration)",
    )
    p.set_defaults(func=_handle_doctor)


def _handle_doctor(args):
    import json
    from pathlib import Path
    from core.config import artifact_log_path

    # Resolve events path
    events_path = getattr(args, "events", None)
    if not events_path:
        events_path = str(artifact_log_path())
    p = Path(events_path)
    if not p.exists():
        print(f"\n  [!] Artifact log not found: {events_path}")
        print(f"  Run: python3 shenron.py run all\n")
        return

    check_fields = SIGMA_FIELDS if getattr(args, "full", False) else KEY_FIELDS
    filter_layer = getattr(args, "layer", None)

    # Build per-layer field inventory
    layer_fields: dict[str, set] = {}
    layer_counts: dict[str, int] = {}
    with open(p) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            layer = r.get("layer", "unknown")
            if filter_layer and layer != filter_layer:
                continue
            if layer not in layer_fields:
                layer_fields[layer] = set()
                layer_counts[layer] = 0
            layer_counts[layer] += 1
            layer_fields[layer].update(
                k for k, v in r.items()
                if v not in (None, [], "", False)
            )

    if not layer_fields:
        if filter_layer:
            print(f"\n  [!] No records found for layer: {filter_layer}\n")
        else:
            print(f"\n  [!] No records in: {events_path}\n")
        return

    # Compute results
    ok_layers = []
    gap_layers = []
    for layer, fields in sorted(layer_fields.items()):
        missing = check_fields - fields
        if missing:
            gap_layers.append((layer, sorted(missing), layer_counts[layer]))
        else:
            ok_layers.append((layer, layer_counts[layer]))

    total = len(layer_fields)
    n_ok  = len(ok_layers)
    n_gap = len(gap_layers)
    mode  = "full sigma" if getattr(args, "full", False) else "key"

    print()
    print(f"  SHENRON Doctor — field emission coverage ({mode} fields)")
    print(f"  Source  : {events_path}")
    print(f"  Layers  : {total}  |  OK: {n_ok}  |  Gaps: {n_gap}")
    print()

    if gap_layers:
        print(f"  {'LAYER':<45} {'EVENTS':>6}  MISSING FIELDS")
        print(f"  {'-'*44} {'------':>6}  {'-'*30}")
        for layer, missing, count in gap_layers:
            print(f"  {layer:<45} {count:>6}  {', '.join(missing)}")
        print()

    if ok_layers and (filter_layer or not gap_layers):
        print(f"  {'LAYER':<45} {'EVENTS':>6}  STATUS")
        print(f"  {'-'*44} {'------':>6}  {'-'*10}")
        for layer, count in ok_layers:
            print(f"  {layer:<45} {count:>6}  OK")
        print()

    # Summary verdict
    if n_gap == 0:
        print(f"  [PASS] All {total} layers emit all {mode} fields.")
    else:
        pct = round(n_ok / total * 100, 1)
        print(f"  [GAPS] {n_gap}/{total} layers missing fields ({pct}% coverage).")
        print()
        print(f"  Fix: add 'behavior_class' and 'detection_opportunities' to each")
        print(f"  layer's event records. See beacon_emitter_cloak.py for reference.")
    print()

    # JSON output for CI
    if getattr(args, "json", False):
        import json as _json
        result = {
            "total": total,
            "ok": n_ok,
            "gaps": n_gap,
            "coverage_pct": round(n_ok / total * 100, 1) if total else 0,
            "pass": n_gap == 0,
            "gap_layers": [
                {"layer": layer, "events": count, "missing": missing}
                for layer, missing, count in gap_layers
            ],
        }
        print(_json.dumps(result, indent=2))
