from pathlib import Path

path = Path("core/layers/system_rebuild_sim.py")
text = path.read_text(encoding="utf-8")
old = '''        scan_results.append({
            "path": f["path"],
            "type": f["type"],
            "state": state["state"],
            "label": state["label"],
            "hash_orig_sim": _fake_hash(),
            "hash_current_sim": _fake_hash() if state["state"] != "match" else None,
        })

    scan_event = {
'''
new = '''        scan_results.append({
            "path": f["path"],
            "type": f["type"],
            "state": state["state"],
            "label": state["label"],
            "hash_orig_sim": _fake_hash(),
            "hash_current_sim": _fake_hash() if state["state"] != "match" else None,
        })

    # The persistence validation contract requires at least one restoration-
    # shaped event (T1543). Preserve randomized file states, but prevent an
    # all-match draw from making required category coverage probabilistic.
    if scan_results and all(result["state"] == "match" for result in scan_results):
        forced = scan_results[0]
        forced["state"] = "mismatch"
        forced["label"] = "hash mismatch detected — restoration triggered"
        forced["hash_current_sim"] = _fake_hash()

    scan_event = {
'''
if text.count(old) != 1:
    raise SystemExit(f"unexpected system_rebuild_sim shape: {text.count(old)} matches")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
