"""
SHENRON Validation History
Persists validation results and sigma results per run for comparison.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from core.config import get_shenron_base


def _history_path() -> Path:
    p = get_shenron_base() / "validation_history.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def record_validation(result, result_type: str = "assumption") -> dict:
    """Persist a validation result. result_type: assumption | sigma | coverage"""
    entry = {
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "result_type": result_type,
        "data":        result.to_dict() if hasattr(result, "to_dict") else result,
    }
    with open(_history_path(), "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def load_history(result_type: str = None, limit: int = 100) -> list:
    """Load validation history. Optionally filter by result_type."""
    p = _history_path()
    if not p.exists():
        return []
    entries = []
    for line in p.read_text().splitlines():
        if not line.strip():
            continue
        try:
            e = json.loads(line)
            if result_type is None or e.get("result_type") == result_type:
                entries.append(e)
        except json.JSONDecodeError:
            pass
    return entries[-limit:]


def print_history(entries: list):
    if not entries:
        print("  [!] No validation history found.")
        return

    print(f"\n  Validation History ({len(entries)} entries)\n")
    print(f"  {'Timestamp':<25} {'Type':<12} {'ID':<35} {'Status'}")
    print(f"  {'-'*25} {'-'*12} {'-'*35} {'-'*20}")

    for e in reversed(entries):
        ts      = e.get("timestamp", "")[:19]
        rtype   = e.get("result_type", "?")
        data    = e.get("data", {})
        id_     = (data.get("assumption_id") or
                   data.get("rule_id") or
                   data.get("run_id") or "?")[:34]
        status  = (data.get("status") or
                   data.get("verdict") or "?")
        print(f"  {ts:<25} {rtype:<12} {id_:<35} {status}")
    print()


def compare_history(id_: str, limit: int = 10) -> list:
    """Get all history entries for a given assumption/rule ID."""
    all_entries = load_history()
    matches = []
    for e in all_entries:
        data = e.get("data", {})
        entry_id = (data.get("assumption_id") or
                    data.get("rule_id") or
                    data.get("run_id") or "")
        if id_.lower() in entry_id.lower():
            matches.append(e)
    return matches[-limit:]


def print_comparison(id_: str, entries: list):
    if not entries:
        print(f"  [!] No history found for: {id_}")
        return

    print(f"\n  History for: {id_} ({len(entries)} runs)\n")
    prev_status = None
    for e in entries:
        ts     = e.get("timestamp", "")[:19]
        data   = e.get("data", {})
        status = (data.get("status") or data.get("verdict") or "?")
        sup    = data.get("supported_count", data.get("triggered_count", "?"))
        uns    = data.get("unsupported_count", "?")

        delta = ""
        if prev_status and prev_status != status:
            delta = f"  <- changed from {prev_status}"
        prev_status = status

        print(f"  {ts}  {status:<30} sup={sup} uns={uns}{delta}")
    print()
