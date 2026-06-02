"""
core/cli/commands/validate_all.py

--validate-all-assumptions command for SHENRON.

Runs each category scoped, validates its assumption, and prints a
summary table. Exits non-zero if any category is not SUPPORTED.

Usage:
    python3 shenron.py --validate-all-assumptions
    python3 shenron.py --validate-all-assumptions --no-rerun
    python3 shenron.py --validate-all-assumptions --out-dir /tmp/scoped
"""

import os
import sys
import tempfile
from pathlib import Path
from datetime import datetime, timezone

# Category → assumption file mapping
CATEGORY_ASSUMPTIONS = {
    "persistence": "assumptions/examples/persistence_coverage.yaml",
    "c2":          "assumptions/examples/c2_coverage.yaml",
    "evasion":     "assumptions/examples/defense_evasion_coverage.yaml",
    "payload":     "assumptions/examples/execution_coverage.yaml",
    "entropy":     "assumptions/examples/entropy_evasion_coverage.yaml",
    "identity":    "assumptions/examples/identity_spoofing_coverage.yaml",
    "llm":         "assumptions/examples/llm_manipulation_coverage.yaml",
}

# Status display
STATUS_MARKERS = {
    "SUPPORTED":              "[✓]",
    "PARTIALLY_SUPPORTED":    "[~]",
    "PARTIALLY SUPPORTED":    "[~]",
    "UNSUPPORTED":            "[✗]",
    "OUT_OF_SCOPE_VIOLATION": "[!]",
    "OUT-OF-SCOPE VIOLATION": "[!]",
}


def _run_category_scoped(category: str, scoped_path: str) -> bool:
    """Run a category and write to scoped_path. Returns True on success."""
    import subprocess
    env = os.environ.copy()
    env["SHENRON_SCOPED_LOG"] = scoped_path

    result = subprocess.run(
        [sys.executable, "shenron.py", "--run", category],
        env=env,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _validate_assumption(assumption_path: str, events_path: str):
    """Run assumption validation and return AssumptionResult."""
    from core.assumptions.validator import validate_assumption
    return validate_assumption(assumption_path, events_path)


def _status_str(result) -> str:
    """Extract clean status string from AssumptionResult."""
    raw = str(result.status.value if hasattr(result.status, 'value') else result.status)
    return raw.replace("_", " ")


def cmd_validate_all(args):
    """--validate-all-assumptions command handler."""
    no_rerun  = getattr(args, "no_rerun", False)
    scope_dir = getattr(args, "scope_dir", None)

    # Determine scoped artifact directory
    if scope_dir:
        out_dir = Path(scope_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        cleanup = False
    else:
        tmp = tempfile.mkdtemp(prefix="shenron_validate_all_")
        out_dir = Path(tmp)
        cleanup = True

    width = 70
    divider = " " + "=" * width

    print()
    print(divider)
    print("  SHENRON — Validate All Assumptions")
    print(f"  checked_at : {datetime.now(timezone.utc).isoformat()}")
    print(f"  categories : {len(CATEGORY_ASSUMPTIONS)}")
    print(f"  rerun      : {'no (using existing scoped artifacts)' if no_rerun else 'yes'}")
    print(divider)
    print()

    results = []
    all_supported = True

    for category, assumption_path in CATEGORY_ASSUMPTIONS.items():
        scoped_path = str(out_dir / f"shenron_{category}.jsonl")

        # Check assumption file exists
        if not Path(assumption_path).exists():
            print(f"  [?] {category:<15} assumption file not found: {assumption_path}")
            results.append((category, "NO_ASSUMPTION", 0, 0, assumption_path))
            all_supported = False
            continue

        # Run category if needed
        if no_rerun and Path(scoped_path).exists():
            print(f"  [~] {category:<15} using existing artifact")
        else:
            ok = _run_category_scoped(category, scoped_path)
            if not ok or not Path(scoped_path).exists():
                print(f"  [✗] {category:<15} run failed")
                results.append((category, "RUN_FAILED", 0, 0, assumption_path))
                all_supported = False
                continue

        # Validate assumption
        try:
            result = _validate_assumption(assumption_path, scoped_path)
            status = _status_str(result)
            supported = result.supported_count
            unsupported = result.unsupported_count
            marker = STATUS_MARKERS.get(status, "[ ]")

            if "SUPPORTED" not in status or "PARTIALLY" in status or "OUT" in status:
                all_supported = False

            results.append((category, status, supported, unsupported, assumption_path))

        except Exception as e:
            print(f"  [!] {category:<15} validation error: {e}")
            results.append((category, "ERROR", 0, 0, assumption_path))
            all_supported = False

    # Summary table
    print()
    print(divider)
    print("  RESULTS")
    print(divider)
    print()
    print(f"  {'CATEGORY':<15} {'STATUS':<25} {'OK':>4}  {'FAIL':>4}  ASSUMPTION")
    print(f"  {'-'*14} {'-'*24} {'-'*4}  {'-'*4}  {'-'*30}")

    for category, status, supported, unsupported, assumption_path in results:
        marker = STATUS_MARKERS.get(status, "[ ]")
        aname = Path(assumption_path).name
        print(f"  {marker} {category:<13} {status:<25} {supported:>4}  {unsupported:>4}  {aname}")

    print()

    # Verdict
    if all_supported:
        print(f"  [✓] VERDICT: ALL SUPPORTED — {len(CATEGORY_ASSUMPTIONS)} categories validated")
    else:
        failed = [r[0] for r in results if r[1] != "SUPPORTED"]
        print(f"  [!] VERDICT: {len(failed)} category/categories not fully supported: {', '.join(failed)}")

    print()

    # Cleanup temp dir
    if cleanup:
        import shutil
        shutil.rmtree(out_dir, ignore_errors=True)

    return 0 if all_supported else 1
