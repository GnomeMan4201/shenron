"""
core/cli/commands/health.py

`shenron health` — full system health check.

Runs all four validation dimensions and prints a single PASS/FAIL verdict:
  1. Tests          — pytest suite
  2. Doctor         — field emission coverage across layers
  3. MITRE drift    -- ATT&CK technique currency
  4. Assumptions    — all category assumptions validated

Usage:
    python3 shenron.py health
    python3 shenron.py health --offline
    python3 shenron.py health --skip-tests
    python3 shenron.py health --drift-cache .cache/attack_bundle.json
"""

import sys
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


WIDTH = 70
DIVIDER = " " + "=" * WIDTH


def _run_pytest(verbose: bool = False) -> tuple[bool, str]:
    """Run pytest and return (passed, summary)."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/", "-q", "--tb=no"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = result.stdout.strip()
        # Extract last line summary
        lines = [l for l in output.splitlines() if l.strip()]
        summary = lines[-1] if lines else "no output"
        passed = result.returncode == 0
        return passed, summary
    except subprocess.TimeoutExpired:
        return False, "timeout after 120s"
    except Exception as e:
        return False, str(e)


def _run_doctor(events_path: str = None) -> tuple[bool, str]:
    """Run doctor check and return (passed, summary)."""
    try:
        cmd = [sys.executable, "shenron.py", "doctor"]
        if events_path:
            cmd += ["--events", events_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout
        # Parse: "Layers  : N  |  OK: N  |  Gaps: N"
        import re
        m = re.search(r"Layers\s*:\s*(\d+).*?Gaps:\s*(\d+)", output)
        if m:
            total, gaps = int(m.group(1)), int(m.group(2))
            if gaps == 0:
                return True, f"{total} layers OK, 0 gaps"
            else:
                return False, f"{total} layers, {gaps} with gaps"
        # Fallback: check for PASS
        if "[PASS]" in output:
            return True, "all layers OK"
        return False, "unexpected output"
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, f"error: {e}"


def _run_drift(offline: bool, cache_path: str = None) -> tuple[bool, str]:
    """Run MITRE drift check and return (passed, summary)."""
    try:
        from core.mitre.drift import check_drift
        report = check_drift(
            manifest_path="shenron_manifest.json",
            offline=offline,
            cached_bundle_path=cache_path,
        )
        if report.verdict == "CURRENT":
            return True, f"{len(report.ok)}/{report.total_techniques} current, v{report.attack_version}"
        else:
            issues = len(report.stale) + len(report.renamed)
            return False, f"{report.verdict}: {issues} technique(s) need attention"
    except Exception as e:
        return False, f"error: {e}"


def _run_validate_all() -> tuple[bool, str]:
    """Run validate-all-assumptions and return (passed, summary)."""
    try:
        from core.cli.commands.validate_all import CATEGORY_ASSUMPTIONS, _run_category_scoped, _validate_assumption, _status_str
        import tempfile, shutil

        tmp = tempfile.mkdtemp(prefix="shenron_health_")
        try:
            supported = []
            failed = []

            for category, assumption_path in CATEGORY_ASSUMPTIONS.items():
                if not Path(assumption_path).exists():
                    failed.append(f"{category}(no file)")
                    continue

                scoped_path = str(Path(tmp) / f"shenron_{category}.jsonl")
                ok = _run_category_scoped(category, scoped_path)
                if not ok or not Path(scoped_path).exists():
                    failed.append(f"{category}(run failed)")
                    continue

                try:
                    result = _validate_assumption(assumption_path, scoped_path)
                    status = _status_str(result)
                    if status == "SUPPORTED":
                        supported.append(category)
                    else:
                        failed.append(f"{category}({status})")
                except Exception as e:
                    failed.append(f"{category}(error)")

            total = len(supported) + len(failed)
            if not failed:
                return True, f"{len(supported)}/{total} categories SUPPORTED"
            else:
                return False, f"{len(supported)}/{total} supported, failed: {', '.join(failed)}"
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    except Exception as e:
        return False, f"error: {e}"


def _print_check(name: str, passed: bool, summary: str, elapsed: float):
    marker = "✓" if passed else "✗"
    status = "PASS" if passed else "FAIL"
    print(f"  [{marker}] {name:<20} {status:<6}  {summary}  ({elapsed:.1f}s)")


def run_health(args) -> int:
    """Main health check runner. Returns exit code."""
    skip_tests   = getattr(args, "skip_tests", False)
    offline      = getattr(args, "offline", False)
    cache_path   = getattr(args, "drift_cache", None)
    events_path  = getattr(args, "events", None)

    # Default cache path
    if not cache_path:
        default_cache = Path(".cache/attack_bundle.json")
        if default_cache.exists():
            cache_path = str(default_cache)
            offline = True

    print()
    print(DIVIDER)
    print("  SHENRON Health Check")
    print(f"  checked_at : {datetime.now(timezone.utc).isoformat()}")
    print(DIVIDER)
    print()

    checks = []
    all_passed = True

    # 1. Tests
    if skip_tests:
        print(f"  [-] {'tests':<20} SKIP   (--skip-tests)")
    else:
        t0 = time.time()
        print(f"  [~] {'tests':<20} running pytest...", end="\r", flush=True)
        passed, summary = _run_pytest()
        elapsed = time.time() - t0
        _print_check("tests", passed, summary, elapsed)
        checks.append(("tests", passed))
        if not passed:
            all_passed = False

    # 2. Doctor
    t0 = time.time()
    print(f"  [~] {'doctor':<20} checking field emission...", end="\r", flush=True)
    passed, summary = _run_doctor(events_path=events_path)
    elapsed = time.time() - t0
    _print_check("doctor", passed, summary, elapsed)
    checks.append(("doctor", passed))
    if not passed:
        all_passed = False

    # 3. MITRE drift
    t0 = time.time()
    mode = "offline" if (offline and cache_path) else "fetching"
    print(f"  [~] {'mitre-drift':<20} {mode}...", end="\r", flush=True)
    passed, summary = _run_drift(offline=offline and bool(cache_path), cache_path=cache_path)
    elapsed = time.time() - t0
    _print_check("mitre-drift", passed, summary, elapsed)
    checks.append(("mitre-drift", passed))
    if not passed:
        all_passed = False

    # 4. Assumptions
    t0 = time.time()
    print(f"  [~] {'assumptions':<20} validating all categories...", end="\r", flush=True)
    passed, summary = _run_validate_all()
    elapsed = time.time() - t0
    _print_check("assumptions", passed, summary, elapsed)
    checks.append(("assumptions", passed))
    if not passed:
        all_passed = False

    # Verdict
    print()
    print(DIVIDER)
    if all_passed:
        print(f"  [✓] VERDICT: HEALTHY — all {len(checks)} checks passed")
    else:
        failed = [name for name, p in checks if not p]
        print(f"  [✗] VERDICT: UNHEALTHY — {len(failed)} check(s) failed: {', '.join(failed)}")
    print(DIVIDER)
    print()

    return 0 if all_passed else 1


def register(subparsers):
    p = subparsers.add_parser(
        "health",
        help="full system health check: tests, doctor, MITRE drift, assumptions",
    )
    p.add_argument(
        "--skip-tests", action="store_true",
        help="skip pytest suite (faster)",
    )
    p.add_argument(
        "--offline", action="store_true",
        help="use cached ATT&CK bundle for drift check",
    )
    p.add_argument(
        "--drift-cache", type=str, default=None, metavar="PATH",
        help="path to cached ATT&CK STIX bundle",
    )
    p.add_argument(
        "--events", type=str, default=None, metavar="JSONL",
        help="artifact log for doctor check (default: auto-detect)",
    )
    p.set_defaults(func=lambda args: sys.exit(run_health(args)))
