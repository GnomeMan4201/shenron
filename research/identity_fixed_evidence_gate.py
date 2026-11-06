#!/usr/bin/env python3
# Deterministic identity evidence CI contract; Python 3.12; dependencies: SHENRON/PyYAML; [needs Linux runner].
"""Check two census-selected identity seeds against frozen evidence and fail closed.

Read-only by default. --execute explicitly runs isolated synthetic SHENRON
layers in subprocesses, writing evidence only into the chosen output directory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

from core.assumptions.validator import (
    _artifact_signals, _normalize, validate_assumption,
)

SOURCE_COMMIT = "fb4eedc15d022ec6856f5978d14a07904fdb9220"
CENSUS_RUN = "https://github.com/GnomeMan4201/shenron/actions/runs/42140359338"
CENSUS_ZIP_SHA256 = "8c00934d827f3fb326024365294d4937b1787ac14ab158f0c9dc700e6b3462d8"
CLAIM_FILE = "assumptions/examples/identity_spoofing_coverage.yaml"
CLAIM_ID = "trusted_name_masquerade_evidence"
TARGET_SIGNAL = "trusted_name_rename_sim"
SIGNAL_FIELDS = (
    "behavior_class", "phase", "detection_opportunities",
    "expected_events", "alert_signatures",
)
POSITIVE_SEED = 2026110500
NEGATIVE_SEED = 2026110506
EXPECTATIONS = {
    POSITIVE_SEED: {
        "record_count": 17,
        "signal_count": 1,
        "semantic_sha256": "36768d2d959ce082de001cc33353d20ad2d21436df728a703a7609d16005eed2",
        "claim_status": "SUPPORTED",
        "identity_status": "SUPPORTED",
    },
    NEGATIVE_SEED: {
        "record_count": 26,
        "signal_count": 0,
        "semantic_sha256": "ace163086a951d3da19348fb43e881199aaa6d528b7013ca64aed58ead0f4a56",
        "claim_status": "UNSUPPORTED",
        "identity_status": "PARTIALLY_SUPPORTED",
    },
}
EXPECTED_OTHER_CLAIMS = {
    "firmware_log_forgery_evidence": "SUPPORTED",
    "firmware_tamper_evidence": "SUPPORTED",
    "device_identity_pollution_evidence": "SUPPORTED",
    "no_exfil_overclaim": "SUPPORTED",
}
RUN_SCRIPT = (
    "import random,runpy,sys;"
    "random.seed(int(sys.argv[1]));"
    "sys.argv=['shenron.py','--run','identity'];"
    "runpy.run_path('shenron.py',run_name='__main__')"
)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_records(path):
    records = []
    with open(path, encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL line {line_number}: {exc}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"non-object JSONL line {line_number}")
            records.append(record)
    if not records:
        raise ValueError(f"no records at {path}")
    return records


def semantic_digest(records):
    # Same semantic normalization used in the archived 100-trial census.
    selected = []
    for record in records:
        selected.append({
            "layer": record.get("layer"),
            "phase": record.get("phase"),
            "behavior_class": record.get("behavior_class"),
            "mitre_techniques": sorted(str(x) for x in record.get("mitre_techniques", [])),
            "detection_opportunities": sorted(str(x) for x in record.get("detection_opportunities", [])),
        })
    canonical = sorted(
        json.dumps(item, sort_keys=True, separators=(",", ":"))
        for item in selected
    )
    return hashlib.sha256("\n".join(canonical).encode()).hexdigest()


def status_for(result):
    statuses = {item.claim.id: item.status.value for item in result.claim_results}
    if CLAIM_ID not in statuses:
        raise ValueError("Target claim missing from frozen assumption")
    for name, expected in EXPECTED_OTHER_CLAIMS.items():
        if statuses.get(name) != expected:
            raise AssertionError(
                f"Unrelated claim {name}: {statuses.get(name)} != {expected}"
            )
    return statuses


def run_seed(seed, repeat_index, output):
    path = output / "fixtures" / f"seed-{seed}-repeat-{repeat_index}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="shenron-fixed-identity-") as home:
        env = os.environ.copy()
        env["SHENRON_SCOPED_LOG"] = str(path)
        env["SHENRON_HOME"] = home
        env["PYTHONHASHSEED"] = "0"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-c", RUN_SCRIPT, str(seed)],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
            check=False,
        )
    if completed.returncode != 0 or not re.search(
        r"\b4 ok\s*\|\s*0 failed\b", completed.stdout
    ):
        raise RuntimeError(
            f"identity run seed={seed} repeat={repeat_index}: "
            f"exit={completed.returncode}; stdout={completed.stdout[-500:]!r}; "
            f"stderr={completed.stderr[-500:]!r}"
        )
    records = load_records(path)
    assumption = validate_assumption(CLAIM_FILE, path)
    statuses = status_for(assumption)
    actual = {
        "seed": seed,
        "repeat_index": repeat_index,
        "record_count": len(records),
        "signal_count": sum(TARGET_SIGNAL in _artifact_signals(row) for row in records),
        "semantic_sha256": semantic_digest(records),
        "raw_sha256": digest(path),
        "claim_status": statuses[CLAIM_ID],
        "identity_status": assumption.status.value,
        "all_claim_statuses": statuses,
    }
    for field, expected in EXPECTATIONS[seed].items():
        if actual[field] != expected:
            raise AssertionError(
                f"seed={seed} repeat={repeat_index}: {field}: "
                f"{actual[field]!r} != census {expected!r}"
            )
    return actual, records


def negative_control(records, output):
    changed = 0
    modified = []
    near_miss = TARGET_SIGNAL + "_not_observed"
    for original in records:
        record = dict(original)
        for field in SIGNAL_FIELDS:
            value = record.get(field)
            if isinstance(value, str) and _normalize(value) == TARGET_SIGNAL:
                record[field] = near_miss
                changed += 1
            elif isinstance(value, list):
                rewritten = []
                for item in value:
                    if _normalize(str(item)) == TARGET_SIGNAL:
                        rewritten.append(near_miss)
                        changed += 1
                    else:
                        rewritten.append(item)
                record[field] = rewritten
        modified.append(record)
    if changed < 1:
        raise AssertionError("Positive fixture had no exact signal to remove")
    if any(TARGET_SIGNAL in _artifact_signals(record) for record in modified):
        raise AssertionError("Negative control still contains exact target signal")
    path = output / "fixtures" / "positive-near-miss-negative-control.jsonl"
    with path.open("w", encoding="utf-8") as stream:
        for record in modified:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
    result = validate_assumption(CLAIM_FILE, path)
    statuses = status_for(result)
    if statuses[CLAIM_ID] != "UNSUPPORTED":
        raise AssertionError(f"Near-miss negative incorrectly accepted: {statuses[CLAIM_ID]}")
    if result.status.value != "PARTIALLY_SUPPORTED":
        raise AssertionError(f"Near-miss identity verdict: {result.status.value}")
    return {
        "replaced_occurrences": changed,
        "claim_status": statuses[CLAIM_ID],
        "identity_status": result.status.value,
        "sha256": digest(path),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="run the synthetic identity subprocesses")
    parser.add_argument("--repeats", type=int, default=3, help="runs per seed, 2..10")
    parser.add_argument("--output", default="/tmp/shenron-fixed-identity-ci")
    args = parser.parse_args()
    if args.repeats < 2 or args.repeats > 10:
        parser.error("--repeats must be 2..10")
    if not args.execute:
        print(json.dumps({
            "mode": "DRY_RUN", "positive_seed": POSITIVE_SEED,
            "negative_seed": NEGATIVE_SEED, "repeats": args.repeats,
            "target": TARGET_SIGNAL, "output": args.output,
        }, indent=2))
        return 0

    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    results = []
    errors = []
    near_miss = None
    started = datetime.now(timezone.utc).isoformat()
    for seed in (POSITIVE_SEED, NEGATIVE_SEED):
        for repeat_index in range(args.repeats):
            try:
                row, records = run_seed(seed, repeat_index, output)
                results.append(row)
                if seed == POSITIVE_SEED and repeat_index == 0:
                    near_miss = negative_control(records, output)
            except (OSError, ValueError, RuntimeError, AssertionError, subprocess.SubprocessError) as exc:
                errors.append({
                    "seed": seed, "repeat_index": repeat_index,
                    "error_type": type(exc).__name__, "error": str(exc),
                })

    # All expected fixtures must pass, and the result metadata must be complete.
    for seed in EXPECTATIONS:
        selected = [row for row in results if row["seed"] == seed]
        if len(selected) != args.repeats:
            errors.append({"seed": seed, "error": "missing successful repeats"})
        elif len({
            (row["semantic_sha256"], row["claim_status"], row["identity_status"],
             row["record_count"], row["signal_count"])
            for row in selected
        }) != 1:
            errors.append({"seed": seed, "error": "seed repeat mismatch"})
    if near_miss is None:
        errors.append({"error": "near-miss negative control not executed"})

    summary = {
        "result": "PASS" if not errors else "FAIL",
        "pinned_source_commit": SOURCE_COMMIT,
        "executed_head": os.getenv("SHENRON_SOURCE_REVISION", "unknown"),
        "census_source_run": CENSUS_RUN,
        "census_artifact_sha256": CENSUS_ZIP_SHA256,
        "python_version": sys.version,
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "repeats_per_seed": args.repeats,
        "tests_passed": len(results),
        "tests_requested": 2 * args.repeats,
        "expected_fixtures": EXPECTATIONS,
        "negative_control": near_miss,
        "results": results,
        "errors": errors,
        "qualification": "Selected synthetic evidence and assumption statuses only; not production detection or independent review.",
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
