#!/usr/bin/env python3
# Identity assumption reproducibility census; Python 3.10+; SHENRON deps (PyYAML); [needs Linux runner].
"""Read-only synthetic identity experiment; executes SHENRON only with --execute."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from core.assumptions.validator import validate_assumption, _normalize, _artifact_signals

PINNED_SOURCE = "fb4eedc15d022ec6856f5978d14a07904fdb9220"
CLAIM_FILE = "assumptions/examples/identity_spoofing_coverage.yaml"
CLAIM_ID = "trusted_name_masquerade_evidence"
TARGET = "trusted_name_rename_sim"
SIGNAL_FIELDS = ("behavior_class", "phase", "detection_opportunities",
                 "expected_events", "alert_signatures")
RUN_CODE = (
    "import random, runpy, sys;"
    "random.seed(int(sys.argv[1]));"
    "sys.argv=['shenron.py','--run','identity'];"
    "runpy.run_path('shenron.py',run_name='__main__')"
)


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_records(path):
    records = []
    with open(path, encoding="utf-8") as stream:
        for lineno, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed trial JSONL line {lineno}: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"Non-object trial JSONL line {lineno}")
            records.append(row)
    if not records:
        raise ValueError("The identity runner emitted no records")
    return records


def claim_by_id(result, claim_id):
    for item in result.claim_results:
        if item.claim.id == claim_id:
            return item
    raise ValueError(f"Claim is absent from the pinned assumption: {claim_id}")


def semantic_digest(records):
    # Exclude UUID, timestamps, hash values, absolute paths, and record ordering.
    selected = []
    for record in records:
        selected.append({
            "layer": record.get("layer"),
            "phase": record.get("phase"),
            "behavior_class": record.get("behavior_class"),
            "mitre_techniques": sorted(str(x) for x in record.get("mitre_techniques", [])),
            "detection_opportunities": sorted(str(x) for x in record.get("detection_opportunities", [])),
        })
    values = sorted(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in selected)
    return hashlib.sha256("\n".join(values).encode()).hexdigest()


def remove_required_signal(records):
    cleaned = []
    replaced = 0
    for source in records:
        record = dict(source)
        for field in SIGNAL_FIELDS:
            val = record.get(field)
            if isinstance(val, str) and _normalize(val) == TARGET:
                record[field] = TARGET + "_not_observed"
                replaced += 1
            elif isinstance(val, list):
                values = []
                for item in val:
                    if _normalize(str(item)) == TARGET:
                        values.append(TARGET + "_not_observed")
                        replaced += 1
                    else:
                        values.append(item)
                record[field] = values
        cleaned.append(record)
    if any(TARGET in _artifact_signals(record) for record in cleaned):
        raise RuntimeError("Negative-control transformation did not remove the exact signal")
    return cleaned, replaced


def run_identity(seed, sequence, root):
    directory = root / f"trial-{sequence:03d}"
    directory.mkdir()
    path = directory / "identity.jsonl"
    env = os.environ.copy()
    env["SHENRON_SCOPED_LOG"] = str(path)
    env["SHENRON_HOME"] = str(directory / "home")
    env["PYTHONHASHSEED"] = "0"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    process = subprocess.run(
        [sys.executable, "-c", RUN_CODE, str(seed)],
        env=env,
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    if process.returncode != 0 or re.search(r"\b4 ok\s*\|\s*0 failed\b", process.stdout) is None:
        raise RuntimeError(
            f"Identity subprocess failed (seed={seed}, code={process.returncode}); "
            f"stdout tail={process.stdout[-800:]!r}; stderr tail={process.stderr[-800:]!r}"
        )
    records = read_records(path)
    result = validate_assumption(CLAIM_FILE, path)
    target_claim = claim_by_id(result, CLAIM_ID)
    signal_present = any(TARGET in _artifact_signals(record) for record in records)
    if (target_claim.status.value == "SUPPORTED") != signal_present:
        raise RuntimeError(
            f"Claim/signal mismatch for seed {seed}: "
            f"signal={signal_present}, verdict={target_claim.status.value}"
        )

    return {
        "seed": seed,
        "sequence": sequence,
        "record_count": len(records),
        "signal_present": signal_present,
        "signal_record_count": sum(TARGET in _artifact_signals(record) for record in records),
        "trusted_claim_status": target_claim.status.value,
        "identity_status": result.status.value,
        "claim_statuses": {item.claim.id: item.status.value for item in result.claim_results},
        "semantic_sha256": semantic_digest(records),
        "raw_artifact_sha256": sha256_file(path),
        "records": records,
    }


def run_experiment(args):
    start = datetime.now(timezone.utc).isoformat()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    observations = []
    controls = []
    errors = []
    original_semantics = {}
    with tempfile.TemporaryDirectory(prefix="shenron_identity_census_") as tempdir:
        root = Path(tempdir)
        for index in range(args.trials):
            seed = args.seed_start + index
            for repeat_index in range(args.repeats):
                sequence = index * args.repeats + repeat_index
                try:
                    trial = run_identity(seed, sequence, root)
                    records = trial.pop("records")
                    trial["repeat_index"] = repeat_index
                    observations.append(trial)
                    key = (trial["semantic_sha256"], trial["trusted_claim_status"],
                           trial["identity_status"], trial["signal_present"],
                           trial["record_count"])
                    if seed in original_semantics and original_semantics[seed] != key:
                        errors.append({
                            "type": "seed_repeat_mismatch", "seed": seed,
                            "original": original_semantics[seed], "repeat": key,
                        })
                    original_semantics.setdefault(seed, key)
                    if repeat_index == 0:
                        control_records, replaced = remove_required_signal(records)
                        control_path = root / f"control-{index:03d}.jsonl"
                        control_path.write_text(
                            "".join(json.dumps(record, sort_keys=True) + "\n"
                                    for record in control_records), encoding="utf-8"
                        )
                        control_result = validate_assumption(CLAIM_FILE, control_path)
                        control_claim = claim_by_id(control_result, CLAIM_ID)
                        control = {
                            "seed": seed,
                            "replaced_occurrences": replaced,
                            "negative_claim_status": control_claim.status.value,
                            "negative_identity_status": control_result.status.value,
                            "negative_control_sha256": sha256_file(control_path),
                        }
                        controls.append(control)
                        if control_claim.status.value == "SUPPORTED" or control_result.status.value == "SUPPORTED":
                            errors.append({
                                "type": "missing_signal_accepted", "seed": seed,
                                "negative_control": control,
                            })
                except Exception as exc:
                    errors.append({"type": "trial_execution_error", "seed": seed,
                                   "repeat_index": repeat_index, "error": str(exc)})
                if len(errors) >= 10:
                    break
            if len(errors) >= 10:
                break

    def write_jsonl(path, values):
        path.write_text(
            "".join(json.dumps(value, sort_keys=True, default=str) + "\n" for value in values),
            encoding="utf-8",
        )
    trial_path = output / "trials.jsonl"
    control_path = output / "negative_controls.jsonl"
    write_jsonl(trial_path, observations)
    write_jsonl(control_path, controls)

    first = [row for row in observations if row["repeat_index"] == 0]
    summary = {
        "status": "VIOLATION" if errors else ("COMPLETE" if len(first) == args.trials
                   and len(observations) == args.trials * args.repeats else "INCOMPLETE"),
        "pinned_source": PINNED_SOURCE,
        "source_head": os.getenv("GITHUB_SHA", "unknown"),
        "started_at": start,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "trials_requested": args.trials,
        "repeats_per_seed": args.repeats,
        "seed_start": args.seed_start,
        "trials_observed": len(first),
        "repeat_runs_observed": len(observations) - len(first),
        "negative_controls_observed": len(controls),
        "trusted_claim_status_counts": dict(Counter(row["trusted_claim_status"] for row in first)),
        "identity_status_counts": dict(Counter(row["identity_status"] for row in first)),
        "trusted_signal_presence_counts": dict(Counter(str(row["signal_present"]) for row in first)),
        "repeat_mismatches": sum(e["type"] == "seed_repeat_mismatch" for e in errors),
        "missing_signal_false_supports": sum(e["type"] == "missing_signal_accepted" for e in errors),
        "errors": errors,
        "trial_file_sha256": sha256_file(trial_path),
        "control_file_sha256": sha256_file(control_path),
        "interpretation": (
            "Semantic repeat comparisons exclude timestamps, UUIDs, and random artifact hashes. "
            "Seed control applies to Python's random module, not all entropy sources. "
            "Synthetic support is not real-world detection coverage."
        ),
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0 if summary["status"] == "COMPLETE" else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="actually run synthetic identity trials")
    parser.add_argument("--trials", type=int, default=100, help="number of distinct seeds")
    parser.add_argument("--repeats", type=int, default=2, help="runs per seed")
    parser.add_argument("--seed-start", type=int, default=2026110500)
    parser.add_argument("--output", default="/tmp/shenron-identity-census")
    args = parser.parse_args()
    if not (1 <= args.trials <= 1000 and 2 <= args.repeats <= 5):
        parser.error("--trials must be 1..1000 and --repeats must be 2..5")
    if not args.execute:
        print("DRY RUN: planned seeded synthetic identity trials",
              {"trials": args.trials, "repeats": args.repeats,
               "seed_start": args.seed_start, "output": args.output})
        return 0
    try:
        return run_experiment(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
