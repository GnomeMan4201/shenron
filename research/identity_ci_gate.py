#!/usr/bin/env python3
# Purpose: qualify seeded synthetic identity evidence for CI; Python 3.10+; project dependencies (PyYAML); [needs Linux runner].
"""CI-only identity fixture gate; passive by default, --execute runs simulations.

This is deliberately different from a random-sample experiment. Two seeds were
chosen from the earlier 100-seed census: 2026110500 (required signal present)
and 2026110506 (required signal absent). A current-code run must demonstrate
both results, semantic repeatability, and a signal-removal negative control.
No old SHA is reused: the T1078 label was removed after that census.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from core.assumptions.validator import (
    _artifact_signals, _normalize, validate_assumption,
)

REPO = Path(__file__).resolve().parents[1]
ASSUMPTION = REPO / "assumptions/examples/identity_spoofing_coverage.yaml"
TARGET = "trusted_name_rename_sim"
CLAIM = "trusted_name_masquerade_evidence"
SEEDS = (("positive", 2026110500, 17, 1), ("negative", 2026110506, 26, 0))
FIELDS = ("behavior_class", "phase", "detection_opportunities",
          "expected_events", "alert_signatures")
OTHER_CLAIMS = {
    "firmware_log_forgery_evidence",
    "firmware_tamper_evidence",
    "device_identity_pollution_evidence",
    "no_exfil_overclaim",
}
RUN_SCRIPT = (
    "import random,runpy,sys;"
    "random.seed(int(sys.argv[1]));"
    "sys.argv=['shenron.py','--run','identity'];"
    "runpy.run_path('shenron.py',run_name='__main__')"
)


class GateFailure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise GateFailure(message)


def records_from(path):
    rows = []
    with path.open(encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise GateFailure(f"{path.name}:{line_no}: bad JSONL: {exc}") from exc
            require(isinstance(value, dict),
                    f"{path.name}:{line_no}: non-object record")
            rows.append(value)
    require(bool(rows), f"{path.name}: no records")
    return rows


def digest_semantics(records):
    selected = [{
        "layer": r.get("layer"),
        "phase": r.get("phase"),
        "behavior_class": r.get("behavior_class"),
        "mitre_techniques": sorted(map(str, r.get("mitre_techniques", []))),
        "detection_opportunities": sorted(map(str, r.get("detection_opportunities", []))),
    } for r in records]
    lines = sorted(json.dumps(r, sort_keys=True, separators=(",", ":"))
                   for r in selected)
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def check_claims(path, expected_target, expected_overall):
    result = validate_assumption(ASSUMPTION, path)
    statuses = {r.claim.id: r.status.value for r in result.claim_results}
    require(statuses.get(CLAIM) == expected_target,
            f"{path.name}: target {statuses.get(CLAIM)} != {expected_target}")
    require(result.status.value == expected_overall,
            f"{path.name}: identity {result.status.value} != {expected_overall}")
    require(all(statuses.get(name) == "SUPPORTED" for name in OTHER_CLAIMS),
            f"{path.name}: unrelated claims changed: {statuses}")
    return statuses


def simulate(seed, path, home):
    env = os.environ.copy()
    env.update({
        "SHENRON_SCOPED_LOG": str(path),
        "SHENRON_HOME": str(home),
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    completed = subprocess.run(
        [sys.executable, "-c", RUN_SCRIPT, str(seed)],
        cwd=REPO, env=env, capture_output=True, text=True,
        timeout=120, check=False,
    )
    require(completed.returncode == 0,
            f"seed={seed}: generator exit={completed.returncode}; "
            f"stdout={completed.stdout[-600:]!r}; stderr={completed.stderr[-600:]!r}")
    require(path.is_file(), f"seed={seed}: missing generated JSONL")


def remove_signal(rows):
    modified = []
    replaced = 0
    for original in rows:
        row = dict(original)
        for key in FIELDS:
            value = row.get(key)
            if isinstance(value, str) and _normalize(value) == TARGET:
                row[key] = TARGET + "_not_observed"
                replaced += 1
            elif isinstance(value, list):
                updated = []
                for item in value:
                    if isinstance(item, str) and _normalize(item) == TARGET:
                        updated.append(TARGET + "_not_observed")
                        replaced += 1
                    else:
                        updated.append(item)
                row[key] = updated
        modified.append(row)
    require(replaced >= 1, "positive seed lacked a removable exact signal")
    require(not any(TARGET in _artifact_signals(r) for r in modified),
            "negative control still contains required signal")
    return modified, replaced


def write_jsonl(path, rows):
    with path.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True) + "\n")


def execute(output):
    require(not (output / "shenron_identity.jsonl").exists(),
            "output identity fixture already exists (refusing to append/replace)")
    summary = {"qualification": "Synthetic, seeded evidence contract only; "
               "not an ATT&CK mapping or real-world detection evaluation.",
               "original_census": "https://github.com/GnomeMan4201/shenron/actions/runs/42140359338",
               "fixed_fixture": "https://github.com/GnomeMan4201/shenron/actions/runs/42151900119",
               "current_code_hashes_are_not_historical_census_hashes": True,
               "runs": [], "near_miss": None}
    with tempfile.TemporaryDirectory(prefix="shenron-identity-gate-") as root:
        base = Path(root)
        positive_rows = None
        for label, seed, expected_records, expected_signals in SEEDS:
            fingerprints = set()
            for repeat in range(2):
                path = base / f"{label}-{repeat}.jsonl"
                home = base / f"home-{label}-{repeat}"
                home.mkdir()
                simulate(seed, path, home)
                rows = records_from(path)
                signal_count = sum(TARGET in _artifact_signals(r) for r in rows)
                require(len(rows) == expected_records,
                        f"seed={seed}: got {len(rows)} records, expected {expected_records}")
                require(signal_count == expected_signals,
                        f"seed={seed}: got {signal_count} target records, expected {expected_signals}")
                status = "SUPPORTED" if label == "positive" else "UNSUPPORTED"
                overall = "SUPPORTED" if label == "positive" else "PARTIALLY_SUPPORTED"
                claims = check_claims(path, status, overall)
                sha = digest_semantics(rows)
                fingerprints.add((sha, status, overall))
                summary["runs"].append({
                    "label": label, "seed": seed, "repeat": repeat,
                    "records": len(rows), "signal_records": signal_count,
                    "semantic_sha256": sha, "claims": claims,
                    "overall": overall,
                })
                if label == "positive" and repeat == 0:
                    positive_rows = rows
                    positive_file = path
                if label == "negative" and repeat == 0:
                    negative_file = path
            require(len(fingerprints) == 1,
                    f"seed={seed}: non-repeatable selected signals or verdicts")

        require(positive_rows is not None, "missing positive evidence")
        near_rows, replaced = remove_signal(positive_rows)
        near_path = base / "near-miss.jsonl"
        write_jsonl(near_path, near_rows)
        check_claims(near_path, "UNSUPPORTED", "PARTIALLY_SUPPORTED")
        summary["near_miss"] = {"replaced": replaced, "result": "PARTIALLY_SUPPORTED"}

        output.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(positive_file, output / "shenron_identity.jsonl")
        shutil.copyfile(negative_file, output / "identity_seed_negative_control.jsonl")
        shutil.copyfile(near_path, output / "identity_removed_signal_control.jsonl")
        (output / "identity_seed_gate_summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true",
                        help="run the two synthetic identity seeds and save CI fixtures")
    parser.add_argument("--output-dir", type=Path, default=Path("/tmp/shenron_scoped"))
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({
            "mode": "DRY_RUN", "positive_seed": SEEDS[0][1],
            "negative_seed": SEEDS[1][1], "repeats": 2,
            "output_dir": str(args.output_dir),
        }, indent=2))
        return 0
    try:
        summary = execute(args.output_dir.resolve())
    except (GateFailure, OSError, ValueError, RuntimeError,
            subprocess.SubprocessError) as exc:
        print(f"identity gate FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
