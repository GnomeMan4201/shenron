"""CLI regression using PRs #50/#51's recorded positive and negative seeds.

Only evidence-bearing identity fields are compared: UUIDs, timestamps and
OS-generated hashes are intentionally outside the repeatability contract.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from core.assumptions.validator import validate_assumption
from research.identity_ci_gate import (
    ASSUMPTION, CLAIM, OTHER_CLAIMS, digest_semantics,
)

REPO = Path(__file__).resolve().parents[1]


def invoke(root, *args, scoped_log=None):
    root.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.pop("SHENRON_SCOPED_LOG", None)
    env.update(SHENRON_HOME=str(root / "home"),
               SHENRON_REPORT_DIR=str(root / "reports"), PYTHONHASHSEED="0")
    if scoped_log is not None:
        env["SHENRON_SCOPED_LOG"] = str(scoped_log)
    return subprocess.run(
        [sys.executable, str(REPO / "shenron.py"), *map(str, args)],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=120,
    )


def fingerprint(path, expected_status, expected_records):
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert len(rows) == expected_records
    result = validate_assumption(ASSUMPTION, path)
    claims = {r.claim.id: r.status.value for r in result.claim_results}
    assert claims == dict.fromkeys(OTHER_CLAIMS, "SUPPORTED") | {CLAIM: expected_status}
    assert result.status.value == (
        "SUPPORTED" if expected_status == "SUPPORTED" else "PARTIALLY_SUPPORTED"
    )
    return digest_semantics(rows), claims


@pytest.mark.parametrize("seed,expected_status,expected_records", [
    (2026110500, "SUPPORTED", 17),
    (2026110506, "UNSUPPORTED", 26),
])
def test_seeded_identity_cli_repeats_across_run_syntaxes(
    tmp_path, seed, expected_status, expected_records,
):
    observed = []
    for index, syntax in enumerate((("--run", "identity"), ("run", "identity")) * 2):
        root = tmp_path / str(index)
        artifact = root / "identity.jsonl"
        # Both run grammars must accept the same seed and preserve the census
        # evidence contract, including the known missing-signal case.
        env_args = (*syntax, "--seed", seed)
        if syntax[0] == "--run":
            proc = invoke(root, *env_args, "--scope-out", artifact)
        else:
            # New run grammar uses the standard scoped-log environment.
            proc = invoke(root, *env_args, scoped_log=artifact)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "4 ok  |  0 failed" in proc.stdout
        observed.append(fingerprint(artifact, expected_status, expected_records))
    assert all(item == observed[0] for item in observed)


@pytest.mark.parametrize("seed,exit_code,status,records", [
    (2026110500, 0, "SUPPORTED", 17),
    (2026110506, 1, "UNSUPPORTED", 26),
])
def test_validate_all_passes_seed_to_fresh_category_subprocesses(
    tmp_path, seed, exit_code, status, records,
):
    observed = []
    for repeat in range(2):
        root = tmp_path / str(repeat)
        scope = root / "scope"
        proc = invoke(root, "--validate-all-assumptions", "--seed", seed,
                      "--scope-dir", scope)
        assert proc.returncode == exit_code, proc.stdout + proc.stderr
        observed.append(fingerprint(scope / "shenron_identity.jsonl", status, records))
    assert observed[0] == observed[1]

    if exit_code == 1:
        # A positive seed must never launder existing negative evidence.
        artifact = scope / "shenron_identity.jsonl"
        original = artifact.read_bytes()
        proc = invoke(root, "--validate-all-assumptions", "--seed", 2026110500,
                      "--no-rerun", "--scope-dir", scope)
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert artifact.read_bytes() == original
