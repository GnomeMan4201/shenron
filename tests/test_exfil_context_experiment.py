#!/usr/bin/env python3
"""Pins the outcome of research/exfil_context.py (docs/EXFIL_CONTEXT_EXPERIMENT.md).

If a change to the bridge, the generator or the fixtures alters the result,
this fails and the write-up must be revisited, not silently left stale.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "research"))
import exfil_context as X  # noqa: E402


@pytest.fixture(scope="module")
def outcome():
    results, positives, negatives = X.run()
    return results, positives, X.run_round2(results, positives)


def test_every_candidate_detects_all_generator_transfers(outcome):
    results, positives, _ = outcome
    assert all(tp == len(positives) for _, _, tp, _, _ in results)


def test_no_single_field_separates(outcome):
    results, _, _ = outcome
    singles = {label: fps for label, names, _, _, fps in results if len(names) == 1}
    assert singles and all(fps for fps in singles.values())


def test_round_one_survivors_are_all_pairs(outcome):
    results, positives, _ = outcome
    survivors = {names for _, names, tp, n, fps in results if tp == n and not fps}
    assert survivors and all(len(names) == 2 for names in survivors)


def test_every_round_one_survivor_breaks_in_round_two(outcome):
    _, _, round2 = outcome
    assert round2 and all(fps for _, fps in round2)
