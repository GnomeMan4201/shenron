#!/usr/bin/env python3
"""Pins the outcome of research/exfil_sequence.py (docs/EXFIL_SEQUENCE_EXPERIMENT.md)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "research"))
import exfil_sequence as S  # noqa: E402


@pytest.fixture(scope="module")
def outcome():
    return S.run()[:5]


def test_full_pattern_separates_round_one(outcome):
    positives, table, _, _, _ = outcome
    full = dict((name, (tp, fps)) for name, tp, _, fps in table)["full pattern"]
    assert full == (len(positives), [])


def test_same_port_and_loopback_carry_the_signal(outcome):
    _, table, _, _, _ = outcome
    fps = {name: fps for name, _, _, fps in table}
    assert fps["without same-port link"] and fps["without loopback exclusion"]
    assert not fps["without one-shot listener check"] and not fps["without port release"]


def test_hole_punch_breaks_full_pattern(outcome):
    _, _, round2, _, _ = outcome
    assert round2 == ["UDP hole punch: one-shot socket, peer on the same port"]


def test_attacker_variation(outcome):
    positives, _, _, evasions, minimal_fps = outcome
    n = len(positives)
    assert set(evasions["full pattern"].values()) == {n}
    minimal = evasions["minimal: same port + non-loopback"]
    assert minimal["sends to 443 instead of the listener port"] == n
    assert minimal["keeps the port open (no release)"] == 0
    assert minimal["listener backlog 5 instead of 1"] == 0
    assert "Syncthing: persistent listener, peers on the same port" in minimal_fps


def test_round_three_invalidates_the_pattern():
    """Routine same-port protocols with the same timing defeat the pattern."""
    positives, _, _, _, _, round3, low_port_evasion = S.run()
    assert len(round3["full pattern"]) == len(S.SYMMETRIC)
    assert round3["full pattern, ephemeral ports only"]
    assert low_port_evasion == len(positives)
