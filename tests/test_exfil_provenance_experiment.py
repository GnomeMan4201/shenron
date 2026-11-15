#!/usr/bin/env python3
"""Pins the outcome of research/exfil_provenance.py (docs/EXFIL_PROVENANCE_EXPERIMENT.md)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "research"))
import exfil_provenance as P  # noqa: E402


def test_round_one_every_predicate_separates_the_twin():
    r1, _, _ = P.run()
    assert all(e and not t for e, t in r1.values())


def test_round_two_relationship_preserving_cases_fire():
    _, r2, _ = P.run()
    assert len(r2["provenance"]) == len(P.PRESERVING)
    assert len(r2["lineage + provenance"]) == 3
    assert "full-system backup includes /etc/shadow" not in r2["lineage + provenance"]


def test_round_three_attacker_evades_the_combined_predicate():
    _, _, r3 = P.run()
    assert len(r3["lineage + provenance"]) == len(P.ATTACKER)


def test_every_case_has_the_identical_network_transfer():
    cases = [P.EXFIL, P.TWIN, *P.PRESERVING, *P.ATTACKER]
    sends = [{k: v for k, v in c.events()[-1].items() if k != "process_id_sim"} for c in cases]
    assert all(s == sends[0] for s in sends)


def test_information_limit_identical_histories():
    """Same input, different authorization: any event-only detector is wrong on one."""
    import hashlib
    import json

    arbitrary = {
        "always alert": lambda evs: True,
        "never alert": lambda evs: False,
        "hash of the input": lambda evs: hashlib.sha256(json.dumps(evs).encode()).digest()[0] % 2 == 0,
        **P.PREDICATES,
    }
    identical, rows = P.information_limit(arbitrary)
    assert identical
    for name, (verdicts, correct) in rows.items():
        assert len(set(verdicts.values())) == 1, name
        assert correct == 1, name
