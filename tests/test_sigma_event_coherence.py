# Purpose: Sigma per-event condition and fallback regressions; Python 3.10+; requires pytest, PyYAML, Shenron; pySigma optional. [a-Shell ok]
import json
import uuid

import pytest

from core.sigma.evaluator import evaluate_sigma_rule
from core.sigma.model import RuleVerdict

A = {"artifact_id": "A", "phase": "OBSERVE", "behavior_class": "idle_sim", "simulation_only": True}
B = {"artifact_id": "B", "phase": "ADAPT", "behavior_class": "marker_sim", "simulation_only": True}
AB = {"artifact_id": "AB", "phase": "OBSERVE", "behavior_class": "marker_sim", "simulation_only": True}

CASES = [
    ("split_AND", "selection_phase and selection_behavior", [A, B], RuleVerdict.NOT_TRIGGERED, 0),
    ("joined_AND", "selection_phase and selection_behavior", [AB], RuleVerdict.TRIGGERED, 1),
    ("only_A_AND", "selection_phase and selection_behavior", [A], RuleVerdict.NOT_TRIGGERED, 0),
    ("only_B_AND", "selection_phase and selection_behavior", [B], RuleVerdict.NOT_TRIGGERED, 0),
    ("split_OR", "selection_phase or selection_behavior", [A, B], RuleVerdict.TRIGGERED, 2),
    ("duplicate_AB", "selection_phase and selection_behavior", [AB, dict(AB)], RuleVerdict.TRIGGERED, 2),
    ("split_ALL", "all of selection_*", [A, B], RuleVerdict.NOT_TRIGGERED, 0),
    ("joined_ALL", "all of selection_*", [AB], RuleVerdict.TRIGGERED, 1),
    ("one_of", "1 of selection_*", [A, B], RuleVerdict.TRIGGERED, 2),
    ("not_A", "selection_phase and not selection_behavior", [A], RuleVerdict.TRIGGERED, 1),
    ("not_AB", "selection_phase and not selection_behavior", [AB], RuleVerdict.NOT_TRIGGERED, 0),
]


def _run(tmp_path, condition, events, *, prefer_pysigma):
    rule = tmp_path / "rule.yml"
    artifact = tmp_path / "events.jsonl"
    rule.write_text(
        "title: Event Coherence Test\n"
        f"id: {uuid.UUID('3a89a2a1-eab2-4bbc-a3d0-8d10fa4b66cc')}\n"
        "status: test\n"
        "logsource:\n  category: process_creation\n"
        "detection:\n"
        "  selection_phase:\n    phase: OBSERVE\n"
        "  selection_behavior:\n    behavior_class: marker_sim\n"
        f"  condition: {condition}\n"
        "level: low\n",
        encoding="utf-8",
    )
    artifact.write_text("".join(json.dumps(item) + "\n" for item in events), encoding="utf-8")
    return evaluate_sigma_rule(rule, artifact, match_mode="strict", prefer_pysigma=prefer_pysigma)


@pytest.mark.parametrize("name,condition,events,expected,count", CASES, ids=[c[0] for c in CASES])
@pytest.mark.parametrize("backend", ["forced_custom", "forced_fallback", "pysigma_if_available"])
def test_rule_respects_event_coherence(tmp_path, monkeypatch, name, condition, events, expected, count, backend):
    from core.sigma import pysigma_bridge
    if backend == "forced_fallback":
        monkeypatch.setattr(pysigma_bridge, "pysigma_available", lambda: False)
    elif backend == "pysigma_if_available" and not pysigma_bridge.pysigma_available():
        pytest.skip("pySigma is not installed")

    result = _run(tmp_path, condition, events, prefer_pysigma=backend != "forced_custom")
    assert result.verdict == expected, (name, backend, result.coverage_note)
    assert result.triggered_count == count, (name, backend)
    if backend == "pysigma_if_available":
        assert result.coverage_note.startswith("[pySigma]"), "Unexpected fallback to custom evaluator"
    else:
        assert not result.coverage_note.startswith("[pySigma]"), "Expected custom evaluator"


@pytest.mark.parametrize("backend", ["forced_custom", "forced_fallback"])
def test_invalid_condition_fails_closed(tmp_path, monkeypatch, backend):
    # Extra trailing tokens used to be silently ignored or reduced to OR.
    if backend == "forced_fallback":
        from core.sigma import pysigma_bridge
        monkeypatch.setattr(pysigma_bridge, "pysigma_available", lambda: False)
    result = _run(
        tmp_path, "selection_phase and selection_behavior EXTRA", [AB],
        prefer_pysigma=backend != "forced_custom",
    )
    assert result.verdict == RuleVerdict.ERROR
    assert result.triggered_count == 0
    assert "parse failed" in result.coverage_note
