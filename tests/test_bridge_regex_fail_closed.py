#!/usr/bin/env python3
"""The |re modifier must match, and a bridge crash must never become a miss.

Before this fix, every `|re` rule crashed inside the pySigma bridge
(the pattern arrived as a SigmaString), and evaluate_sigma_rule swallowed
the exception and fell back to an evaluator that does not understand
modifiers, reporting NOT_TRIGGERED: a silent fail-open.
"""
import json
from pathlib import Path

import pytest

from core.sigma.evaluator import evaluate_sigma_rule
from core.sigma.model import RuleVerdict

RULE = """\
title: regex probe
id: 11111111-2222-3333-4444-555555555555
status: experimental
logsource:
    product: shenron
    category: simulation
detection:
    selection:
        uptime_sim|re: '^[0-9](\\\\.[0-9]+)?$'
    condition: selection
level: low
"""


def _evaluate(tmp_path, event, rule=RULE):
    rule_path = tmp_path / "rule.yml"
    rule_path.write_text(rule)
    art = tmp_path / "events.jsonl"
    art.write_text(json.dumps(event) + "\n")
    return evaluate_sigma_rule(str(rule_path), str(art), match_mode="strict")


def test_regex_matches(tmp_path):
    result = _evaluate(tmp_path, {"uptime_sim": 3.2})
    assert result.verdict == RuleVerdict.TRIGGERED


def test_regex_non_match(tmp_path):
    result = _evaluate(tmp_path, {"uptime_sim": 42.0})
    assert result.verdict == RuleVerdict.NOT_TRIGGERED


def test_bridge_crash_is_error_not_miss(tmp_path, monkeypatch):
    import core.sigma.pysigma_bridge as bridge

    def boom(*args, **kwargs):
        raise TypeError("simulated bridge failure")

    monkeypatch.setattr(bridge, "_match_sigma_value", boom)
    result = _evaluate(tmp_path, {"uptime_sim": 3.2})
    assert result.verdict == RuleVerdict.ERROR
