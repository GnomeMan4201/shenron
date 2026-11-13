"""
Malformed Sigma conditions must never yield a match verdict.

Rule under test: an exclusion filter that matches the same synthetic event as
the selection. The correct verdict for `selection and not filter` is therefore
NOT_TRIGGERED. Each malformed variant must produce ERROR on BOTH backends; a
TRIGGERED verdict means the malformed condition silently disabled the filter.
"""
import glob
import json
import textwrap
from pathlib import Path

import pytest
import yaml

from core.sigma.evaluator import evaluate_sigma_rule
from core.sigma.model import RuleVerdict
from core.sigma.pysigma_bridge import BridgeVerdict, _eval_condition, evaluate_with_pysigma

REPO = Path(__file__).resolve().parent.parent

RULE = textwrap.dedent("""\
    title: Condition strictness probe
    id: 6f1c2f0e-1111-4222-8333-944455556666
    status: experimental
    logsource:
      category: shenron_simulation
      product: probe
    detection:
      selection:
        layer: probe_layer
        behavior_class: suspicious_thing
      selection_extra:
        layer: probe_layer
      filter:
        behavior_class: suspicious_thing
      condition: {cond}
    level: high
""")
EVENT = {"artifact_id": "a1", "layer": "probe_layer", "behavior_class": "suspicious_thing",
         "phase": "execution", "simulation_only": True}

MALFORMED = [
    "selection and not filtr",          # typo: undefined name silently became False
    "selection filter",                 # missing operator: trailing token dropped
    "selection and not filter garbage", # trailing garbage
    "selection and not filter )",       # stray close paren
    "( selection and not filter",       # unclosed paren
    "selection and",                    # dangling operator
    "not",                              # missing operand
    "1 of nomatch_*",                   # quantifier target matches no block
    "all of",                           # incomplete quantifier
    "selection | count() > 5",          # unsupported aggregation must not be ignored
]

VALID = [
    ("selection and not filter", RuleVerdict.NOT_TRIGGERED),
    ("selection", RuleVerdict.TRIGGERED),
    ("( selection ) and not filter", RuleVerdict.NOT_TRIGGERED),
    ("1 of selection*", RuleVerdict.TRIGGERED),
    ("all of selection*", RuleVerdict.TRIGGERED),
    ("all of them", RuleVerdict.TRIGGERED),
    ("2 of selection*", RuleVerdict.TRIGGERED),
    ("not filter", RuleVerdict.NOT_TRIGGERED),
]


def _write(tmp_path, cond):
    rule = tmp_path / "rule.yml"
    rule.write_text(RULE.format(cond=cond), encoding="utf-8")
    events = tmp_path / "events.jsonl"
    events.write_text(json.dumps(EVENT) + "\n", encoding="utf-8")
    return rule, events


@pytest.mark.parametrize("prefer_pysigma", [True, False], ids=["pysigma", "custom"])
@pytest.mark.parametrize("cond", MALFORMED)
def test_malformed_condition_is_error_not_match(tmp_path, cond, prefer_pysigma):
    rule, events = _write(tmp_path, cond)
    result = evaluate_sigma_rule(rule, events, prefer_pysigma=prefer_pysigma)
    assert result.verdict == RuleVerdict.ERROR, (cond, result.verdict, result.coverage_note)
    assert result.triggered_count == 0


@pytest.mark.parametrize("prefer_pysigma", [True, False], ids=["pysigma", "custom"])
@pytest.mark.parametrize("cond,expected", VALID)
def test_valid_condition_controls(tmp_path, cond, expected, prefer_pysigma):
    rule, events = _write(tmp_path, cond)
    result = evaluate_sigma_rule(rule, events, prefer_pysigma=prefer_pysigma)
    assert result.verdict == expected, (cond, result.verdict, result.coverage_note)


@pytest.mark.parametrize("cond", MALFORMED)
def test_bridge_never_falls_back_to_or_of_blocks(tmp_path, cond):
    rule, events = _write(tmp_path, cond)
    result = evaluate_with_pysigma(str(rule), str(events))
    assert result.verdict == BridgeVerdict.ERROR, (cond, result.verdict, result.errors)
    assert result.triggered_count == 0 and not result.matched_events


def test_bridge_rejects_malformed_condition_even_without_events(tmp_path):
    rule, events = _write(tmp_path, "selection and not filtr")
    events.write_text("", encoding="utf-8")
    assert evaluate_with_pysigma(str(rule), str(events)).verdict == BridgeVerdict.ERROR


@pytest.mark.parametrize("cond", ["selection and not filtr", "selection filter", "( selection"])
def test_eval_condition_raises_on_malformed(cond):
    names = ["selection", "filter"]
    with pytest.raises(ValueError):
        _eval_condition(cond, {"selection": True, "filter": True}, names)


def _committed_conditions():
    for path in sorted(glob.glob(str(REPO / "sigma" / "rules" / "**" / "*.y*ml"), recursive=True)):
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        detection = doc.get("detection") or {}
        conds = detection.get("condition")
        for cond in conds if isinstance(conds, list) else [conds]:
            names = [k for k in detection if k not in ("condition", "timeframe")]
            yield pytest.param(str(cond), names, id=f"{Path(path).stem}:{cond}")


@pytest.mark.parametrize("cond,names", list(_committed_conditions()))
def test_every_committed_rule_condition_is_strictly_valid(cond, names):
    from core.sigma.evaluator import parse_condition_strict
    parse_condition_strict(cond, names)


@pytest.mark.parametrize("prefer_pysigma", [True, False], ids=["pysigma", "custom"])
@pytest.mark.parametrize("line", ["condition: ''", ""], ids=["empty", "absent"])
def test_missing_or_empty_condition_must_not_or_all_blocks(tmp_path, line, prefer_pysigma):
    # Both the selection and exclusion filter match. The previous no-condition
    # fallback ORs blocks, which turns an incomplete rule into TRIGGERED.
    rule, events = _write(tmp_path, "selection and not filter")
    source = rule.read_text(encoding="utf-8")
    marker = "condition: selection and not filter"
    assert source.count(marker) == 1
    rule.write_text(source.replace(marker, line), encoding="utf-8")
    result = evaluate_sigma_rule(rule, events, prefer_pysigma=prefer_pysigma)
    assert result.verdict == RuleVerdict.ERROR, (
        line, prefer_pysigma, result.verdict, result.coverage_note
    )
    assert result.triggered_count == 0
