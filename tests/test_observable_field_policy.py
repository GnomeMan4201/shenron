"""Rules in converted folders must detect observables, not simulator labels."""
import json
import tempfile
from pathlib import Path

import pytest
import yaml

from core.sigma.fields import (
    LABEL_FIELDS, OBSERVABLE_ONLY_RULE_DIRS, detection_fields, get_path,
)
from core.mutation.sigma_aware import SigmaAwareMutator

RULES = Path(__file__).resolve().parent.parent / "sigma" / "rules"
CONVERTED = sorted(
    p for d in OBSERVABLE_ONLY_RULE_DIRS for p in (RULES / d).rglob("*.yml")
)


def test_converted_folders_have_rules():
    assert CONVERTED, "OBSERVABLE_ONLY_RULE_DIRS lists folders with no rules"


@pytest.mark.parametrize("rule_path", CONVERTED, ids=lambda p: p.name)
def test_rule_uses_no_label_fields(rule_path):
    rule = yaml.safe_load(rule_path.read_text())
    used = {f.split(".")[0] for f in detection_fields(rule)}
    leaked = used & LABEL_FIELDS
    assert not leaked, f"{rule_path.name} keys on label fields {sorted(leaked)}"


@pytest.mark.parametrize("rule_path", CONVERTED, ids=lambda p: p.name)
def test_mutator_targets_every_detection_field(rule_path):
    # Every field the rule detects on must be one the mutator can attack;
    # otherwise the rule looks durable only because it is out of reach.
    rule = yaml.safe_load(rule_path.read_text())
    mutator = SigmaAwareMutator(str(rule_path))
    for field in detection_fields(rule):
        assert field in mutator.targets, f"{field} is not a mutation target"
        assert field.split(".")[0] not in mutator.PROTECTED_FIELDS


def test_dotted_paths_mutate_nested_values():
    rule = RULES / "c2" / "shenron_beacon.yml"
    mutator = SigmaAwareMutator(str(rule))
    event = {"beacon_interval_sim": 60.0, "beacon_data": {"method": "http_get"}}
    out = mutator.mutate_targeted(event, "field_omit")
    assert get_path(out, "beacon_data.method") is None
    assert "beacon_interval_sim" not in out
    assert event["beacon_data"]["method"] == "http_get"  # input untouched


DEMO_EVENTS = RULES.parent.parent / "artifacts" / "demo" / "shenron_demo_run.jsonl"


@pytest.mark.parametrize("rule_path", CONVERTED, ids=lambda p: p.name)
def test_rule_fires_with_simulator_labels_stripped(rule_path):
    """Hold the event evidence constant and remove every label field.

    A rule that detects behavior must fire on the same events whether or not
    the simulator labelled them. Rules that key on labels drop to zero here.
    """
    from core.sigma.evaluator import evaluate_sigma_rule
    from core.sigma.model import RuleVerdict

    events = [json.loads(line) for line in DEMO_EVENTS.read_text().splitlines() if line.strip()]
    stripped = [{k: v for k, v in e.items() if k not in LABEL_FIELDS} for e in events]

    def matched(path):
        r = evaluate_sigma_rule(str(rule_path), str(path), match_mode="strict")
        return r.verdict == RuleVerdict.TRIGGERED, r.triggered_count

    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        f.write("\n".join(json.dumps(e) for e in stripped) + "\n")
        stripped_path = f.name
    try:
        labelled, stripped_result = matched(DEMO_EVENTS), matched(stripped_path)
    finally:
        Path(stripped_path).unlink()

    assert labelled[0], f"{rule_path.name} should fire on the demo events"
    assert stripped_result == labelled, (
        f"{rule_path.name} fired {labelled[1]}x with labels, {stripped_result[1]}x without"
    )
