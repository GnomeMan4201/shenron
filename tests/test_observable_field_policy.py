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
