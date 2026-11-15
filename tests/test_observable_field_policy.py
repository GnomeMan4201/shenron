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



REPO = RULES.parent.parent
DEMO_EVENTS = REPO / "artifacts" / "demo" / "shenron_demo_run.jsonl"
BENIGN_EVENTS = REPO / "artifacts" / "benign_demo.jsonl"

# Ground truth for the tests only: which generator each converted rule is
# meant to detect. Rules never read these labels; the tests use them to
# catch false positives on other generators' events.
INTENDED_LAYERS = {
    "shenron_beacon.yml": {"beacon_emitter_cloak"},
    "shenron_covert_channel.yml": {"covert_socket_relay"},
    "shenron_transient_exfil_shell.yml": {"transient_exfil_sim"},
    "shenron_llm_manipulation.yml": {"llm_prompt_injector", "llm_echo_chamber", "llm_shroud_writer"},
}


@pytest.fixture(scope="module")
def corpus_events(tmp_path_factory):
    """Full generated corpus (every layer), as in test_sigma_integration."""
    import os
    import subprocess
    import sys

    out = tmp_path_factory.mktemp("observable-corpus") / "all-layers.jsonl"
    env = dict(os.environ, SHENRON_SCOPED_LOG=str(out))
    result = subprocess.run(
        [sys.executable, "shenron.py", "run", "all"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=180,
    )
    assert result.returncode == 0 and out.exists(), result.stderr[-2000:]
    return [json.loads(line) for line in out.read_text().splitlines() if line.strip()]


def _load(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def _hits(rule_path, events):
    from core.sigma.evaluator import evaluate_sigma_rule

    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        f.write("".join(json.dumps(e) + "\n" for e in events))
        path = f.name
    try:
        return evaluate_sigma_rule(str(rule_path), path, match_mode="strict").triggered_count
    finally:
        Path(path).unlink()


def _strip(events):
    return [{k: v for k, v in e.items() if k not in LABEL_FIELDS} for e in events]


def test_every_converted_rule_has_intended_layers():
    assert {p.name for p in CONVERTED} == set(INTENDED_LAYERS)


@pytest.mark.parametrize("rule_path", CONVERTED, ids=lambda p: p.name)
def test_rule_fires_with_simulator_labels_stripped(rule_path, corpus_events):
    """Positive control: hold event evidence constant and remove every label.

    A rule that detects behavior fires on the same events whether or not the
    simulator labelled them; a label-keyed rule drops to zero.
    """
    total = 0
    for name, events in (("demo", _load(DEMO_EVENTS)), ("corpus", corpus_events)):
        labelled, stripped = _hits(rule_path, events), _hits(rule_path, _strip(events))
        assert stripped == labelled, f"{rule_path.name} on {name}: {labelled} with labels, {stripped} without"
        total += labelled
    assert total > 0, f"{rule_path.name} never fires on demo or corpus"


@pytest.mark.parametrize("rule_path", CONVERTED, ids=lambda p: p.name)
def test_rule_ignores_benign_events(rule_path):
    """Negative control: benign synthetic activity must not match."""
    assert _hits(rule_path, _load(BENIGN_EVENTS)) == 0


@pytest.mark.parametrize("rule_path", CONVERTED, ids=lambda p: p.name)
def test_rule_matches_only_intended_generators(rule_path, corpus_events):
    """Negative control: no matches on other generators' events."""
    intended = INTENDED_LAYERS[rule_path.name]
    others = [e for e in corpus_events if e.get("layer") not in intended]
    assert _hits(rule_path, others) == 0
