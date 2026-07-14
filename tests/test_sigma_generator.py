"""
tests/test_sigma_generator.py

Tests for core/sigma/generator.py — SHENRON Sigma Rule Generator.
All tests are read-only and use the committed demo artifact.
"""
import json
import os
import tempfile
from pathlib import Path
import pytest

# Ensure repo root is on path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.sigma.generator import (
    generate_rules,
    _load_artifact,
    _group_by_layer,
    _extract_signal_vocabulary,
    _confidence_from_vocab,
    _build_sigma_yaml,
    _validate_rule,
    _get_tactic,
    _get_attack_tags,
    GeneratedRule,
    GenerationReport,
)

DEMO_ARTIFACT = Path(__file__).parent.parent / "artifacts" / "demo" / "shenron_demo_run.jsonl"
MANIFEST_PATH = Path(__file__).parent.parent / "shenron_manifest.json"


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def demo_events():
    return _load_artifact(str(DEMO_ARTIFACT))


@pytest.fixture
def demo_by_layer(demo_events):
    return _group_by_layer(demo_events)


@pytest.fixture
def beacon_vocab(demo_by_layer):
    events = demo_by_layer.get("beacon_emitter_cloak", [])
    return _extract_signal_vocabulary(events)


# ── Artifact loading ───────────────────────────────────────────────────────────

def test_load_artifact_returns_list(demo_events):
    assert isinstance(demo_events, list)
    assert len(demo_events) > 0


def test_load_artifact_all_dicts(demo_events):
    assert all(isinstance(e, dict) for e in demo_events)


def test_load_artifact_nonexistent_raises():
    with pytest.raises(FileNotFoundError):
        _load_artifact("/nonexistent/path/artifact.jsonl")


# ── Layer grouping ─────────────────────────────────────────────────────────────

def test_group_by_layer_returns_dict(demo_events):
    groups = _group_by_layer(demo_events)
    assert isinstance(groups, dict)


def test_group_by_layer_nonempty(demo_events):
    groups = _group_by_layer(demo_events)
    assert len(groups) > 0


def test_group_by_layer_all_lists(demo_events):
    groups = _group_by_layer(demo_events)
    assert all(isinstance(v, list) for v in groups.values())


def test_group_by_layer_events_sum(demo_events):
    groups = _group_by_layer(demo_events)
    total = sum(len(v) for v in groups.values())
    assert total == len(demo_events)


# ── Vocabulary extraction ──────────────────────────────────────────────────────

def test_extract_vocab_returns_dict(beacon_vocab):
    assert isinstance(beacon_vocab, dict)


def test_extract_vocab_has_required_keys(beacon_vocab):
    required = {"behavior_classes", "detection_opportunities", "mitre_techniques", "phases", "layer"}
    assert required.issubset(beacon_vocab.keys())


def test_extract_vocab_techniques_are_strings(beacon_vocab):
    assert all(isinstance(t, str) for t in beacon_vocab["mitre_techniques"])


def test_extract_vocab_detection_opps_are_strings(beacon_vocab):
    assert all(isinstance(o, str) for o in beacon_vocab["detection_opportunities"])


def test_extract_vocab_layer_is_string(beacon_vocab):
    assert isinstance(beacon_vocab["layer"], str)


def test_extract_vocab_nonempty_for_beacon(beacon_vocab):
    assert len(beacon_vocab["mitre_techniques"]) > 0 or len(beacon_vocab["behavior_classes"]) > 0


# ── Confidence scoring ─────────────────────────────────────────────────────────

def test_confidence_high_rich_vocab():
    vocab = {
        "detection_opportunities": ["a", "b", "c", "d"],
        "behavior_classes": ["x", "y"],
        "mitre_techniques": ["T1071", "T1132"],
    }
    assert _confidence_from_vocab(vocab) == "HIGH"


def test_confidence_medium():
    vocab = {
        "detection_opportunities": ["a"],
        "behavior_classes": ["x"],
        "mitre_techniques": ["T1071"],
    }
    assert _confidence_from_vocab(vocab) in ("MEDIUM", "HIGH")


def test_confidence_low_empty_vocab():
    vocab = {
        "detection_opportunities": [],
        "behavior_classes": [],
        "mitre_techniques": [],
    }
    assert _confidence_from_vocab(vocab) == "LOW"


# ── Tactic mapping ─────────────────────────────────────────────────────────────

def test_get_tactic_known():
    assert _get_tactic("T1071") == "command-and-control"
    assert _get_tactic("T1053") == "persistence"
    assert _get_tactic("T1055") == "privilege-escalation"


def test_get_tactic_unknown_returns_default():
    result = _get_tactic("T9999")
    assert isinstance(result, str)
    assert len(result) > 0


def test_get_attack_tags_format():
    tags = _get_attack_tags(["T1071", "T1053"])
    assert any("attack.t1071" in t for t in tags)
    assert any("attack.t1053" in t for t in tags)
    assert any("command-and-control" in t for t in tags)


# ── Sigma YAML assembly ────────────────────────────────────────────────────────

def test_build_sigma_yaml_returns_string(beacon_vocab):
    yaml_str = _build_sigma_yaml(
        rule_id="test-001",
        title="Test Rule",
        description="Test description",
        layer="beacon_emitter_cloak",
        vocab=beacon_vocab,
        manifest_entry=None,
        generated_at="2026-06-25T00:00:00+00:00",
    )
    assert isinstance(yaml_str, str)
    assert len(yaml_str) > 0


def test_build_sigma_yaml_has_required_fields(beacon_vocab):
    yaml_str = _build_sigma_yaml(
        rule_id="test-001",
        title="Test Rule",
        description="Test description",
        layer="beacon_emitter_cloak",
        vocab=beacon_vocab,
        manifest_entry=None,
        generated_at="2026-06-25T00:00:00+00:00",
    )
    assert "title:" in yaml_str
    assert "detection:" in yaml_str
    assert "condition:" in yaml_str
    assert "falsepositives:" in yaml_str
    assert "logsource:" in yaml_str


def test_build_sigma_yaml_contains_layer(beacon_vocab):
    yaml_str = _build_sigma_yaml(
        rule_id="test-001",
        title="Test Rule",
        description="Test description",
        layer="beacon_emitter_cloak",
        vocab=beacon_vocab,
        manifest_entry=None,
        generated_at="2026-06-25T00:00:00+00:00",
    )
    assert "beacon_emitter_cloak" in yaml_str


def test_build_sigma_yaml_contains_techniques(beacon_vocab):
    if not beacon_vocab["mitre_techniques"]:
        pytest.skip("No techniques in beacon vocab")
    yaml_str = _build_sigma_yaml(
        rule_id="test-001",
        title="Test Rule",
        description="Test description",
        layer="beacon_emitter_cloak",
        vocab=beacon_vocab,
        manifest_entry=None,
        generated_at="2026-06-25T00:00:00+00:00",
    )
    assert any(t in yaml_str for t in beacon_vocab["mitre_techniques"])


# ── Rule validation ────────────────────────────────────────────────────────────

def test_validate_rule_returns_string(beacon_vocab):
    yaml_str = _build_sigma_yaml(
        rule_id="test-001",
        title="Test Rule",
        description="Test",
        layer="beacon_emitter_cloak",
        vocab=beacon_vocab,
        manifest_entry=None,
        generated_at="2026-06-25T00:00:00+00:00",
    )
    verdict = _validate_rule(yaml_str, str(DEMO_ARTIFACT))
    assert isinstance(verdict, str)
    assert verdict in ("TRIGGERED", "PARTIAL", "NOT_TRIGGERED", "UNSUPPORTED") or verdict.startswith("ERROR")


def test_validate_rule_cleans_up_tempfile(beacon_vocab):
    import glob
    before = set(glob.glob("/tmp/*.yml"))
    yaml_str = _build_sigma_yaml(
        rule_id="test-001",
        title="Test Rule",
        description="Test",
        layer="beacon_emitter_cloak",
        vocab=beacon_vocab,
        manifest_entry=None,
        generated_at="2026-06-25T00:00:00+00:00",
    )
    _validate_rule(yaml_str, str(DEMO_ARTIFACT))
    after = set(glob.glob("/tmp/*.yml"))
    assert after == before


# ── Full generation pipeline ───────────────────────────────────────────────────

def test_generate_rules_returns_report():
    with tempfile.TemporaryDirectory() as tmpdir:
        report = generate_rules(
            artifact_path=str(DEMO_ARTIFACT),
            output_dir=tmpdir,
            manifest_path=str(MANIFEST_PATH),
            validate=False,
            verbose=False,
        )
    assert isinstance(report, GenerationReport)


def test_generate_rules_produces_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        report = generate_rules(
            artifact_path=str(DEMO_ARTIFACT),
            output_dir=tmpdir,
            manifest_path=str(MANIFEST_PATH),
            validate=False,
            verbose=False,
        )
        yml_files = list(Path(tmpdir).glob("*.yml"))
    assert len(yml_files) > 0


def test_generate_rules_report_counts_consistent():
    with tempfile.TemporaryDirectory() as tmpdir:
        report = generate_rules(
            artifact_path=str(DEMO_ARTIFACT),
            output_dir=tmpdir,
            manifest_path=str(MANIFEST_PATH),
            validate=False,
            verbose=False,
        )
    assert report.rules_generated == len(report.rules)


def test_generate_rules_with_validation():
    with tempfile.TemporaryDirectory() as tmpdir:
        report = generate_rules(
            artifact_path=str(DEMO_ARTIFACT),
            output_dir=tmpdir,
            manifest_path=str(MANIFEST_PATH),
            validate=True,
            verbose=False,
        )
    assert report.rules_validated_triggered > 0


def test_generate_rules_triggered_plus_partial_plus_not_consistent():
    with tempfile.TemporaryDirectory() as tmpdir:
        report = generate_rules(
            artifact_path=str(DEMO_ARTIFACT),
            output_dir=tmpdir,
            manifest_path=str(MANIFEST_PATH),
            validate=True,
            verbose=False,
        )
    accounted = (
        report.rules_validated_triggered
        + report.rules_validated_partial
        + report.rules_not_triggered
    )
    assert accounted <= report.rules_generated


def test_generate_rules_min_confidence_high():
    with tempfile.TemporaryDirectory() as tmpdir:
        report = generate_rules(
            artifact_path=str(DEMO_ARTIFACT),
            output_dir=tmpdir,
            manifest_path=str(MANIFEST_PATH),
            validate=False,
            min_confidence="HIGH",
            verbose=False,
        )
    assert all(r.confidence == "HIGH" for r in report.rules)


def test_generate_rules_all_rules_have_layer():
    with tempfile.TemporaryDirectory() as tmpdir:
        report = generate_rules(
            artifact_path=str(DEMO_ARTIFACT),
            output_dir=tmpdir,
            manifest_path=str(MANIFEST_PATH),
            validate=False,
            verbose=False,
        )
    assert all(r.layer for r in report.rules)


def test_generate_rules_all_rules_have_id():
    with tempfile.TemporaryDirectory() as tmpdir:
        report = generate_rules(
            artifact_path=str(DEMO_ARTIFACT),
            output_dir=tmpdir,
            manifest_path=str(MANIFEST_PATH),
            validate=False,
            verbose=False,
        )
    assert all(r.rule_id for r in report.rules)


def test_generate_rules_to_dict():
    with tempfile.TemporaryDirectory() as tmpdir:
        report = generate_rules(
            artifact_path=str(DEMO_ARTIFACT),
            output_dir=tmpdir,
            manifest_path=str(MANIFEST_PATH),
            validate=False,
            verbose=False,
        )
    d = report.to_dict()
    assert "rules" in d
    assert "rules_generated" in d
    assert isinstance(d["rules"], list)


def test_generate_rules_to_markdown():
    with tempfile.TemporaryDirectory() as tmpdir:
        report = generate_rules(
            artifact_path=str(DEMO_ARTIFACT),
            output_dir=tmpdir,
            manifest_path=str(MANIFEST_PATH),
            validate=False,
            verbose=False,
        )
    md = report.to_markdown()
    assert "SHENRON Sigma Rule Generation Report" in md
    assert "| Title |" in md
