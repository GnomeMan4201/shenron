"""
tests/test_benign_generator.py

Tests for core/noise/benign_generator.py — SHENRON Benign Event Generator.
"""
import json
import os
import tempfile
from pathlib import Path
from datetime import datetime, timezone
import pytest
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.noise.benign_generator import (
    generate_benign_events,
    generate_mixed_artifact,
    write_benign_artifact,
    _safe_fields,
    _build_event,
    _sample_template,
    ALL_TEMPLATES,
    CATEGORY_WEIGHTS,
    AUTH_EVENTS,
    NETWORK_EVENTS,
    SYSTEM_EVENTS,
    STORAGE_EVENTS,
    PROCESS_EVENTS,
    HARDWARE_EVENTS,
)
import random

DEMO_ARTIFACT = Path(__file__).parent.parent / "artifacts" / "demo" / "shenron_demo_run.jsonl"


# -- Safety contract -----------------------------------------------------------

def test_safe_fields_returns_dict():
    assert isinstance(_safe_fields(), dict)

def test_safe_fields_simulation_only():
    assert _safe_fields()["simulation_only"] is True

def test_safe_fields_executable_false():
    assert _safe_fields()["executable"] is False

def test_safe_fields_payload_false():
    assert _safe_fields()["payload_present"] is False

def test_safe_fields_no_network():
    assert _safe_fields()["network_connection"] is False


# -- Template catalog ----------------------------------------------------------

def test_all_templates_nonempty():
    assert len(ALL_TEMPLATES) > 0

def test_all_templates_have_required_keys():
    required = {"layer", "behavior_class", "signal", "category",
                "description", "detection_opportunities", "mitre_techniques"}
    for t in ALL_TEMPLATES:
        assert required.issubset(t.keys()), f"Missing keys in {t}"

def test_all_templates_benign_mitre():
    for t in ALL_TEMPLATES:
        assert t["mitre_techniques"] == [], f"Benign template has MITRE: {t}"

def test_all_templates_benign_detection_opps():
    for t in ALL_TEMPLATES:
        assert t["detection_opportunities"] == [], f"Benign template has opps: {t}"

def test_category_weights_sum_to_one():
    total = sum(CATEGORY_WEIGHTS.values())
    assert abs(total - 1.0) < 0.001

def test_all_categories_in_templates():
    template_cats = {t["category"] for t in ALL_TEMPLATES}
    for cat in CATEGORY_WEIGHTS:
        assert cat in template_cats


# -- Event building ------------------------------------------------------------

def test_build_event_returns_dict():
    rng = random.Random(42)
    ts = datetime.now(timezone.utc)
    ev = _build_event(ALL_TEMPLATES[0], "run-001", ts, rng)
    assert isinstance(ev, dict)

def test_build_event_required_fields():
    rng = random.Random(42)
    ts = datetime.now(timezone.utc)
    ev = _build_event(ALL_TEMPLATES[0], "run-001", ts, rng)
    required = {"artifact_id", "run_id", "session_id", "layer", "phase",
                "behavior_class", "simulation_only", "safety", "benign",
                "detection_opportunities", "mitre_techniques", "timestamp"}
    assert required.issubset(ev.keys())

def test_build_event_simulation_only():
    rng = random.Random(42)
    ev = _build_event(ALL_TEMPLATES[0], "run-001", datetime.now(timezone.utc), rng)
    assert ev["simulation_only"] is True

def test_build_event_benign_flag():
    rng = random.Random(42)
    ev = _build_event(ALL_TEMPLATES[0], "run-001", datetime.now(timezone.utc), rng)
    assert ev["benign"] is True

def test_build_event_no_mitre():
    rng = random.Random(42)
    ev = _build_event(ALL_TEMPLATES[0], "run-001", datetime.now(timezone.utc), rng)
    assert ev["mitre_techniques"] == []

def test_build_event_entropy_in_range():
    rng = random.Random(42)
    ev = _build_event(ALL_TEMPLATES[0], "run-001", datetime.now(timezone.utc), rng)
    assert 0.0 <= ev["entropy"] <= 10.0

def test_build_event_safety_contract():
    rng = random.Random(42)
    ev = _build_event(ALL_TEMPLATES[0], "run-001", datetime.now(timezone.utc), rng)
    safety = ev["safety"]
    assert safety["simulation_only"] is True
    assert safety["executable"] is False
    assert safety["payload_present"] is False


# -- Template sampling ---------------------------------------------------------

def test_sample_template_returns_dict():
    rng = random.Random(42)
    t = _sample_template(rng)
    assert isinstance(t, dict)

def test_sample_template_from_known_pool():
    rng = random.Random(42)
    for _ in range(20):
        t = _sample_template(rng)
        assert t in ALL_TEMPLATES

def test_sample_template_respects_weights():
    rng = random.Random(42)
    cats = [_sample_template(rng)["category"] for _ in range(200)]
    from collections import Counter
    counts = Counter(cats)
    # system should be most common (weight 0.30)
    assert counts["system"] > counts["hardware"]


# -- Generation ----------------------------------------------------------------

def test_generate_benign_events_count():
    events = generate_benign_events(n=20, seed=42)
    assert len(events) == 20

def test_generate_benign_events_zero():
    events = generate_benign_events(n=0, seed=42)
    assert events == []

def test_generate_benign_events_deterministic():
    fixed_ts = datetime(2026, 6, 25, 0, 0, 0, tzinfo=timezone.utc)
    e1 = generate_benign_events(n=10, seed=99, base_timestamp=fixed_ts)
    e2 = generate_benign_events(n=10, seed=99, base_timestamp=fixed_ts)
    assert e1 == e2

def test_generate_benign_events_different_seeds():
    e1 = generate_benign_events(n=10, seed=1)
    e2 = generate_benign_events(n=10, seed=2)
    assert e1 != e2

def test_generate_benign_events_schema():
    events = generate_benign_events(n=10, seed=42)
    required = {"artifact_id", "layer", "phase", "behavior_class",
                "simulation_only", "safety", "benign", "timestamp"}
    for ev in events:
        assert required.issubset(ev.keys())

def test_generate_benign_events_all_simulation_only():
    events = generate_benign_events(n=50, seed=42)
    assert all(ev["simulation_only"] is True for ev in events)

def test_generate_benign_events_no_mitre():
    events = generate_benign_events(n=50, seed=42)
    assert all(ev["mitre_techniques"] == [] for ev in events)

def test_generate_benign_events_no_detection_opps():
    events = generate_benign_events(n=50, seed=42)
    assert all(ev["detection_opportunities"] == [] for ev in events)

def test_generate_benign_events_all_benign_flag():
    events = generate_benign_events(n=50, seed=42)
    assert all(ev["benign"] is True for ev in events)

def test_generate_benign_events_unique_artifact_ids():
    events = generate_benign_events(n=50, seed=42)
    ids = [ev["artifact_id"] for ev in events]
    assert len(ids) == len(set(ids))

def test_generate_benign_events_timestamps_advancing():
    events = generate_benign_events(n=10, seed=42)
    timestamps = [ev["timestamp"] for ev in events]
    assert timestamps == sorted(timestamps)

def test_generate_benign_events_category_coverage():
    events = generate_benign_events(n=200, seed=42)
    cats = {ev["category"] for ev in events}
    assert "authentication" in cats
    assert "network" in cats
    assert "system" in cats


# -- Mixed artifact ------------------------------------------------------------

def test_generate_mixed_artifact_basic():
    campaign = [{"layer": "beacon", "benign": False, "simulation_only": True,
                 "timestamp": "2026-06-25T00:00:00+00:00"}]
    mixed = generate_mixed_artifact(campaign, noise_ratio=0.4, seed=42)
    assert len(mixed) > len(campaign)

def test_generate_mixed_artifact_contains_campaign():
    campaign = [{"layer": "beacon", "benign": False, "simulation_only": True,
                 "timestamp": "2026-06-25T00:00:00+00:00"}]
    mixed = generate_mixed_artifact(campaign, noise_ratio=0.4, seed=42)
    adversarial = [e for e in mixed if not e.get("benign")]
    assert len(adversarial) == len(campaign)

def test_generate_mixed_artifact_has_benign():
    campaign = [{"layer": "beacon", "benign": False, "simulation_only": True,
                 "timestamp": "2026-06-25T00:00:00+00:00"}] * 10
    mixed = generate_mixed_artifact(campaign, noise_ratio=0.4, seed=42)
    benign = [e for e in mixed if e.get("benign")]
    assert len(benign) > 0

def test_generate_mixed_artifact_deterministic():
    campaign = [{"layer": "beacon", "benign": False, "simulation_only": True,
                 "timestamp": "2026-06-25T00:00:00+00:00"}] * 5
    m1 = generate_mixed_artifact(campaign, seed=42)
    m2 = generate_mixed_artifact(campaign, seed=42)
    assert m1 == m2

def test_generate_mixed_artifact_with_demo():
    with open(DEMO_ARTIFACT) as f:
        campaign = [json.loads(l) for l in f if l.strip()]
    mixed = generate_mixed_artifact(campaign, noise_ratio=0.4, seed=42)
    adversarial = sum(1 for e in mixed if not e.get("benign"))
    benign = sum(1 for e in mixed if e.get("benign"))
    assert adversarial == len(campaign)
    assert benign > 0
    assert len(mixed) == adversarial + benign


# -- Write artifact ------------------------------------------------------------

def test_write_benign_artifact_creates_file():
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/test_noise.jsonl"
        write_benign_artifact(10, path, seed=42, verbose=False)
        assert Path(path).exists()

def test_write_benign_artifact_valid_jsonl():
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/test_noise.jsonl"
        write_benign_artifact(10, path, seed=42, verbose=False)
        with open(path) as f:
            lines = [json.loads(l) for l in f if l.strip()]
        assert len(lines) == 10

def test_write_benign_artifact_returns_summary():
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/test_noise.jsonl"
        summary = write_benign_artifact(10, path, seed=42, verbose=False)
        assert "events_written" in summary
        assert "by_category" in summary
        assert summary["events_written"] == 10

def test_write_benign_artifact_creates_parent_dirs():
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/nested/deep/noise.jsonl"
        write_benign_artifact(5, path, seed=42, verbose=False)
        assert Path(path).exists()
