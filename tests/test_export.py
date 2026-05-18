# tests/test_export.py
import json
import tempfile
from pathlib import Path
from core.formats.adapter import (
    to_ecs, to_splunk_hec,
    write_ecs_array, write_ecs_bulk, write_splunk_hec,
)

DEMO = "artifacts/demo/shenron_demo_run.jsonl"

def _load():
    with open(DEMO) as f:
        return [json.loads(l) for l in f if l.strip()]


# ── to_ecs unit tests ─────────────────────────────────────────────────────────

def test_to_ecs_required_fields():
    events = _load()
    ecs = to_ecs(events[0])
    for field in ["@timestamp", "event.kind", "event.category", "event.type",
                  "event.dataset", "message", "threat.framework",
                  "labels.simulation_only", "labels.executable",
                  "labels.no_payload_present", "labels.shenron_layer",
                  "observer.name"]:
        assert field in ecs, f"Missing ECS field: {field}"


def test_to_ecs_safety_contract():
    events = _load()
    for e in events:
        ecs = to_ecs(e)
        assert ecs["labels.simulation_only"] is True
        assert ecs["labels.executable"] is False


def test_to_ecs_mitre_techniques():
    events = _load()
    # Find an event with known techniques
    e = next(ev for ev in events if ev.get("mitre_techniques"))
    ecs = to_ecs(e)
    assert isinstance(ecs["threat.technique.id"], list)
    assert len(ecs["threat.technique.id"]) > 0
    assert ecs["threat.technique.id"] == e["mitre_techniques"]


def test_to_ecs_message_contains_synthetic():
    events = _load()
    for e in events:
        ecs = to_ecs(e)
        assert "SHENRON SYNTHETIC" in ecs["message"]


# ── to_splunk_hec unit tests ──────────────────────────────────────────────────

def test_to_splunk_hec_structure():
    events = _load()
    hec = to_splunk_hec(events[0])
    for field in ["time", "host", "source", "sourcetype", "index", "event"]:
        assert field in hec, f"Missing HEC field: {field}"


def test_to_splunk_hec_sourcetype():
    events = _load()
    for e in events:
        hec = to_splunk_hec(e)
        assert hec["sourcetype"] == "shenron:synthetic:telemetry"


def test_to_splunk_hec_safety_contract():
    events = _load()
    for e in events:
        hec = to_splunk_hec(e)
        assert hec["event"]["simulation_only"] is True


def test_to_splunk_hec_time_is_float():
    events = _load()
    hec = to_splunk_hec(events[0])
    assert isinstance(hec["time"], float)
    assert hec["time"] > 0


# ── write_* integration tests ─────────────────────────────────────────────────

def test_write_ecs_array():
    events = _load()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    write_ecs_array(events, path)
    result = json.loads(Path(path).read_text())
    assert isinstance(result, list)
    assert len(result) == len(events)
    assert "@timestamp" in result[0]


def test_write_ecs_bulk():
    events = _load()
    with tempfile.NamedTemporaryFile(suffix=".ndjson", delete=False) as f:
        path = f.name
    write_ecs_bulk(events, path)
    lines = [l for l in Path(path).read_text().splitlines() if l.strip()]
    # bulk format: index line + event line per record
    assert len(lines) == len(events) * 2
    meta = json.loads(lines[0])
    assert "index" in meta
    event = json.loads(lines[1])
    assert "@timestamp" in event


def test_write_splunk_hec():
    events = _load()
    with tempfile.NamedTemporaryFile(suffix=".ndjson", delete=False) as f:
        path = f.name
    write_splunk_hec(events, path)
    lines = [l for l in Path(path).read_text().splitlines() if l.strip()]
    assert len(lines) == len(events)
    hec = json.loads(lines[0])
    assert hec["sourcetype"] == "shenron:synthetic:telemetry"
    assert hec["event"]["simulation_only"] is True
