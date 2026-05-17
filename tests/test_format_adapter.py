"""
tests/test_format_adapter.py
SHENRON — ECS and Splunk HEC format adapter tests

Run: pytest tests/test_format_adapter.py -v
"""
import json
import pytest
from pathlib import Path


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _record(technique="T1071", phase="OBSERVE", signal="periodic_beacon",
            layer="beacon_emitter_cloak", ts="2026-05-16T19:00:00+00:00"):
    return {
        "run_id":         "test-run-001",
        "sequence":       1,
        "timestamp":      ts,
        "phase":          phase,
        "layer":          layer,
        "event_type":     "synthetic_telemetry",
        "signal":         signal,
        "mitre_technique": technique,
        "description":    f"{signal} descriptor",
        "entropy":        5.18,
        "artifact_hash":  "abc123",
        "safety": {
            "simulation_only":                True,
            "executable":                     False,
            "payload_present":                False,
            "portable_adversarial_procedure": False,
            "network_connection":             False,
            "subprocess_spawned":             False,
            "real_file_written":              False,
            "shell_invoked":                  False,
        },
        "generator": "shenron/test",
    }


# ── ECS tests ─────────────────────────────────────────────────────────────────

class TestECSFormatter:

    def _convert(self, **kwargs):
        from core.formats.adapter import to_ecs
        return to_ecs(_record(**kwargs))

    def test_timestamp_preserved(self):
        ecs = self._convert(ts="2026-05-16T19:00:00+00:00")
        assert "@timestamp" in ecs
        assert "2026-05-16" in ecs["@timestamp"]

    def test_event_kind_is_event(self):
        ecs = self._convert()
        assert ecs["event.kind"] == "event"

    def test_event_dataset_is_shenron(self):
        ecs = self._convert()
        assert ecs["event.dataset"] == "shenron.synthetic"

    def test_message_contains_synthetic(self):
        ecs = self._convert()
        assert "SHENRON SYNTHETIC" in ecs["message"]

    def test_simulation_only_in_labels(self):
        ecs = self._convert()
        assert ecs["labels.simulation_only"] is True

    def test_payload_present_false_in_labels(self):
        ecs = self._convert()
        assert ecs["labels.payload_present"] is False

    def test_portable_adversarial_procedure_false(self):
        ecs = self._convert()
        assert ecs["labels.portable_adversarial_procedure"] is False

    def test_layer_in_labels(self):
        ecs = self._convert(layer="beacon_emitter_cloak")
        assert ecs["labels.shenron_layer"] == "beacon_emitter_cloak"

    def test_phase_in_labels(self):
        ecs = self._convert(phase="OBSERVE")
        assert ecs["labels.shenron_phase"] == "OBSERVE"

    def test_signal_in_labels(self):
        ecs = self._convert(signal="periodic_beacon")
        assert ecs["labels.shenron_signal"] == "periodic_beacon"

    def test_threat_technique_id_set(self):
        ecs = self._convert(technique="T1071")
        assert "T1071" in ecs["threat.technique.id"]

    def test_threat_tactic_set_for_c2(self):
        ecs = self._convert(technique="T1071")
        assert "command-and-control" in ecs["threat.tactic.name"]

    def test_threat_tactic_persistence_for_t1053(self):
        ecs = self._convert(technique="T1053")
        assert "persistence" in ecs["threat.tactic.name"]

    def test_threat_tactic_defense_evasion_for_t1070(self):
        ecs = self._convert(technique="T1070")
        assert "defense-evasion" in ecs["threat.tactic.name"]

    def test_sub_technique_resolved(self):
        ecs = self._convert(technique="T1036.005")
        assert len(ecs["threat.technique.id"]) > 0
        assert ecs["threat.technique.id"][0] == "T1036.005"
        # Should resolve to parent tactic
        assert len(ecs["threat.tactic.name"]) > 0

    def test_unknown_technique_defaults_gracefully(self):
        ecs = self._convert(technique="T9999")
        assert isinstance(ecs["threat.technique.id"], list)
        assert isinstance(ecs["event.category"], list)

    def test_missing_technique_handled(self):
        from core.formats.adapter import to_ecs
        r = _record()
        del r["mitre_technique"]
        ecs = to_ecs(r)
        assert "@timestamp" in ecs
        assert ecs["threat.technique.id"] == []

    def test_entropy_in_labels(self):
        ecs = self._convert()
        assert "labels.entropy" in ecs
        assert isinstance(ecs["labels.entropy"], float)

    def test_all_required_ecs_fields_present(self):
        ecs = self._convert()
        required = [
            "@timestamp", "event.kind", "event.category", "event.type",
            "event.dataset", "event.module", "message",
            "threat.framework", "labels.simulation_only",
        ]
        for field in required:
            assert field in ecs, f"Missing ECS field: {field}"

    def test_observer_fields_present(self):
        ecs = self._convert()
        assert ecs["observer.name"] == "shenron"
        assert "observer.version" in ecs

    def test_ecs_is_json_serializable(self):
        ecs = self._convert()
        serialized = json.dumps(ecs)
        assert "SHENRON SYNTHETIC" in serialized


# ── Splunk HEC tests ──────────────────────────────────────────────────────────

class TestSplunkHECFormatter:

    def _convert(self, **kwargs):
        from core.formats.adapter import to_splunk_hec
        return to_splunk_hec(_record(**kwargs))

    def test_hec_has_time(self):
        hec = self._convert()
        assert "time" in hec
        assert isinstance(hec["time"], float)

    def test_hec_has_sourcetype(self):
        hec = self._convert()
        assert hec["sourcetype"] == "shenron:synthetic:telemetry"

    def test_hec_event_has_signal(self):
        hec = self._convert(signal="periodic_beacon")
        assert hec["event"]["shenron_signal"] == "periodic_beacon"

    def test_hec_event_has_layer(self):
        hec = self._convert(layer="beacon_emitter_cloak")
        assert hec["event"]["shenron_layer"] == "beacon_emitter_cloak"

    def test_hec_simulation_only_true(self):
        hec = self._convert()
        assert hec["event"]["simulation_only"] is True

    def test_hec_payload_present_false(self):
        hec = self._convert()
        assert hec["event"]["payload_present"] is False

    def test_hec_message_contains_synthetic(self):
        hec = self._convert()
        assert "SHENRON SYNTHETIC" in hec["event"]["message"]

    def test_hec_has_mitre_technique(self):
        hec = self._convert(technique="T1071")
        assert hec["event"]["mitre_technique"] == "T1071"

    def test_hec_is_json_serializable(self):
        hec = self._convert()
        serialized = json.dumps(hec)
        assert "shenron:synthetic" in serialized

    def test_hec_index_field(self):
        hec = self._convert()
        assert "index" in hec
        assert hec["index"] == "shenron_demo"


# ── Bulk writer tests ─────────────────────────────────────────────────────────

class TestBulkWriters:

    def _records(self):
        return [
            _record(technique="T1071", signal="periodic_beacon"),
            _record(technique="T1053", signal="scheduled_task", phase="EXECUTE"),
            _record(technique="T1021", signal="subnet_sweep",   phase="SIMULATE"),
        ]

    def test_ecs_array_write(self, tmp_path):
        from core.formats.adapter import write_ecs_array
        out = tmp_path / "ecs.json"
        write_ecs_array(self._records(), str(out))
        data = json.loads(out.read_text())
        assert isinstance(data, list)
        assert len(data) == 3
        assert data[0]["event.dataset"] == "shenron.synthetic"

    def test_ecs_bulk_write(self, tmp_path):
        from core.formats.adapter import write_ecs_bulk
        out = tmp_path / "bulk.ndjson"
        write_ecs_bulk(self._records(), str(out))
        lines = [l for l in out.read_text().splitlines() if l.strip()]
        # Each record produces 2 lines: action + document
        assert len(lines) == 6
        action = json.loads(lines[0])
        assert "index" in action
        doc = json.loads(lines[1])
        assert "@timestamp" in doc

    def test_splunk_hec_write(self, tmp_path):
        from core.formats.adapter import write_splunk_hec
        out = tmp_path / "hec.json"
        write_splunk_hec(self._records(), str(out))
        lines = [l for l in out.read_text().splitlines() if l.strip()]
        assert len(lines) == 3
        hec = json.loads(lines[0])
        assert hec["sourcetype"] == "shenron:synthetic:telemetry"

    def test_all_records_have_simulation_only(self, tmp_path):
        from core.formats.adapter import write_ecs_array
        out = tmp_path / "ecs.json"
        write_ecs_array(self._records(), str(out))
        data = json.loads(out.read_text())
        for ev in data:
            assert ev["labels.simulation_only"] is True, \
                "ECS record missing simulation_only: true"

    def test_no_payload_in_any_record(self, tmp_path):
        from core.formats.adapter import write_ecs_array
        out = tmp_path / "ecs.json"
        write_ecs_array(self._records(), str(out))
        raw = out.read_text()
        assert '"payload_present": true' not in raw
        assert '"executable": true' not in raw


# ── Integration: real demo JSONL if available ─────────────────────────────────

class TestRealDemoJSONL:

    DEMO_PATH = "artifacts/demo/shenron_demo_run.jsonl"

    def _load(self):
        p = Path(self.DEMO_PATH)
        if not p.exists():
            pytest.skip(f"Demo JSONL not found: {self.DEMO_PATH}")
        records = []
        for line in p.read_text().splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))
        return records

    def test_all_demo_records_convert_to_ecs(self):
        from core.formats.adapter import to_ecs
        records = self._load()
        for r in records:
            ecs = to_ecs(r)
            assert "@timestamp" in ecs
            assert ecs["labels.simulation_only"] is True

    def test_all_demo_records_convert_to_splunk(self):
        from core.formats.adapter import to_splunk_hec
        records = self._load()
        for r in records:
            hec = to_splunk_hec(r)
            assert "time" in hec
            assert hec["event"]["simulation_only"] is True

    def test_ecs_bulk_from_demo(self, tmp_path):
        from core.formats.adapter import write_ecs_bulk
        records = self._load()
        out = tmp_path / "demo_bulk.ndjson"
        write_ecs_bulk(records, str(out))
        lines = [l for l in out.read_text().splitlines() if l.strip()]
        assert len(lines) == len(records) * 2
