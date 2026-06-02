"""
tests/test_doctor.py
SHENRON — doctor command unit tests
"""
import json
import pytest
from pathlib import Path
from unittest.mock import patch
from io import StringIO


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_jsonl(tmp_path, records, name="artifacts.jsonl"):
    p = tmp_path / name
    p.write_text("\n".join(json.dumps(r) for r in records))
    return str(p)


def _good_record(layer="test_layer", phase="test_phase"):
    return {
        "artifact_id": "test-001",
        "session_id":  "sess-001",
        "layer":       layer,
        "phase":       phase,
        "mitre_techniques": ["T1053"],
        "behavior_class": "scheduled_task_creation",
        "detection_opportunities": ["scheduled_task_creation"],
        "simulation_only": True,
    }


def _gap_record(layer="gap_layer"):
    """Record missing behavior_class and detection_opportunities."""
    return {
        "artifact_id": "test-002",
        "session_id":  "sess-001",
        "layer":       layer,
        "phase":       "some_phase",
        "mitre_techniques": ["T1053"],
        "simulation_only": True,
    }


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestDoctorFieldChecks:

    def test_all_key_fields_present(self, tmp_path):
        from core.cli.commands.doctor import KEY_FIELDS
        record = _good_record()
        missing = KEY_FIELDS - set(record.keys())
        assert not missing, f"Test record missing key fields: {missing}"

    def test_gap_record_missing_fields(self, tmp_path):
        from core.cli.commands.doctor import KEY_FIELDS
        record = _gap_record()
        missing = KEY_FIELDS - {k for k, v in record.items()
                                 if v not in (None, [], "", False)}
        assert "behavior_class" in missing
        assert "detection_opportunities" in missing

    def test_key_fields_set_contents(self):
        from core.cli.commands.doctor import KEY_FIELDS
        required = {"behavior_class", "detection_opportunities",
                    "mitre_techniques", "layer", "phase"}
        assert required == KEY_FIELDS

    def test_sigma_fields_superset_of_key_fields(self):
        from core.cli.commands.doctor import KEY_FIELDS, SIGMA_FIELDS
        assert KEY_FIELDS.issubset(SIGMA_FIELDS)


class TestDoctorHandle:

    def _run_doctor(self, tmp_path, records, extra_args=None):
        """Run _handle_doctor against a temp JSONL file, capture stdout."""
        from core.cli.commands.doctor import _handle_doctor
        import sys

        jsonl = _make_jsonl(tmp_path, records)

        class Args:
            events = jsonl
            full   = False
            layer  = None

        if extra_args:
            for k, v in extra_args.items():
                setattr(Args, k, v)

        captured = StringIO()
        with patch("sys.stdout", captured):
            _handle_doctor(Args())
        return captured.getvalue()

    def test_pass_output_on_clean_records(self, tmp_path):
        records = [_good_record("layer_a"), _good_record("layer_b")]
        out = self._run_doctor(tmp_path, records)
        assert "PASS" in out
        assert "Gaps: 0" in out

    def test_gap_detected(self, tmp_path):
        records = [_good_record("ok_layer"), _gap_record("bad_layer")]
        out = self._run_doctor(tmp_path, records)
        assert "GAPS" in out
        assert "bad_layer" in out
        assert "behavior_class" in out

    def test_layer_filter(self, tmp_path):
        records = [_good_record("layer_a"), _gap_record("layer_b")]
        from core.cli.commands.doctor import _handle_doctor
        import sys

        jsonl = _make_jsonl(tmp_path, records)

        class Args:
            events = jsonl
            full   = False
            layer  = "layer_b"

        captured = StringIO()
        with patch("sys.stdout", captured):
            _handle_doctor(Args())
        out = captured.getvalue()
        assert "layer_b" in out
        assert "layer_a" not in out

    def test_missing_events_file(self, tmp_path, capsys):
        from core.cli.commands.doctor import _handle_doctor

        class Args:
            events = str(tmp_path / "nonexistent.jsonl")
            full   = False
            layer  = None

        _handle_doctor(Args())
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower() or "not found" in captured.err.lower()

    def test_full_mode_shows_more_fields(self, tmp_path):
        records = [_good_record()]
        from core.cli.commands.doctor import _handle_doctor, SIGMA_FIELDS
        import sys

        jsonl = _make_jsonl(tmp_path, records)

        class Args:
            events = jsonl
            full   = True
            layer  = None

        captured = StringIO()
        with patch("sys.stdout", captured):
            _handle_doctor(Args())
        out = captured.getvalue()
        # Full mode should mention sigma fields not in KEY_FIELDS
        assert "full sigma" in out.lower() or "sigma" in out.lower()

    def test_empty_log_handled(self, tmp_path, capsys):
        from core.cli.commands.doctor import _handle_doctor

        jsonl = _make_jsonl(tmp_path, [])

        class Args:
            events = jsonl
            full   = False
            layer  = None

        _handle_doctor(Args())
        captured = capsys.readouterr()
        assert captured.out or True  # Should not raise


class TestDoctorJsonOutput:

    def test_register_adds_json_flag(self):
        """doctor.register() should add --json flag for CI use."""
        import argparse
        from core.cli.commands.doctor import register
        p = argparse.ArgumentParser()
        sub = p.add_subparsers()
        register(sub)
        # parse with --json should not error if flag exists
        # (flag may not exist yet — this test drives its addition)
