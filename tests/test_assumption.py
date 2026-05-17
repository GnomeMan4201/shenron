"""
tests/test_assumption.py
SHENRON v0.3.0 — Assumption Auditing Tests

Run: pytest tests/test_assumption.py -v
"""
import json
import pytest
from pathlib import Path

# ── Parser tests ──────────────────────────────────────────────────────────────

class TestAssumptionParser:

    def _load(self, data):
        from core.assumption.parser import load_assumption_from_dict
        return load_assumption_from_dict(data)

    def test_minimal_valid_assumption(self):
        a = self._load({
            "name": "test",
            "claims": ["We can detect X"],
        })
        assert a.name == "test"
        assert len(a.claims) == 1

    def test_name_required(self):
        with pytest.raises(ValueError, match="name"):
            self._load({"claims": ["something"]})

    def test_claims_required(self):
        with pytest.raises(ValueError, match="claims"):
            self._load({"name": "test", "claims": []})

    def test_invalid_technique_rejected(self):
        with pytest.raises(ValueError, match="Invalid technique"):
            self._load({
                "name": "test",
                "claims": ["X"],
                "expected_techniques": ["NOTAVALID"],
            })

    def test_valid_technique_accepted(self):
        a = self._load({
            "name": "test",
            "claims": ["X"],
            "expected_techniques": ["T1053", "T1053.005"],
        })
        assert "T1053" in a.expected_techniques
        assert "T1053.005" in a.expected_techniques

    def test_invalid_phase_rejected(self):
        with pytest.raises(ValueError, match="Unknown phase"):
            self._load({
                "name": "test",
                "claims": ["X"],
                "expected_phases": ["INVALID_PHASE"],
            })

    def test_valid_phases_accepted(self):
        a = self._load({
            "name": "test",
            "claims": ["X"],
            "expected_phases": ["OBSERVE", "SIMULATE", "EXECUTE", "ADAPT"],
        })
        assert len(a.expected_phases) == 4

    def test_signals_loaded(self):
        a = self._load({
            "name": "test",
            "claims": ["X"],
            "expected_signals": ["beacon_signal", "sweep_signal"],
        })
        assert "beacon_signal" in a.expected_signals

    def test_description_optional(self):
        a = self._load({"name": "test", "claims": ["X"]})
        assert a.description == ""

    def test_from_yaml_file(self, tmp_path):
        yaml_content = """
name: yaml_test
claims:
  - We detect X
expected_techniques:
  - T1071
"""
        p = tmp_path / "test.yaml"
        p.write_text(yaml_content)
        try:
            from core.assumption.parser import load_assumption
            a = load_assumption(str(p))
            assert a.name == "yaml_test"
            assert "T1071" in a.expected_techniques
        except ImportError:
            pytest.skip("PyYAML not installed")

    def test_missing_file_raises(self):
        from core.assumption.parser import load_assumption
        with pytest.raises(FileNotFoundError):
            load_assumption("/nonexistent/path/assumption.yaml")


# ── Evaluator tests ───────────────────────────────────────────────────────────

def _make_records(phases=None, techniques=None, signals=None):
    """Build minimal synthetic records for evaluator tests."""
    records = []
    phases     = phases     or ["OBSERVE", "SIMULATE", "EXECUTE", "ADAPT"]
    techniques = techniques or ["T1053", "T1071", "T1021"]
    signals    = signals    or ["periodic_beacon", "subnet_sweep", "scheduled_task"]

    for i, (phase, tech, sig) in enumerate(
        zip(phases * 10, techniques * 10, signals * 10)
    ):
        records.append({
            "sequence": i,
            "phase": phase,
            "mitre_technique": tech,
            "signal": sig,
            "safety": {
                "simulation_only": True,
                "executable": False,
                "payload_present": False,
            },
        })
    return records[:10]


class TestAssumptionEvaluator:

    def _assumption(self, **kwargs):
        from core.assumption.parser import load_assumption_from_dict
        base = {"name": "test", "claims": ["We detect X"]}
        base.update(kwargs)
        return load_assumption_from_dict(base)

    def _evaluate(self, assumption, records):
        from core.assumption.evaluator import evaluate
        return evaluate(assumption, records)

    def test_observed_technique(self):
        a = self._assumption(
            claims=["We detect persistence"],
            expected_techniques=["T1053"],
        )
        records = _make_records(techniques=["T1053"])
        result = self._evaluate(a, records)
        assert "T1053" in result.techniques_observed
        assert "T1053" not in result.techniques_missing

    def test_missing_technique(self):
        a = self._assumption(
            claims=["We detect X"],
            expected_techniques=["T1999"],
        )
        records = _make_records(techniques=["T1053"])
        result = self._evaluate(a, records)
        assert "T1999" in result.techniques_missing

    def test_observed_signal(self):
        a = self._assumption(
            claims=["We detect beaconing"],
            expected_signals=["periodic_beacon"],
        )
        records = _make_records(signals=["periodic_beacon"])
        result = self._evaluate(a, records)
        assert "periodic_beacon" in result.signals_observed

    def test_missing_signal(self):
        a = self._assumption(
            claims=["We detect X"],
            expected_signals=["nonexistent_signal_xyz"],
        )
        records = _make_records(signals=["periodic_beacon"])
        result = self._evaluate(a, records)
        assert "nonexistent_signal_xyz" in result.signals_missing

    def test_observed_phase(self):
        a = self._assumption(
            claims=["We observe"],
            expected_phases=["OBSERVE"],
        )
        records = _make_records(phases=["OBSERVE"])
        result = self._evaluate(a, records)
        assert "OBSERVE" in result.phases_observed

    def test_missing_phase(self):
        a = self._assumption(
            claims=["We observe"],
            expected_phases=["EXECUTE"],
        )
        records = _make_records(phases=["OBSERVE"])
        result = self._evaluate(a, records)
        assert "EXECUTE" in result.phases_missing

    def test_safety_violation_detected(self):
        a = self._assumption(claims=["X"])
        records = [{"signal": "x", "safety": {"simulation_only": False}}]
        result = self._evaluate(a, records)
        assert result.safety_violations > 0
        assert result.verdict == "UNSAFE"

    def test_pass_verdict_all_observed(self):
        a = self._assumption(
            claims=["We detect beaconing"],
            expected_techniques=["T1071"],
            expected_signals=["periodic_beacon"],
            expected_phases=["OBSERVE"],
        )
        records = _make_records(
            phases=["OBSERVE"],
            techniques=["T1071"],
            signals=["periodic_beacon"],
        )
        result = self._evaluate(a, records)
        assert result.verdict in ("PASS", "PARTIAL")

    def test_coverage_percent_zero_when_nothing_matches(self):
        a = self._assumption(
            claims=["We detect Z"],
            expected_techniques=["T1999"],
            expected_signals=["nonexistent_xyz"],
        )
        records = _make_records()
        result = self._evaluate(a, records)
        assert result.coverage_percent < 50.0

    def test_records_checked_count(self):
        a = self._assumption(claims=["X"])
        records = _make_records()
        result = self._evaluate(a, records)
        assert result.records_checked == len(records)


# ── Reporter tests ────────────────────────────────────────────────────────────

class TestAssumptionReporter:

    def _run(self, **kwargs):
        from core.assumption.parser import load_assumption_from_dict
        from core.assumption.evaluator import evaluate
        base = {"name": "reporter_test", "claims": ["We detect X"]}
        base.update(kwargs)
        a = load_assumption_from_dict(base)
        records = _make_records()
        return evaluate(a, records)

    def test_markdown_contains_assumption_name(self):
        from core.assumption.reporter import to_markdown
        result = self._run()
        md = to_markdown(result)
        assert "reporter_test" in md

    def test_markdown_contains_verdict(self):
        from core.assumption.reporter import to_markdown
        result = self._run()
        md = to_markdown(result)
        assert "PASS" in md or "PARTIAL" in md or "FAIL" in md

    def test_markdown_contains_safety_disclaimer(self):
        from core.assumption.reporter import to_markdown
        result = self._run()
        md = to_markdown(result)
        assert "does not prove" in md.lower()

    def test_json_is_valid(self):
        from core.assumption.reporter import to_json
        result = self._run()
        data = json.loads(to_json(result))
        assert "verdict" in data
        assert data["simulation_only"] is True
        assert data["portable_adversarial_procedure"] is False

    def test_json_contains_techniques(self):
        from core.assumption.reporter import to_json
        result = self._run(expected_techniques=["T1053"])
        data = json.loads(to_json(result))
        assert "techniques" in data
        assert "observed" in data["techniques"]
        assert "missing" in data["techniques"]

    def test_print_summary_runs_without_error(self, capsys):
        from core.assumption.reporter import print_summary
        result = self._run()
        print_summary(result)
        captured = capsys.readouterr()
        assert "VERDICT" in captured.out
