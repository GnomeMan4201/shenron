"""
tests/test_assumption.py
SHENRON — Assumption engine tests (migrated to core/assumptions/)

Replaces the old core/assumption/ (singular) tests.
All coverage preserved; data model updated to Claim/AssumptionResult.

Run: pytest tests/test_assumption.py -v
"""
import json
import pytest
from pathlib import Path


# ── Helpers ───────────────────────────────────────────────────────────────────

def _write_yaml(tmp_path, name, content):
    """Write a YAML assumption file with schema_version prepended."""
    p = tmp_path / name
    p.write_text(f'schema_version: "1.0"\n{content}')
    return p


def _write_jsonl(tmp_path, records, name="artifacts.jsonl"):
    p = tmp_path / name
    p.write_text("\n".join(json.dumps(r) for r in records))
    return p


def _make_records(phases=None, techniques=None, signals=None):
    """Build minimal synthetic records for evaluator tests."""
    phases     = phases     or ["OBSERVE", "SIMULATE", "EXECUTE", "ADAPT"]
    techniques = techniques or ["T1053", "T1071", "T1021"]
    signals    = signals    or ["periodic_beacon", "subnet_sweep", "scheduled_task"]

    records = []
    for i, (phase, tech, sig) in enumerate(
        zip(phases * 10, techniques * 10, signals * 10)
    ):
        records.append({
            "sequence":          i,
            "phase":             phase,
            "mitre_techniques":  [tech],
            "behavior_class":    sig,
            "detection_opportunities": [sig],
            "layer":             "test_layer",
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
        })
    return records[:10]


# ── Loader tests (replaces TestAssumptionParser) ──────────────────────────────

class TestAssumptionLoader:

    def test_minimal_valid_assumption(self, tmp_path):
        from core.assumptions.loader import load_assumption
        p = _write_yaml(tmp_path, "minimal.yaml", """
id: test_assumption
description: Test
claims:
  - id: detect_x
    type: positive_evidence
    severity: medium
    requires_techniques:
      - T1053
""")
        assumption_id, description, claims = load_assumption(p)
        assert assumption_id == "test_assumption"
        assert len(claims) == 1
        assert claims[0].id == "detect_x"

    def test_valid_technique_in_claim(self, tmp_path):
        from core.assumptions.loader import load_assumption
        p = _write_yaml(tmp_path, "tech.yaml", """
id: tech_test
description: Test
claims:
  - id: t1
    type: positive_evidence
    severity: medium
    requires_techniques:
      - T1053
      - T1053.005
""")
        _, _, claims = load_assumption(p)
        assert "T1053" in claims[0].requires_techniques
        assert "T1053.005" in claims[0].requires_techniques

    def test_signals_loaded(self, tmp_path):
        from core.assumptions.loader import load_assumption
        p = _write_yaml(tmp_path, "sig.yaml", """
id: sig_test
description: Test
claims:
  - id: s1
    type: positive_evidence
    severity: medium
    requires_signals:
      - beacon_signal
      - sweep_signal
""")
        _, _, claims = load_assumption(p)
        assert "beacon_signal" in claims[0].requires_signals

    def test_missing_file_raises(self):
        from core.assumptions.loader import load_assumption
        with pytest.raises(FileNotFoundError):
            load_assumption("/nonexistent/path/assumption.yaml")

    def test_out_of_scope_claim_type(self, tmp_path):
        from core.assumptions.loader import load_assumption
        from core.assumptions.model import ClaimType
        p = _write_yaml(tmp_path, "oos.yaml", """
id: oos_test
description: Test
claims:
  - id: no_c2
    type: out_of_scope_claim
    severity: high
    requires_techniques:
      - T1071
""")
        _, _, claims = load_assumption(p)
        assert claims[0].type == ClaimType.OUT_OF_SCOPE

    def test_description_optional(self, tmp_path):
        from core.assumptions.loader import load_assumption
        p = _write_yaml(tmp_path, "nodesc.yaml", """
id: nodesc_test
claims:
  - id: c1
    type: positive_evidence
    severity: low
    requires_techniques:
      - T1053
""")
        _, description, _ = load_assumption(p)
        # description may be empty string or None — just must not raise
        assert description is not None or description == ""


# ── Validator tests (replaces TestAssumptionEvaluator) ───────────────────────

class TestAssumptionValidator:

    def _validate(self, tmp_path, yaml_content, records):
        from core.assumptions.validator import validate_assumption
        p = _write_yaml(tmp_path, "test.yaml", yaml_content)
        j = _write_jsonl(tmp_path, records)
        return validate_assumption(p, j)

    def test_observed_technique_supported(self, tmp_path):
        result = self._validate(tmp_path, """
id: tech_test
description: Test
claims:
  - id: t1
    type: positive_evidence
    severity: medium
    requires_techniques:
      - T1053
""", _make_records(techniques=["T1053"]))
        assert result.supported_count >= 1

    def test_missing_technique_unsupported(self, tmp_path):
        result = self._validate(tmp_path, """
id: tech_missing
description: Test
claims:
  - id: t1
    type: positive_evidence
    severity: medium
    requires_techniques:
      - T1999
""", _make_records(techniques=["T1053"]))
        assert result.unsupported_count >= 1

    def test_observed_signal_supported(self, tmp_path):
        result = self._validate(tmp_path, """
id: sig_test
description: Test
claims:
  - id: s1
    type: positive_evidence
    severity: medium
    requires_signals:
      - periodic_beacon
""", _make_records(signals=["periodic_beacon"]))
        assert result.supported_count >= 1

    def test_missing_signal_unsupported(self, tmp_path):
        result = self._validate(tmp_path, """
id: sig_missing
description: Test
claims:
  - id: s1
    type: positive_evidence
    severity: medium
    requires_signals:
      - nonexistent_signal_xyz
""", _make_records(signals=["periodic_beacon"]))
        assert result.unsupported_count >= 1

    def test_out_of_scope_violation_detected(self, tmp_path):
        from core.assumptions.model import AssumptionStatus
        result = self._validate(tmp_path, """
id: oos_test
description: Test
claims:
  - id: no_beacon
    type: out_of_scope_claim
    severity: high
    requires_signals:
      - periodic_beacon
""", _make_records(signals=["periodic_beacon"]))
        assert result.status == AssumptionStatus.OUT_OF_SCOPE_VIOLATION
        assert len(result.out_of_scope_violations) >= 1

    def test_fully_supported_verdict(self, tmp_path):
        from core.assumptions.model import AssumptionStatus
        result = self._validate(tmp_path, """
id: full_test
description: Test
claims:
  - id: t1
    type: positive_evidence
    severity: medium
    requires_techniques:
      - T1053
    requires_signals:
      - periodic_beacon
""", _make_records(techniques=["T1053"], signals=["periodic_beacon"]))
        assert result.status in (
            AssumptionStatus.SUPPORTED,
            AssumptionStatus.PARTIALLY_SUPPORTED,
        )

    def test_safe_conclusion_present(self, tmp_path):
        result = self._validate(tmp_path, """
id: sc_test
description: Test
claims:
  - id: c1
    type: positive_evidence
    severity: medium
    requires_techniques:
      - T1053
""", _make_records())
        assert result.safe_conclusion
        assert len(result.safe_conclusion) > 10

    def test_to_dict_has_required_keys(self, tmp_path):
        result = self._validate(tmp_path, """
id: dict_test
description: Test
claims:
  - id: c1
    type: positive_evidence
    severity: medium
    requires_techniques:
      - T1053
""", _make_records())
        d = result.to_dict()
        for key in ("assumption_id", "status", "supported_count",
                    "unsupported_count", "safe_conclusion", "timestamp"):
            assert key in d, f"Missing key in to_dict(): {key}"

    def test_print_result_runs_without_error(self, tmp_path, capsys):
        from core.assumptions.validator import print_result
        result = self._validate(tmp_path, """
id: print_test
description: Test
claims:
  - id: c1
    type: positive_evidence
    severity: medium
    requires_techniques:
      - T1053
""", _make_records())
        print_result(result)
        captured = capsys.readouterr()
        assert "ASSUMPTION" in captured.out
        assert "STATUS" in captured.out
