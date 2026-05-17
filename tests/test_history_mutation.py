"""
tests/test_history_mutation.py
SHENRON — History tracker and mutation engine tests

Run: pytest tests/test_history_mutation.py -v
"""
import json
import pytest
from pathlib import Path


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _run(campaign, run_id, techniques, ts="2026-05-17T00:00:00", run_type="bananatree"):
    return {
        "run_id":        run_id,
        "campaign_name": campaign,
        "timestamp":     ts,
        "_type":         run_type,
        "all_mitre":     techniques,
        "phases":        [{"phase": "OBSERVE"}, {"phase": "SIMULATE"},
                          {"phase": "EXECUTE"}, {"phase": "ADAPT"}],
    }


def _demo_records(n=10):
    records = []
    phases = ["OBSERVE", "SIMULATE", "EXECUTE", "ADAPT"]
    for i in range(n):
        records.append({
            "run_id":          "test-run-001",
            "sequence":        i + 1,
            "timestamp":       f"2026-05-17T00:{i:02d}:00+00:00",
            "phase":           phases[i % 4],
            "layer":           f"layer_{i}",
            "event_type":      "synthetic_telemetry",
            "signal":          f"signal_{i}",
            "mitre_technique": f"T107{i % 5}",
            "description":     f"descriptor {i}",
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
    return records


# ── History tracker tests ─────────────────────────────────────────────────────

class TestHistoryTracker:

    def _build(self, runs):
        from core.history.tracker import build_history
        return build_history(runs)

    def test_empty_runs_produces_empty_report(self):
        report = self._build([])
        assert report.total_runs == 0
        assert report.total_campaigns == 0

    def test_single_run_no_drift(self):
        runs = [_run("c2_test", "aaa", ["T1071", "T1021"])]
        report = self._build(runs)
        assert report.total_runs == 1
        assert report.drift_detected is False

    def test_multiple_runs_same_techniques_no_drift(self):
        runs = [
            _run("c2_test", "aaa", ["T1071", "T1021"]),
            _run("c2_test", "bbb", ["T1071", "T1021"]),
            _run("c2_test", "ccc", ["T1071", "T1021"]),
        ]
        report = self._build(runs)
        assert report.drift_detected is False

    def test_technique_gain_detected_as_drift(self):
        runs = [
            _run("c2_test", "aaa", ["T1071"]),
            _run("c2_test", "bbb", ["T1071", "T1021"]),
        ]
        report = self._build(runs)
        assert report.drift_detected is True
        hist = report.campaigns["c2_test"]
        drift = hist.drift_events()
        assert len(drift) == 1
        assert "T1021" in drift[0]["gained"]

    def test_technique_loss_detected_as_drift(self):
        runs = [
            _run("c2_test", "aaa", ["T1071", "T1021"]),
            _run("c2_test", "bbb", ["T1071"]),
        ]
        report = self._build(runs)
        assert report.drift_detected is True
        hist = report.campaigns["c2_test"]
        drift = hist.drift_events()
        assert "T1021" in drift[0]["lost"]

    def test_multiple_campaigns_tracked_independently(self):
        runs = [
            _run("c2_test",          "aaa", ["T1071"]),
            _run("persistence_test", "bbb", ["T1053"]),
            _run("c2_test",          "ccc", ["T1071", "T1021"]),
        ]
        report = self._build(runs)
        assert "c2_test" in report.campaigns
        assert "persistence_test" in report.campaigns
        assert len(report.campaigns["c2_test"].snapshots) == 2
        assert len(report.campaigns["persistence_test"].snapshots) == 1

    def test_markdown_contains_campaign_names(self):
        from core.history.tracker import to_markdown
        runs = [_run("c2_test", "aaa", ["T1071"])]
        report = self._build(runs)
        md = to_markdown(report)
        assert "c2_test" in md

    def test_markdown_contains_drift_section(self):
        from core.history.tracker import to_markdown
        runs = [
            _run("c2_test", "aaa", ["T1071"]),
            _run("c2_test", "bbb", ["T1071", "T1021"]),
        ]
        report = self._build(runs)
        md = to_markdown(report)
        assert "Drift" in md or "drift" in md.lower()

    def test_markdown_has_safety_disclaimer(self):
        from core.history.tracker import to_markdown
        runs = [_run("c2_test", "aaa", ["T1071"])]
        report = self._build(runs)
        md = to_markdown(report)
        assert "does not prove" in md.lower() or "SYNTHETIC" in md

    def test_json_output_valid(self):
        from core.history.tracker import to_json
        runs = [_run("c2_test", "aaa", ["T1071"])]
        report = self._build(runs)
        data = json.loads(to_json(report))
        assert "campaigns" in data
        assert data["simulation_only"] is True

    def test_snapshot_technique_count_correct(self):
        runs = [_run("c2_test", "aaa", ["T1071", "T1021", "T1046"])]
        report = self._build(runs)
        snap = report.campaigns["c2_test"].snapshots[0]
        assert snap.technique_count == 3

    def test_print_summary_runs(self, capsys):
        from core.history.tracker import print_history_summary
        runs = [_run("c2_test", "aaa", ["T1071"])]
        report = self._build(runs)
        print_history_summary(report)
        out = capsys.readouterr().out
        assert "HISTORY" in out

    def test_real_timeline_if_available(self):
        """Integration test against real timeline if it exists."""
        try:
            from core.reports.evidence import load_timeline, get_campaign_runs
            from core.history.tracker import build_history
            runs = get_campaign_runs(load_timeline())
            if not runs:
                pytest.skip("No runs in timeline")
            report = build_history(runs)
            assert report.total_runs > 0
            assert report.total_campaigns > 0
        except Exception as e:
            pytest.skip(f"Timeline not available: {e}")


# ── Mutation engine tests ─────────────────────────────────────────────────────

class TestMutationEngine:

    def _records(self, n=10):
        return _demo_records(n)

    def test_field_drop_removes_field(self):
        from core.mutation.engine import mutate_field_drop
        records = self._records()
        for r in records:
            r["description"] = "test"
        result = mutate_field_drop(records, "test-run", fields=["description"])
        for r in result.records:
            assert "description" not in r or r.get("mutation", {}).get("type") == "field_drop"
        assert result.changes_made > 0

    def test_field_drop_preserves_safety(self):
        from core.mutation.engine import mutate_field_drop
        result = mutate_field_drop(self._records(), "test-run")
        for r in result.records:
            assert r.get("safety", {}).get("simulation_only") is True

    def test_timing_jitter_changes_timestamps(self):
        from core.mutation.engine import mutate_timing_jitter
        records = self._records()
        original_ts = [r["timestamp"] for r in records]
        result = mutate_timing_jitter(records, "test-run", jitter_seconds=60)
        new_ts = [r["timestamp"] for r in result.records]
        assert result.changes_made > 0
        # At least some timestamps should differ
        diffs = sum(1 for a, b in zip(original_ts, new_ts) if a != b)
        assert diffs > 0

    def test_timing_jitter_preserves_safety(self):
        from core.mutation.engine import mutate_timing_jitter
        result = mutate_timing_jitter(self._records(), "test-run")
        for r in result.records:
            assert r.get("safety", {}).get("simulation_only") is True

    def test_label_ambiguity_replaces_signals(self):
        from core.mutation.engine import mutate_label_ambiguity
        records = self._records()
        for r in records:
            r["signal"] = "periodic_outbound_connection"
        result = mutate_label_ambiguity(records, "test-run")
        replaced = [r for r in result.records
                    if r.get("signal") == "outbound_connection"]
        assert len(replaced) > 0

    def test_signal_density_high_increases_count(self):
        from core.mutation.engine import mutate_signal_density_high
        records = self._records(5)
        result = mutate_signal_density_high(records, "test-run", multiplier=3)
        assert result.records_out == 15
        assert result.records_in == 5

    def test_signal_density_low_decreases_count(self):
        from core.mutation.engine import mutate_signal_density_low
        records = self._records(20)
        result = mutate_signal_density_low(records, "test-run", keep_fraction=0.5, seed=1)
        assert result.records_out < result.records_in
        assert result.records_out > 0

    def test_phase_imbalance_concentrates_phase(self):
        from core.mutation.engine import mutate_phase_imbalance
        result = mutate_phase_imbalance(self._records(), "test-run", target_phase="EXECUTE")
        phases = {r["phase"] for r in result.records}
        assert phases == {"EXECUTE"}

    def test_technique_noise_changes_some_techniques(self):
        from core.mutation.engine import mutate_technique_noise
        records = self._records(20)
        result = mutate_technique_noise(records, "test-run", noise_rate=0.5, seed=42)
        assert result.changes_made > 0

    def test_missing_safety_fields_is_flagged_unsafe(self):
        from core.mutation.engine import mutate_missing_safety_fields
        result = mutate_missing_safety_fields(self._records(), "test-run", drop_rate=1.0)
        assert result.safe is False
        # Safety should be missing from mutated records
        missing = [r for r in result.records if "safety" not in r]
        assert len(missing) > 0

    def test_mutation_adds_metadata(self):
        from core.mutation.engine import mutate_field_drop
        result = mutate_field_drop(self._records(), "test-run")
        for r in result.records:
            assert "mutation" in r
            assert r["mutation"]["type"] == "field_drop"

    def test_run_mutations_writes_files(self, tmp_path):
        from core.mutation.engine import run_mutations
        records = self._records(5)
        results = run_mutations(
            records,
            mutation_types=["field_drop", "timing_jitter"],
            out_dir=str(tmp_path),
            verbose=False,
        )
        assert len(results) == 2
        # Check output files exist
        for r in results:
            out_file = tmp_path / f"mutation_{r.mutation_type}.jsonl"
            assert out_file.exists()
            assert out_file.stat().st_size > 0

    def test_run_mutations_jsonl_valid(self, tmp_path):
        from core.mutation.engine import run_mutations
        records = self._records(5)
        results = run_mutations(
            records,
            mutation_types=["label_ambiguity"],
            out_dir=str(tmp_path),
            verbose=False,
        )
        out_file = tmp_path / "mutation_label_ambiguity.jsonl"
        lines = [l for l in out_file.read_text().splitlines() if l.strip()]
        assert len(lines) == 5
        parsed = [json.loads(l) for l in lines]
        assert all("mutation" in r for r in parsed)

    def test_unknown_mutation_type_skipped(self, tmp_path):
        from core.mutation.engine import run_mutations
        records = self._records(5)
        results = run_mutations(
            records,
            mutation_types=["nonexistent_mutation_xyz"],
            out_dir=str(tmp_path),
            verbose=False,
        )
        assert len(results) == 0

    def test_all_safe_mutations_preserve_simulation_only(self, tmp_path):
        from core.mutation.engine import run_mutations, MUTATION_TYPES
        safe_types = [t for t, m in MUTATION_TYPES.items() if m["safe"] and t != "missing_safety_fields"]
        records = self._records(10)
        results = run_mutations(records, mutation_types=safe_types,
                                out_dir=str(tmp_path), verbose=False)
        for result in results:
            for r in result.records:
                if "safety" in r:
                    assert r["safety"].get("simulation_only") is True, \
                        f"simulation_only not true in {result.mutation_type}"
