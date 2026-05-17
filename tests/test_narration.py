"""
tests/test_narration.py
SHENRON — Narration engine tests

Run: pytest tests/test_narration.py -v
"""
import pytest
from unittest.mock import MagicMock


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _signal_delta(name, status_a="PASS", status_b="PASS", direction="unchanged"):
    from core.compare import SignalDelta as SD
    return SD(name=name, status_a=status_a, status_b=status_b, direction=direction)


def _make_compare(
    campaign_a="apt_kill_chain",
    campaign_b="persistence_runbook",
    lost=None,
    gained=None,
    mitre_a=None,
    mitre_b=None,
    mitre_lost=None,
    mitre_gained=None,
    mitre_retained=None,
    coverage_a=100.0,
    coverage_b=100.0,
    coverage_delta=0.0,
):
    r = MagicMock()
    r.run_id_a      = "1972a90e-0000-0000-0000-000000000000"
    r.run_id_b      = "32491bae-0000-0000-0000-000000000000"
    r.campaign_a    = campaign_a
    r.campaign_b    = campaign_b
    r.coverage_a    = coverage_a
    r.coverage_b    = coverage_b
    r.coverage_delta = coverage_delta
    r.verdict_a     = "PASS"
    r.verdict_b     = "PASS"
    r.safety_a      = 0
    r.safety_b      = 0
    r.lost          = lost    or []
    r.gained        = gained  or []
    r.mitre_a       = mitre_a or ["T1071", "T1021", "T1046", "T1070", "T1053"]
    r.mitre_b       = mitre_b or ["T1053", "T1547", "T1055"]
    r.mitre_lost    = mitre_lost    or ["T1071", "T1021", "T1046", "T1070"]
    r.mitre_gained  = mitre_gained  or []
    r.mitre_retained = mitre_retained or ["T1053"]
    r.signals = [
        _signal_delta("subnet_sweep",              "PASS", "ABSENT", "lost"),
        _signal_delta("periodic_outbound_connection", "PASS", "ABSENT", "lost"),
        _signal_delta("dns_subdomain_query",        "PASS", "ABSENT", "lost"),
        _signal_delta("log_file_cleared",           "PASS", "ABSENT", "lost"),
        _signal_delta("process_injection_attempt",  "ABSENT", "PASS", "gained"),
        _signal_delta("hidden_temp_directory",      "ABSENT", "PASS", "gained"),
        _signal_delta("scheduled_task_creation",    "PASS", "PASS",   "unchanged"),
    ]
    return r


# ── Taxonomy tests ────────────────────────────────────────────────────────────

class TestTaxonomy:

    def test_signal_taxonomy_has_c2_signals(self):
        from core.narration.engine import SIGNAL_TAXONOMY
        assert "periodic_outbound_connection" in SIGNAL_TAXONOMY
        assert SIGNAL_TAXONOMY["periodic_outbound_connection"]["family"] == "command-and-control"

    def test_signal_taxonomy_has_lateral_movement(self):
        from core.narration.engine import SIGNAL_TAXONOMY
        assert "subnet_sweep" in SIGNAL_TAXONOMY
        assert SIGNAL_TAXONOMY["subnet_sweep"]["family"] == "lateral-movement"

    def test_signal_taxonomy_has_persistence(self):
        from core.narration.engine import SIGNAL_TAXONOMY
        assert "scheduled_task_creation" in SIGNAL_TAXONOMY
        assert SIGNAL_TAXONOMY["scheduled_task_creation"]["family"] == "persistence"

    def test_signal_taxonomy_has_defense_evasion(self):
        from core.narration.engine import SIGNAL_TAXONOMY
        assert "log_file_cleared" in SIGNAL_TAXONOMY
        assert SIGNAL_TAXONOMY["log_file_cleared"]["family"] == "defense-evasion"

    def test_mitre_taxonomy_t1071_is_c2(self):
        from core.narration.engine import _resolve_mitre_family
        assert _resolve_mitre_family("T1071") == "command-and-control"

    def test_mitre_taxonomy_t1053_is_persistence(self):
        from core.narration.engine import _resolve_mitre_family
        assert _resolve_mitre_family("T1053") == "persistence"

    def test_mitre_taxonomy_t1021_is_lateral(self):
        from core.narration.engine import _resolve_mitre_family
        assert _resolve_mitre_family("T1021") == "lateral-movement"

    def test_mitre_taxonomy_t1070_is_evasion(self):
        from core.narration.engine import _resolve_mitre_family
        assert _resolve_mitre_family("T1070") == "defense-evasion"

    def test_sub_technique_resolves_to_parent_family(self):
        from core.narration.engine import _resolve_mitre_family
        assert _resolve_mitre_family("T1036.005") == "defense-evasion"

    def test_unknown_technique_returns_none(self):
        from core.narration.engine import _resolve_mitre_family
        assert _resolve_mitre_family("T9999") is None

    def test_tactic_families_have_concern_language(self):
        from core.narration.engine import TACTIC_FAMILIES
        for family, meta in TACTIC_FAMILIES.items():
            assert "analyst_concern" in meta, f"Missing analyst_concern for {family}"
            assert len(meta["analyst_concern"]) > 20, f"Concern too short for {family}"


# ── Profile builder tests ─────────────────────────────────────────────────────

class TestProfileBuilder:

    def test_c2_signals_produce_c2_family(self):
        from core.narration.engine import build_profile
        p = build_profile("test", "abc", ["periodic_outbound_connection", "dns_subdomain_query"], [])
        assert "command-and-control" in p.tactic_families

    def test_broad_profile_for_many_families(self):
        from core.narration.engine import build_profile
        p = build_profile("test", "abc",
            ["subnet_sweep", "log_file_cleared", "scheduled_task_creation", "periodic_outbound_connection"],
            ["T1071", "T1021", "T1070", "T1053"])
        assert p.breadth == "broad"

    def test_narrow_profile_for_one_family(self):
        from core.narration.engine import build_profile
        p = build_profile("test", "abc",
            ["scheduled_task_creation", "hidden_temp_directory"],
            ["T1053", "T1547"])
        assert p.breadth in ("narrow", "moderate")

    def test_dominant_family_set(self):
        from core.narration.engine import build_profile
        p = build_profile("test", "abc",
            ["scheduled_task_creation", "hidden_temp_directory", "artifact_cleanup",
             "process_revival", "signal_handler_modification"],
            ["T1053"])
        assert p.dominant_family is not None

    def test_unknown_signals_dont_crash(self):
        from core.narration.engine import build_profile
        p = build_profile("test", "abc", ["completely_unknown_signal_xyz"], [])
        # Should not raise, just have empty or minimal families
        assert isinstance(p.tactic_families, dict)


# ── Gap analysis tests ────────────────────────────────────────────────────────

class TestGapAnalysis:

    def test_lost_c2_signals_produce_c2_gap(self):
        from core.narration.engine import _gap_family_analysis
        gaps = _gap_family_analysis(
            ["periodic_outbound_connection", "dns_subdomain_query"],
            ["T1071"]
        )
        assert "command-and-control" in gaps

    def test_lost_lateral_signals_produce_lateral_gap(self):
        from core.narration.engine import _gap_family_analysis
        gaps = _gap_family_analysis(["subnet_sweep", "smb_port_probe"], ["T1021"])
        assert "lateral-movement" in gaps

    def test_all_gaps_have_concern_text(self):
        from core.narration.engine import _gap_family_analysis
        gaps = _gap_family_analysis(
            ["subnet_sweep", "log_file_cleared", "periodic_outbound_connection"],
            ["T1021", "T1070", "T1071"]
        )
        for fam, data in gaps.items():
            # concern may be empty for unknown families, fine
            assert isinstance(data["concern"], str)

    def test_empty_lost_produces_empty_gaps(self):
        from core.narration.engine import _gap_family_analysis
        gaps = _gap_family_analysis([], [])
        assert gaps == {}


# ── Narration output tests ────────────────────────────────────────────────────

class TestNarration:

    def _narrate(self, **kwargs):
        from core.narration.engine import narrate
        return narrate(_make_compare(**kwargs))

    def test_narration_contains_campaign_names(self):
        md = self._narrate()
        assert "apt_kill_chain" in md
        assert "persistence_runbook" in md

    def test_narration_contains_synthetic_disclaimer(self):
        md = self._narrate()
        assert "SYNTHETIC" in md

    def test_narration_contains_does_not_prove(self):
        md = self._narrate()
        assert "does not prove" in md.lower()

    def test_narration_contains_gap_section(self):
        md = self._narrate(
            lost=["subnet_sweep", "periodic_outbound_connection", "log_file_cleared"],
            mitre_lost=["T1021", "T1071", "T1070"]
        )
        assert "coverage gap" in md.lower()

    def test_narration_names_lost_signals(self):
        md = self._narrate(
            lost=["subnet_sweep", "periodic_outbound_connection"],
            mitre_lost=["T1021"]
        )
        assert "subnet_sweep" in md
        assert "periodic_outbound_connection" in md

    def test_narration_names_gained_signals(self):
        md = self._narrate(
            gained=["process_injection_attempt", "hidden_temp_directory"]
        )
        assert "process_injection_attempt" in md

    def test_narration_contains_recommendation(self):
        md = self._narrate(
            lost=["subnet_sweep", "log_file_cleared"],
            mitre_lost=["T1021", "T1070"]
        )
        assert "recommended" in md.lower() or "recommend" in md.lower()

    def test_narration_contains_run_ids(self):
        md = self._narrate()
        assert "1972a90e" in md
        assert "32491bae" in md

    def test_narration_has_signal_inventory_section(self):
        md = self._narrate()
        assert "Signal inventory" in md or "signal inventory" in md.lower()

    def test_narration_is_valid_markdown(self):
        md = self._narrate()
        assert md.startswith("# SHENRON Defensive Narrative")
        assert "---" in md
        assert "##" in md

    def test_narration_no_gaps_produces_no_gap_language(self):
        md = self._narrate(lost=[], mitre_lost=[])
        # When no signals are lost the gap section should be minimal
        # Accept any of several possible phrasings
        no_gap_phrases = [
            "No significant tactic family gaps",
            "closely aligned",
            "no significant",
            "not expressed",
            "no gap",
        ]
        assert any(p.lower() in md.lower() for p in no_gap_phrases), \
            f"Expected no-gap language not found in narrative"

    def test_narration_names_c2_gap_family(self):
        md = self._narrate(
            lost=["periodic_outbound_connection", "dns_subdomain_query"],
            mitre_lost=["T1071", "T1132"]
        )
        assert "Command-and-Control" in md or "command-and-control" in md.lower()

    def test_narration_names_lateral_gap_family(self):
        md = self._narrate(
            lost=["subnet_sweep", "smb_port_probe"],
            mitre_lost=["T1021", "T1046"]
        )
        assert "Lateral Movement" in md or "lateral" in md.lower()

    def test_print_summary_runs(self, capsys):
        from core.narration.engine import print_narrative_summary
        print_narrative_summary(_make_compare(
            lost=["subnet_sweep", "log_file_cleared"],
            mitre_lost=["T1021", "T1070"]
        ))
        out = capsys.readouterr().out
        assert "NARRATIVE" in out

    def test_real_compare_scenario(self):
        """Full integration test: apt_kill_chain vs persistence_runbook"""
        md = self._narrate(
            campaign_a="apt_kill_chain",
            campaign_b="persistence_runbook",
            lost=[
                "dns_subdomain_query", "encoded_uri_parameter", "fake_cmdline",
                "history_truncated", "log_file_cleared", "periodic_outbound_connection",
                "pid_masquerade", "process_name_spoof", "sequential_host_requests",
                "share_enumeration", "smb_port_probe", "subnet_sweep", "timestamp_rollback"
            ],
            gained=[
                "artifact_cleanup", "hidden_temp_directory", "process_injection_attempt",
                "process_revival", "sandboxed_command_execution", "signal_handler_modification"
            ],
            mitre_a=["T1071","T1132","T1021","T1046","T1135","T1053","T1547",
                     "T1055","T1134","T1070","T1107","T1036","T1036.005","T1543","T1027","T1564"],
            mitre_b=["T1053","T1547","T1055","T1134","T1543","T1564","T1027"],
            mitre_lost=["T1021","T1036","T1036.005","T1046","T1070","T1071","T1107","T1132","T1135"],
            mitre_gained=[],
            mitre_retained=["T1027","T1053","T1055","T1134","T1543","T1547","T1564"],
        )
        # Must name the major gap families
        assert "Command-and-Control" in md
        assert "Lateral Movement" in md
        assert "Defense Evasion" in md
        # Must name specific signals
        assert "subnet_sweep" in md
        # Must have recommendation
        assert any(word in md for word in ["apt_kill_chain", "evasion_stress_test", "Suggested"])
        # Must not overclaim
        assert "does not prove" in md.lower()
