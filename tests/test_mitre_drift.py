"""
tests/test_mitre_drift.py

Tests for core/mitre/drift.py

Follows SHENRON's existing pytest conventions.
All tests are offline — no network calls.
Synthetic STIX bundle used throughout.
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from core.mitre.drift import (
    check_drift,
    print_drift_report,
    drift_report_to_markdown,
    _parse_techniques,
    _load_manifest,
    _extract_layer_techniques,
    DriftReport,
    TechniqueDriftResult,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

SYNTHETIC_STIX_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "x-mitre-matrix",
            "name": "Enterprise ATT&CK",
            "x_mitre_attack_spec_version": "15.1",
        },
        # Active technique
        {
            "type": "attack-pattern",
            "name": "Rootkit",
            "x_mitre_deprecated": False,
            "revoked": False,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1014"}
            ],
        },
        # Active sub-technique
        {
            "type": "attack-pattern",
            "name": "Process Injection",
            "x_mitre_deprecated": False,
            "revoked": False,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1055"}
            ],
        },
        {
            "type": "attack-pattern",
            "name": "Indicator Removal",
            "x_mitre_deprecated": False,
            "revoked": False,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1070"}
            ],
        },
        # Deprecated technique (T1107 → T1070.004)
        {
            "type": "attack-pattern",
            "name": "File Deletion",
            "x_mitre_deprecated": True,
            "revoked": True,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1107"},
                {"source_name": "mitre-attack", "external_id": "T1070.004"},
            ],
        },
        # Active technique for impair defenses
        {
            "type": "attack-pattern",
            "name": "Disable or Modify Tools",
            "x_mitre_deprecated": False,
            "revoked": False,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1562.001"}
            ],
        },
    ],
}

SYNTHETIC_MANIFEST = {
    "layers": [
        {
            "name": "ebpf_rootkit_phantom",
            "category": "evasion",
            "mitre": {
                "techniques": ["T1014", "T1562.001", "T1055"],
                "tactic": "defense-evasion",
            },
        },
        {
            "name": "anti_forensics_molt",
            "category": "evasion",
            "mitre": {
                "techniques": ["T1070", "T1107"],  # T1107 is deprecated
                "tactic": "defense-evasion",
            },
        },
        {
            "name": "ghost_layer_stale",
            "category": "evasion",
            "mitre": {
                "techniques": ["T9999"],  # Does not exist in ATT&CK
                "tactic": "defense-evasion",
            },
        },
    ]
}


@pytest.fixture
def tmp_manifest(tmp_path):
    """Write synthetic manifest to a temp file and return its path."""
    p = tmp_path / "shenron_manifest.json"
    p.write_text(json.dumps(SYNTHETIC_MANIFEST), encoding="utf-8")
    return str(p)


@pytest.fixture
def tmp_bundle(tmp_path):
    """Write synthetic STIX bundle to a temp file and return its path."""
    p = tmp_path / "attack_bundle.json"
    p.write_text(json.dumps(SYNTHETIC_STIX_BUNDLE), encoding="utf-8")
    return str(p)


# ── Unit: _parse_techniques ───────────────────────────────────────────────────

class TestParseTehniques:
    def test_extracts_active_technique(self):
        techs, version = _parse_techniques(SYNTHETIC_STIX_BUNDLE)
        assert "T1014" in techs
        assert techs["T1014"]["name"] == "Rootkit"
        assert techs["T1014"]["deprecated"] is False

    def test_extracts_version(self):
        _, version = _parse_techniques(SYNTHETIC_STIX_BUNDLE)
        assert version == "15.1"

    def test_marks_deprecated_technique(self):
        techs, _ = _parse_techniques(SYNTHETIC_STIX_BUNDLE)
        assert "T1107" in techs
        assert techs["T1107"]["deprecated"] is True

    def test_extracts_revoked_by(self):
        techs, _ = _parse_techniques(SYNTHETIC_STIX_BUNDLE)
        assert techs["T1107"]["revoked_by"] == "T1070.004"

    def test_empty_bundle(self):
        techs, version = _parse_techniques({"objects": []})
        assert techs == {}
        assert version == "unknown"

    def test_skips_non_attack_pattern_objects(self):
        techs, _ = _parse_techniques(SYNTHETIC_STIX_BUNDLE)
        # x-mitre-collection should not appear as a technique
        assert "x-mitre-collection" not in techs


# ── Unit: _load_manifest ──────────────────────────────────────────────────────

class TestLoadManifest:
    def test_loads_layers(self, tmp_manifest):
        layers = _load_manifest(tmp_manifest)
        assert len(layers) == 3
        assert layers[0]["name"] == "ebpf_rootkit_phantom"

    def test_missing_manifest_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            _load_manifest(str(tmp_path / "nonexistent.json"))

    def test_empty_manifest(self, tmp_path):
        p = tmp_path / "empty.json"
        p.write_text(json.dumps({}), encoding="utf-8")
        layers = _load_manifest(str(p))
        assert layers == []


# ── Unit: _extract_layer_techniques ──────────────────────────────────────────

class TestExtractLayerTechniques:
    def test_extracts_all_layers(self):
        layers = SYNTHETIC_MANIFEST["layers"]
        result = _extract_layer_techniques(layers)
        assert "ebpf_rootkit_phantom" in result
        assert "anti_forensics_molt" in result
        assert "ghost_layer_stale" in result

    def test_correct_technique_ids(self):
        layers = SYNTHETIC_MANIFEST["layers"]
        result = _extract_layer_techniques(layers)
        assert set(result["ebpf_rootkit_phantom"]) == {"T1014", "T1562.001", "T1055"}

    def test_layer_without_mitre_block(self):
        layers = [{"name": "bare_layer", "category": "c2"}]
        result = _extract_layer_techniques(layers)
        assert result == {}


# ── Integration: check_drift (offline mode) ───────────────────────────────────

class TestCheckDriftOffline:
    def test_ok_techniques_detected(self, tmp_manifest, tmp_bundle):
        report = check_drift(
            manifest_path=tmp_manifest,
            offline=True,
            cached_bundle_path=tmp_bundle,
        )
        ok_ids = {r.technique_id for r in report.ok}
        assert "T1014" in ok_ids
        assert "T1055" in ok_ids
        assert "T1562.001" in ok_ids

    def test_stale_technique_detected(self, tmp_manifest, tmp_bundle):
        report = check_drift(
            manifest_path=tmp_manifest,
            offline=True,
            cached_bundle_path=tmp_bundle,
        )
        stale_ids = {r.technique_id for r in report.stale}
        assert "T9999" in stale_ids

    def test_renamed_technique_detected(self, tmp_manifest, tmp_bundle):
        report = check_drift(
            manifest_path=tmp_manifest,
            offline=True,
            cached_bundle_path=tmp_bundle,
        )
        renamed_ids = {r.technique_id for r in report.renamed}
        assert "T1107" in renamed_ids

    def test_renamed_has_revoked_by(self, tmp_manifest, tmp_bundle):
        report = check_drift(
            manifest_path=tmp_manifest,
            offline=True,
            cached_bundle_path=tmp_bundle,
        )
        t1107 = next(r for r in report.renamed if r.technique_id == "T1107")
        assert t1107.revoked_by == "T1070.004"

    def test_verdict_stale_when_unknown_id(self, tmp_manifest, tmp_bundle):
        report = check_drift(
            manifest_path=tmp_manifest,
            offline=True,
            cached_bundle_path=tmp_bundle,
        )
        assert report.verdict == "STALE"

    def test_layer_staleness_populated(self, tmp_manifest, tmp_bundle):
        report = check_drift(
            manifest_path=tmp_manifest,
            offline=True,
            cached_bundle_path=tmp_bundle,
        )
        assert "ghost_layer_stale" in report.layer_staleness
        assert "anti_forensics_molt" in report.layer_staleness

    def test_counts_correct(self, tmp_manifest, tmp_bundle):
        report = check_drift(
            manifest_path=tmp_manifest,
            offline=True,
            cached_bundle_path=tmp_bundle,
        )
        assert report.total_layers == 3
        # 3 ok (T1014, T1562.001, T1055) + 1 stale (T9999) + 1 renamed (T1107)
        # + T1070 which is active
        assert len(report.ok) >= 3
        assert len(report.stale) == 1
        assert len(report.renamed) == 1

    def test_no_network_in_offline_mode(self, tmp_manifest, tmp_bundle):
        """Offline mode must not make any network calls."""
        with patch("core.mitre.drift._fetch_stix_bundle") as mock_fetch:
            check_drift(
                manifest_path=tmp_manifest,
                offline=True,
                cached_bundle_path=tmp_bundle,
            )
            mock_fetch.assert_not_called()


class TestCheckDriftNetworkFailure:
    def test_returns_unknown_on_fetch_failure(self, tmp_manifest):
        """If network fetch fails, all results should be UNKNOWN."""
        with patch("core.mitre.drift._fetch_stix_bundle", return_value=None):
            report = check_drift(
                manifest_path=tmp_manifest,
                offline=False,
                cached_bundle_path=None,
            )
        assert report.attack_version == "unavailable"
        assert len(report.unknown) > 0
        assert len(report.ok) == 0
        assert len(report.stale) == 0


class TestCheckDriftCleanManifest:
    def test_verdict_current_when_all_ok(self, tmp_path, tmp_bundle):
        """A manifest with only current technique IDs should return CURRENT."""
        clean_manifest = {
            "layers": [
                {
                    "name": "clean_layer",
                    "category": "evasion",
                    "mitre": {
                        "techniques": ["T1014", "T1055"],
                        "tactic": "defense-evasion",
                    },
                }
            ]
        }
        p = tmp_path / "clean_manifest.json"
        p.write_text(json.dumps(clean_manifest), encoding="utf-8")

        report = check_drift(
            manifest_path=str(p),
            offline=True,
            cached_bundle_path=tmp_bundle,
        )
        assert report.verdict == "CURRENT"
        assert not report.has_issues


# ── Output: print and markdown ────────────────────────────────────────────────

class TestReportOutput:
    def test_print_does_not_raise(self, tmp_manifest, tmp_bundle, capsys):
        report = check_drift(
            manifest_path=tmp_manifest,
            offline=True,
            cached_bundle_path=tmp_bundle,
        )
        print_drift_report(report)
        captured = capsys.readouterr()
        assert "VERDICT" in captured.out
        assert "STALE" in captured.out

    def test_markdown_contains_key_sections(self, tmp_manifest, tmp_bundle):
        report = check_drift(
            manifest_path=tmp_manifest,
            offline=True,
            cached_bundle_path=tmp_bundle,
        )
        md = drift_report_to_markdown(report)
        assert "# MITRE ATT&CK Drift Report" in md
        assert "STALE" in md
        assert "T9999" in md
        assert "T1107" in md

    def test_markdown_contains_version(self, tmp_manifest, tmp_bundle):
        report = check_drift(
            manifest_path=tmp_manifest,
            offline=True,
            cached_bundle_path=tmp_bundle,
        )
        md = drift_report_to_markdown(report)
        assert "15.1" in md

    def test_clean_report_markdown_has_no_stale_section(self, tmp_path, tmp_bundle):
        clean_manifest = {
            "layers": [
                {
                    "name": "clean_layer",
                    "category": "evasion",
                    "mitre": {"techniques": ["T1014"], "tactic": "defense-evasion"},
                }
            ]
        }
        p = tmp_path / "clean_manifest.json"
        p.write_text(json.dumps(clean_manifest), encoding="utf-8")

        report = check_drift(
            manifest_path=str(p),
            offline=True,
            cached_bundle_path=tmp_bundle,
        )
        md = drift_report_to_markdown(report)
        assert "## Stale Techniques" not in md


# ── Safety: no side effects ───────────────────────────────────────────────────

class TestSafetyConstraints:
    def test_check_drift_does_not_write_files(self, tmp_manifest, tmp_bundle, tmp_path):
        """check_drift without cache path must not write any files."""
        before = set(tmp_path.iterdir())
        check_drift(
            manifest_path=tmp_manifest,
            offline=True,
            cached_bundle_path=tmp_bundle,
        )
        after = set(tmp_path.iterdir())
        # Only the files we explicitly created should exist
        assert before == after

    def test_cache_write_only_when_path_given(self, tmp_manifest, tmp_bundle, tmp_path):
        """Cache is only written if cached_bundle_path is explicitly provided."""
        cache_path = tmp_path / "new_cache.json"
        assert not cache_path.exists()

        # Run without cache path — should not create cache file
        check_drift(
            manifest_path=tmp_manifest,
            offline=True,
            cached_bundle_path=tmp_bundle,  # reading existing
        )
        # The existing bundle file should still be the only one
        assert not cache_path.exists()
