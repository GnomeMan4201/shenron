"""Regression coverage for deterministic persistence assumption evidence."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from core.assumptions.model import AssumptionStatus
from core.assumptions.validator import validate_assumption
from core.layers import dormant_persistence_sim
from core.layers import memory_persistence_sim
from core.layers import system_rebuild_sim


def _force_all_match_system_rebuild(tmp_path: Path):
    log_path = tmp_path / "system-rebuild.jsonl"
    with patch.object(
        system_rebuild_sim,
        "_get_artifact_log",
        return_value=log_path,
    ), patch.object(
        system_rebuild_sim.random,
        "sample",
        return_value=system_rebuild_sim.FAKE_SYSTEM_FILES[:3],
    ), patch.object(
        system_rebuild_sim.random,
        "randint",
        return_value=3,
    ), patch.object(
        system_rebuild_sim.random,
        "choice",
        return_value=system_rebuild_sim.FAKE_HASH_STATES[0],
    ):
        return system_rebuild_sim.simulate_shadow_rebuild()


def test_all_match_random_draw_still_emits_restoration_evidence(tmp_path):
    _, scan_results, events = _force_all_match_system_rebuild(tmp_path)

    assert len(scan_results) == 3
    restores = [event for event in events if event["phase"] == "shadow_restore"]
    assert restores
    assert any("T1543" in event["mitre_techniques"] for event in restores)

    scan_event = events[0]
    assert scan_event["phase"] == "integrity_scan"
    assert scan_event["mitre_techniques"] == ["T1547"]
    assert scan_event["simulation_only"] is True
    assert scan_event["filesystem_modified"] is False


def test_forced_all_match_path_still_satisfies_persistence_assumption(tmp_path):
    shared_log = tmp_path / "layer-output.jsonl"
    with patch.object(
        dormant_persistence_sim,
        "_get_artifact_log",
        return_value=shared_log,
    ):
        _, dormant_events = dormant_persistence_sim.simulate_sleeper_seed()

    with patch.object(
        memory_persistence_sim,
        "_get_artifact_log",
        return_value=shared_log,
    ):
        _, _, memory_events = memory_persistence_sim.simulate_memory_latch()

    _, _, rebuild_events = _force_all_match_system_rebuild(tmp_path)

    artifact = tmp_path / "persistence.jsonl"
    all_events = dormant_events + memory_events + rebuild_events
    artifact.write_text(
        "".join(json.dumps(event) + "\n" for event in all_events),
        encoding="utf-8",
    )

    assumption = (
        Path(__file__).resolve().parents[1]
        / "assumptions"
        / "examples"
        / "persistence_coverage.yaml"
    )
    result = validate_assumption(str(assumption), str(artifact))

    assert result.status == AssumptionStatus.SUPPORTED
    assert result.unsupported_count == 0
