#!/usr/bin/env python3
"""Tests for core/campaign/builder.py and CLI dispatch."""
import sys
import json
import pytest
from pathlib import Path
from argparse import Namespace

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.campaign.builder import CampaignBuilder, Campaign, CampaignStage, SCENARIOS
from core.cli.commands.campaign import handle as campaign_handle


def test_campaign_builder_initialization():
    builder = CampaignBuilder.from_scenario("apt29-style", 72)
    assert isinstance(builder, CampaignBuilder)
    assert builder.scenario_name == "apt29-style"
    assert builder.duration_hours == 72


def test_invalid_scenario_raises():
    with pytest.raises(ValueError, match="Unknown scenario"):
        CampaignBuilder.from_scenario("invalid-scenario")


def test_campaign_build_structure():
    builder = CampaignBuilder.from_scenario("ransomware-precursor")
    campaign = builder.build()
    assert isinstance(campaign, Campaign)
    assert len(campaign.events) == len(SCENARIOS["ransomware-precursor"])
    assert campaign.events[0].parent_event_id is None
    assert campaign.events[1].parent_event_id == campaign.events[0].event_id


def test_causal_ordering_and_jitter():
    builder = CampaignBuilder.from_scenario("insider-threat")
    campaign = builder.build()
    timestamps = [e.timestamp for e in campaign.events]
    assert timestamps == sorted(timestamps)
    from datetime import datetime
    dts = [datetime.fromisoformat(ts) for ts in timestamps]
    assert (dts[1] - dts[0]).total_seconds() >= 15 * 60


def test_session_id_consistency():
    builder = CampaignBuilder.from_scenario("apt29-style")
    campaign = builder.build()
    session_ids = {e.session_id for e in campaign.events}
    actor_ids = {e.actor_id for e in campaign.events}
    assert len(session_ids) == 1
    assert len(actor_ids) == 1
    assert session_ids.pop() == campaign.session_id


def test_to_jsonl_artifacts_contain_required_fields():
    builder = CampaignBuilder.from_scenario("apt29-style")
    builder.build()
    jsonl = builder.to_jsonl()
    assert len(jsonl) == len(SCENARIOS["apt29-style"])
    required = {
        "simulation_only", "artifact_id", "session_id", "mitre_techniques",
        "behavior_class", "detection_opportunities", "campaign_id", "actor_id",
        "stage", "parent_event_id", "causal_chain_index", "safety",
    }
    for art in jsonl:
        assert required.issubset(art.keys())
        assert art["simulation_only"] is True


def test_cli_dispatch_list_scenarios(capsys):
    args = Namespace(list_scenarios=True, scenario="apt29-style", length=72, output=None, stress_test=False)
    campaign_handle(args)
    captured = capsys.readouterr()
    assert "apt29-style" in captured.out


def test_cli_dispatch_generates_campaign(tmp_path, capsys):
    out_file = tmp_path / "camp.jsonl"
    args = Namespace(list_scenarios=False, scenario="apt29-style", length=24, output=str(out_file), stress_test=False)
    campaign_handle(args)
    captured = capsys.readouterr()
    assert "[CAMPAIGN]" in captured.out
    assert out_file.exists()
    lines = out_file.read_text().strip().split("\n")
    assert len(lines) == len(SCENARIOS["apt29-style"])
