#!/usr/bin/env python3
"""Tests for core/persistence/db.py and persistence wiring in comparator."""
import os
import sys
import time
import pytest
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.persistence.db import (
    init_db, insert_run, insert_scenario_result,
    insert_rule_metrics, query_runs, query_scenario_history,
    query_weakest_rules, get_connection,
)


@pytest.fixture
def tmp_db(tmp_path):
    db = tmp_path / "test_shenron.db"
    init_db(db)
    return db


def test_init_db_creates_tables(tmp_db):
    conn = get_connection(tmp_db)
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    conn.close()
    assert "run" in tables
    assert "scenario_result" in tables
    assert "rule_metric" in tables


def test_insert_run_returns_id(tmp_db):
    run_id = insert_run("sigma/rules", tmp_db)
    assert isinstance(run_id, int)
    assert run_id > 0


def test_insert_run_stores_fields(tmp_db):
    run_id = insert_run("sigma/rules", tmp_db)
    rows = query_runs(tmp_db)
    assert len(rows) == 1
    assert rows[0]["ruleset_path"] == "sigma/rules"
    assert rows[0]["started_at"] > 0


def test_multiple_runs_ordered_desc(tmp_db):
    insert_run("sigma/rules", tmp_db)
    time.sleep(0.01)
    insert_run("sigma/rules/v2", tmp_db)
    rows = query_runs(tmp_db)
    assert len(rows) == 2
    assert rows[0]["ruleset_path"] == "sigma/rules/v2"


class FakeResult:
    def __init__(self):
        self.scenario_name = "apt29-style"
        self.overall_brittleness = 0.50
        self.weighted_brittleness = 0.37
        self.correlation_brittleness = 0.25
        self.triggered_count = 7
        self.total_stages = 7
        self.most_brittle_stage = "INITIAL_ACCESS"


def test_insert_scenario_result(tmp_db):
    run_id = insert_run("sigma/rules", tmp_db)
    insert_scenario_result(run_id, FakeResult(), tmp_db)
    history = query_scenario_history("apt29-style", tmp_db)
    assert len(history) == 1
    assert abs(history[0]["raw_brittleness"] - 0.50) < 0.001
    assert history[0]["most_brittle_stage"] == "INITIAL_ACCESS"


def test_scenario_history_multiple_runs(tmp_db):
    for _ in range(3):
        run_id = insert_run("sigma/rules", tmp_db)
        insert_scenario_result(run_id, FakeResult(), tmp_db)
    history = query_scenario_history("apt29-style", tmp_db)
    assert len(history) == 3


def test_insert_rule_metrics(tmp_db):
    run_id = insert_run("sigma/rules", tmp_db)
    metrics = [
        {"rule_name": "detect_lsass", "stage_name": "EXECUTION",
         "triggered": 1, "evaded": 4, "total_mutations": 6, "brittleness": 0.67},
        {"rule_name": "detect_lateral", "stage_name": "LATERAL_MOVEMENT",
         "triggered": 1, "evaded": 2, "total_mutations": 6, "brittleness": 0.33},
    ]
    insert_rule_metrics(run_id, "apt29-style", metrics, tmp_db)
    weakest = query_weakest_rules("apt29-style", run_id=run_id, db_path=tmp_db)
    assert len(weakest) == 2
    assert weakest[0]["rule_name"] == "detect_lsass"
    assert weakest[0]["brittleness"] > weakest[1]["brittleness"]


def test_query_weakest_rules_limit(tmp_db):
    run_id = insert_run("sigma/rules", tmp_db)
    metrics = [
        {"rule_name": f"rule_{i}", "stage_name": "EXECUTION",
         "triggered": 1, "evaded": i, "total_mutations": 6,
         "brittleness": i / 6}
        for i in range(10)
    ]
    insert_rule_metrics(run_id, "apt29-style", metrics, tmp_db)
    weakest = query_weakest_rules("apt29-style", run_id=run_id,
                                  limit=3, db_path=tmp_db)
    assert len(weakest) == 3
    assert weakest[0]["brittleness"] >= weakest[1]["brittleness"]


def test_persist_flag_false_no_db_created(tmp_path):
    """Comparator with persist=False should not create a DB file."""
    db_path = str(tmp_path / "should_not_exist.db")
    from core.campaign.comparator import ScenarioComparator
    comp = ScenarioComparator("sigma/rules", persist=False, db_path=db_path)
    assert not Path(db_path).exists()


def test_init_db_idempotent(tmp_db):
    """Calling init_db twice should not raise."""
    init_db(tmp_db)
    init_db(tmp_db)
    tables = {r[0] for r in get_connection(tmp_db).execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    assert "run" in tables
