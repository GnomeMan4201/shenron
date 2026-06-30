"""
SHENRON persistence layer — SQLite storage for longitudinal brittleness tracking.
Schema: run, scenario_result, rule_metric
"""
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

DB_PATH = Path(os.environ.get("SHENRON_DB", "shenron_runs.db"))


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _git_commit() -> Optional[str]:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=_repo_root(),
            stderr=subprocess.DEVNULL,
        ).decode().strip()
    except Exception:
        return None


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path = DB_PATH) -> None:
    """Create tables if they don't exist."""
    conn = get_connection(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS run (
            id          INTEGER PRIMARY KEY,
            started_at  INTEGER NOT NULL,
            ruleset_path TEXT NOT NULL,
            git_commit  TEXT,
            cli_args    TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_run_started ON run (started_at);

        CREATE TABLE IF NOT EXISTS scenario_result (
            id                      INTEGER PRIMARY KEY,
            run_id                  INTEGER NOT NULL REFERENCES run(id),
            scenario_name           TEXT NOT NULL,
            raw_brittleness         REAL NOT NULL,
            weighted_brittleness    REAL NOT NULL,
            correlation_brittleness REAL NOT NULL,
            triggered_stages        INTEGER NOT NULL,
            total_stages            INTEGER NOT NULL,
            most_brittle_stage      TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scenario_run
            ON scenario_result (run_id, scenario_name);

        CREATE TABLE IF NOT EXISTS rule_metric (
            id              INTEGER PRIMARY KEY,
            run_id          INTEGER NOT NULL REFERENCES run(id),
            scenario_name   TEXT NOT NULL,
            rule_name       TEXT NOT NULL,
            stage_name      TEXT NOT NULL,
            triggered       INTEGER NOT NULL,
            evaded          INTEGER NOT NULL,
            total_mutations INTEGER NOT NULL,
            brittleness     REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_rule_run
            ON rule_metric (run_id, rule_name);
        CREATE INDEX IF NOT EXISTS idx_rule_scenario_stage
            ON rule_metric (scenario_name, stage_name, rule_name);
    """)
    conn.commit()
    conn.close()


def insert_run(ruleset_path: str, db_path: Path = DB_PATH) -> int:
    """Insert a run row and return its id."""
    conn = get_connection(db_path)
    cur = conn.execute(
        "INSERT INTO run (started_at, ruleset_path, git_commit, cli_args) VALUES (?, ?, ?, ?)",
        (int(time.time()), ruleset_path, _git_commit(), " ".join(sys.argv)),
    )
    run_id = cur.lastrowid
    conn.commit()
    conn.close()
    return run_id


def insert_scenario_result(run_id: int, result, db_path: Path = DB_PATH) -> None:
    """Insert one ScenarioResult row."""
    conn = get_connection(db_path)
    conn.execute(
        """INSERT INTO scenario_result
           (run_id, scenario_name, raw_brittleness, weighted_brittleness,
            correlation_brittleness, triggered_stages, total_stages, most_brittle_stage)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            run_id,
            result.scenario_name,
            result.overall_brittleness,
            result.weighted_brittleness,
            result.correlation_brittleness,
            result.triggered_count,
            result.total_stages,
            result.most_brittle_stage,
        ),
    )
    conn.commit()
    conn.close()


def insert_rule_metrics(run_id: int, scenario_name: str,
                        rule_metrics: list, db_path: Path = DB_PATH) -> None:
    """Insert a batch of rule_metric rows.

    rule_metrics: list of dicts with keys:
        rule_name, stage_name, triggered, evaded, total_mutations, brittleness
    """
    conn = get_connection(db_path)
    conn.executemany(
        """INSERT INTO rule_metric
           (run_id, scenario_name, rule_name, stage_name,
            triggered, evaded, total_mutations, brittleness)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                run_id,
                scenario_name,
                rm["rule_name"],
                rm["stage_name"],
                rm["triggered"],
                rm["evaded"],
                rm["total_mutations"],
                rm["brittleness"],
            )
            for rm in rule_metrics
        ],
    )
    conn.commit()
    conn.close()


def query_runs(db_path: Path = DB_PATH) -> list:
    """Return all runs ordered by most recent first."""
    conn = get_connection(db_path)
    rows = conn.execute(
        "SELECT * FROM run ORDER BY started_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def query_scenario_history(scenario_name: str,
                           db_path: Path = DB_PATH) -> list:
    """Return brittleness history for a scenario across all runs."""
    conn = get_connection(db_path)
    rows = conn.execute(
        """SELECT r.started_at, r.git_commit,
                  s.raw_brittleness, s.weighted_brittleness,
                  s.correlation_brittleness, s.most_brittle_stage
           FROM scenario_result s
           JOIN run r ON r.id = s.run_id
           WHERE s.scenario_name = ?
           ORDER BY r.started_at ASC""",
        (scenario_name,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def query_weakest_rules(scenario_name: str, run_id: Optional[int] = None,
                        limit: int = 10, db_path: Path = DB_PATH) -> list:
    """Return the most brittle rules for a scenario, optionally filtered to a run."""
    conn = get_connection(db_path)
    if run_id is not None:
        rows = conn.execute(
            """SELECT rule_name, stage_name, brittleness, triggered, evaded, total_mutations
               FROM rule_metric
               WHERE scenario_name = ? AND run_id = ?
               ORDER BY brittleness DESC LIMIT ?""",
            (scenario_name, run_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT rule_name, stage_name, brittleness, triggered, evaded, total_mutations
               FROM rule_metric
               WHERE scenario_name = ?
               ORDER BY brittleness DESC LIMIT ?""",
            (scenario_name, limit),
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
