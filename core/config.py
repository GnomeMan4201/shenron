#!/usr/bin/env python3
# SHENRON: Centralized path configuration
# Environment variables:
#   SHENRON_HOME       — base directory for logs and data (default: ~/SHENRON)
#   SHENRON_REPORT_DIR — report output directory (default: <repo>/reports)
import os
from pathlib import Path


def get_shenron_base() -> Path:
    """Return SHENRON base directory. Respects SHENRON_HOME env var."""
    env = os.environ.get("SHENRON_HOME")
    if env:
        return Path(env)
    return Path.home() / "SHENRON"


def get_log_dir() -> Path:
    p = get_shenron_base() / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_report_dir() -> Path:
    env = os.environ.get("SHENRON_REPORT_DIR")
    if env:
        p = Path(env)
    else:
        p = Path(__file__).parent.parent / "reports"
    p.mkdir(parents=True, exist_ok=True)
    return p


def artifact_log_path() -> Path:
    # Respect SHENRON_SCOPED_LOG env var for category-scoped runs
    scoped = os.environ.get("SHENRON_SCOPED_LOG")
    if scoped:
        return Path(scoped)
    return get_log_dir() / "simulation_artifacts.jsonl"

def scoped_artifact_log_path(scope: str) -> Path:
    """Return a scoped artifact log path for a specific category or layer."""
    return get_log_dir() / f"simulation_artifacts_{scope}.jsonl"


def timeline_log_path() -> Path:
    return get_log_dir() / "scenario_timelines.jsonl"


def mutation_history_path() -> Path:
    return get_log_dir() / "mutation_history.json"
