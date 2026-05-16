#!/usr/bin/env python3
"""Tests for centralized path configuration."""
import os
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def _reload_config(monkeypatch, home=None, report_dir=None):
    """Re-import config with patched env vars."""
    if home is not None:
        monkeypatch.setenv("SHENRON_HOME", str(home))
    else:
        monkeypatch.delenv("SHENRON_HOME", raising=False)
    if report_dir is not None:
        monkeypatch.setenv("SHENRON_REPORT_DIR", str(report_dir))
    else:
        monkeypatch.delenv("SHENRON_REPORT_DIR", raising=False)

    import importlib
    import core.config
    importlib.reload(core.config)
    return core.config


def test_default_base_is_home_shenron(monkeypatch):
    cfg = _reload_config(monkeypatch)
    assert cfg.get_shenron_base() == Path.home() / "SHENRON"

def test_shenron_home_env_overrides_base(monkeypatch, tmp_path):
    cfg = _reload_config(monkeypatch, home=tmp_path)
    assert cfg.get_shenron_base() == tmp_path

def test_log_dir_is_under_base(monkeypatch, tmp_path):
    cfg = _reload_config(monkeypatch, home=tmp_path)
    assert cfg.get_log_dir() == tmp_path / "logs"

def test_log_dir_is_created(monkeypatch, tmp_path):
    cfg = _reload_config(monkeypatch, home=tmp_path)
    log_dir = cfg.get_log_dir()
    assert log_dir.exists()
    assert log_dir.is_dir()

def test_artifact_log_path_suffix(monkeypatch, tmp_path):
    cfg = _reload_config(monkeypatch, home=tmp_path)
    assert cfg.artifact_log_path().name == "simulation_artifacts.jsonl"

def test_timeline_log_path_suffix(monkeypatch, tmp_path):
    cfg = _reload_config(monkeypatch, home=tmp_path)
    assert cfg.timeline_log_path().name == "scenario_timelines.jsonl"

def test_mutation_history_path_suffix(monkeypatch, tmp_path):
    cfg = _reload_config(monkeypatch, home=tmp_path)
    assert cfg.mutation_history_path().name == "mutation_history.json"

def test_artifact_log_under_log_dir(monkeypatch, tmp_path):
    cfg = _reload_config(monkeypatch, home=tmp_path)
    assert cfg.artifact_log_path().parent == cfg.get_log_dir()

def test_timeline_log_under_log_dir(monkeypatch, tmp_path):
    cfg = _reload_config(monkeypatch, home=tmp_path)
    assert cfg.timeline_log_path().parent == cfg.get_log_dir()

def test_mutation_history_under_log_dir(monkeypatch, tmp_path):
    cfg = _reload_config(monkeypatch, home=tmp_path)
    assert cfg.mutation_history_path().parent == cfg.get_log_dir()

def test_default_report_dir_is_repo_local(monkeypatch):
    cfg = _reload_config(monkeypatch)
    report_dir = cfg.get_report_dir()
    assert report_dir.name == "reports"
    # Should be within the repo, not under SHENRON home
    assert "SHENRON" not in str(report_dir) or report_dir == Path.home() / "SHENRON" / "reports"

def test_shenron_report_dir_env_overrides(monkeypatch, tmp_path):
    cfg = _reload_config(monkeypatch, report_dir=tmp_path)
    assert cfg.get_report_dir() == tmp_path

def test_report_dir_is_created(monkeypatch, tmp_path):
    report_path = tmp_path / "custom_reports"
    cfg = _reload_config(monkeypatch, report_dir=report_path)
    assert cfg.get_report_dir().exists()

def test_shenron_home_affects_all_log_paths(monkeypatch, tmp_path):
    cfg = _reload_config(monkeypatch, home=tmp_path)
    for fn in [cfg.artifact_log_path, cfg.timeline_log_path, cfg.mutation_history_path]:
        assert str(tmp_path) in str(fn())

def test_no_hardcoded_paths_in_core():
    """Verify no hardcoded /home/gnomeman4201 paths remain in core/ or scripts/."""
    bad = []
    path_marker = "/home/gnomeman4201/SHENRON"
    for f in Path("core").rglob("*.py"):
        try:
            c = f.read_text(encoding="utf-8", errors="ignore")
            if path_marker in c:
                bad.append(str(f))
        except Exception:
            pass
    for f in Path("scripts").rglob("*.py"):
        try:
            c = f.read_text(encoding="utf-8", errors="ignore")
            if path_marker in c:
                bad.append(str(f))
        except Exception:
            pass
    assert bad == [], f"Hardcoded paths found in: {bad}"

def test_no_hardcoded_paths_in_shenron_py():
    """shenron.py should not contain hardcoded /home/gnomeman4201 paths."""
    content = Path("shenron.py").read_text()
    assert "/home/gnomeman4201/SHENRON" not in content
