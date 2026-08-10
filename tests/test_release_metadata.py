import subprocess
import sys
from pathlib import Path

from core.navigator import build_navigator_layer
from core.version import get_version, version_from_pyproject
from scripts.check_release_version import check_release_version, latest_changelog_version


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_project_and_changelog_versions_match():
    project = version_from_pyproject(REPO_ROOT / "pyproject.toml")
    changelog = latest_changelog_version(REPO_ROOT / "CHANGELOG.md")
    assert project == changelog == "0.4.4"
    assert check_release_version("v0.4.4") == "0.4.4"


def test_version_command_uses_project_metadata():
    result = subprocess.run(
        [sys.executable, "shenron.py", "--version"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == f"shenron {get_version()}"


def test_navigator_metadata_uses_current_version():
    layer = build_navigator_layer(["T1071"], run_id="test", campaign_name="test")
    generated_by = next(
        item["value"] for item in layer["metadata"]
        if item["name"] == "generated_by"
    )
    assert generated_by == f"SHENRON v{get_version()}"
