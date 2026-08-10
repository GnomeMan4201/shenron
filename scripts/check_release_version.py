#!/usr/bin/env python3
"""Fail when package, changelog, and release tag versions disagree."""
import argparse
from pathlib import Path
import re
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from core.version import version_from_pyproject  # noqa: E402


_CHANGELOG_RELEASE = re.compile(
    r"(?m)^## \[v(?P<version>\d+\.\d+\.\d+)\](?:\s+—\s+\d{4}-\d{2}-\d{2})?\s*$"
)


def latest_changelog_version(path: Path) -> str:
    match = _CHANGELOG_RELEASE.search(path.read_text(encoding="utf-8"))
    if not match:
        raise RuntimeError(f"No released version section found in {path}")
    return match.group("version")


def check_release_version(tag: str | None = None) -> str:
    project_version = version_from_pyproject(REPO_ROOT / "pyproject.toml")
    changelog_version = latest_changelog_version(REPO_ROOT / "CHANGELOG.md")

    if project_version != changelog_version:
        raise RuntimeError(
            "Release metadata mismatch: "
            f"pyproject.toml={project_version}, CHANGELOG.md={changelog_version}"
        )

    if tag is not None:
        expected_tag = f"v{project_version}"
        if tag != expected_tag:
            raise RuntimeError(
                f"Release tag mismatch: received {tag}, expected {expected_tag}"
            )

    return project_version


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", help="tag to compare with the project version")
    args = parser.parse_args()

    try:
        resolved = check_release_version(args.tag)
    except RuntimeError as exc:
        print(f"[release-version] ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"[release-version] OK: v{resolved}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
