"""Resolve the SHENRON package version from source or installed metadata."""
from importlib.metadata import PackageNotFoundError, version as distribution_version
from pathlib import Path
import re


_PROJECT_VERSION = re.compile(
    r"(?ms)^\[project\]\s+.*?^version\s*=\s*[\"']([^\"']+)[\"']"
)


def version_from_pyproject(path: Path) -> str:
    """Return the PEP 621 project version from a pyproject.toml file."""
    match = _PROJECT_VERSION.search(path.read_text(encoding="utf-8"))
    if not match:
        raise RuntimeError(f"Unable to resolve [project].version from {path}")
    return match.group(1)


def get_version() -> str:
    """Return the source-tree version, falling back to installed metadata."""
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    if pyproject.exists():
        return version_from_pyproject(pyproject)
    try:
        return distribution_version("shenron")
    except PackageNotFoundError:
        return "0+unknown"
