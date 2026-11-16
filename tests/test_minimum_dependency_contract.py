#!/usr/bin/env python3
"""The declared minimum versions are a compatibility contract.

pyproject.toml declares ">=" minimums; the minimum-dependencies CI job
installs exactly those versions and runs the full suite on them. If the two
drift apart (for example, an automated update raises a minimum), the job no
longer tests what pyproject.toml promises. This keeps them identical.
"""
import re
from pathlib import Path

from packaging.version import Version  # installed with pytest

ROOT = Path(__file__).resolve().parent.parent


def _dependency_block():
    """Runtime dependencies and optional (dev) dependencies; not build-system."""
    text = (ROOT / "pyproject.toml").read_text()
    return text[text.index("dependencies = ["):text.index("[project.scripts]")]


def _declared_minimums():
    deps = re.findall(r'"([A-Za-z0-9_.\-]+)>=([0-9][^",;\s]*)"', _dependency_block())
    return {name.lower(): Version(version) for name, version in deps}


def _ci_minimums():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    job = ci[ci.index("minimum-dependencies:"):]
    job = job[:job.index("Verify minimum dependency consistency")]
    pins = re.findall(r"'([A-Za-z0-9_.\-]+)==([0-9][^']*)'", job)
    return {name.lower(): Version(version) for name, version in pins if name.lower() not in {"setuptools"}}


def test_every_declared_minimum_is_tested_by_ci():
    declared = _declared_minimums()
    assert declared, "no >= minimums found in pyproject.toml"
    assert declared == _ci_minimums()


def test_minimums_are_lower_bounds_without_caps():
    """Only plain >= minimums: a newer release always satisfies them, so
    Dependabot's increase-if-necessary strategy never needs to edit them."""
    for spec in re.findall(r'"([^"]+)"', _dependency_block()):
        assert re.fullmatch(r"[A-Za-z0-9_.\-]+>=[0-9][0-9.]*", spec), spec
