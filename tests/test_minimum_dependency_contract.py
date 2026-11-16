#!/usr/bin/env python3
"""The declared minimum versions are a compatibility contract.

pyproject.toml declares ">=" minimums; the minimum-dependencies CI job
installs exactly those versions and runs the full suite on them. If the two
drift apart (for example, an automated update raises a minimum), the job no
longer tests what pyproject.toml promises. This keeps them identical.

Raising a minimum on purpose is allowed: change pyproject.toml and the
minimum-dependencies job's pins together, in the same PR. This test only
rejects one changing without the other.

Formatting assumptions (deliberately simple text parsing, because the
minimum supported Python, 3.10, has no tomllib and the job is plain YAML):
  * pyproject.toml lists requirements as quoted strings between
    `dependencies = [` and `[project.scripts]`;
  * the minimum-dependencies job pins each one as 'name==version' before
    its "Verify minimum dependency consistency" step.
If either file is restructured, update the two helpers below; a parsing
failure here means the helpers are stale, not that the contract broke.
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
    ci = _ci_minimums()
    assert declared, "no >= minimums parsed from pyproject.toml: helper is stale?"
    assert ci, "no pins parsed from the minimum-dependencies job: helper is stale?"
    assert declared == ci, (
        "pyproject.toml minimums and the minimum-dependencies CI pins differ. "
        "If you raised a minimum on purpose, update both in the same change."
    )


def test_minimums_are_lower_bounds_without_caps():
    """Only plain >= minimums: a newer release always satisfies them, so
    Dependabot's increase-if-necessary strategy never needs to edit them."""
    for spec in re.findall(r'"([^"]+)"', _dependency_block()):
        assert re.fullmatch(r"[A-Za-z0-9_.\-]+>=[0-9][0-9.]*", spec), spec


def _requirements_txt_minimums():
    lines = (ROOT / "requirements.txt").read_text().splitlines()
    pins = [re.fullmatch(r"([A-Za-z0-9_.\-]+)>=([0-9][0-9.]*)", l.strip()) for l in lines]
    return {m.group(1).lower(): Version(m.group(2)) for m in pins if m}


def test_requirements_txt_matches_runtime_minimums():
    """requirements.txt repeats the runtime minimums; it must not drift either.

    Dependabot's pip updater edits this file too (see #45's original diff).
    """
    runtime_block = _dependency_block().split("[project.optional-dependencies]")[0]
    runtime = {n.lower(): Version(v) for n, v in re.findall(r'"([A-Za-z0-9_.\-]+)>=([0-9][^",;\s]*)"', runtime_block)}
    req = _requirements_txt_minimums()
    assert req, "no >= minimums parsed from requirements.txt: helper is stale?"
    assert req == runtime, "requirements.txt and pyproject.toml runtime minimums differ"

