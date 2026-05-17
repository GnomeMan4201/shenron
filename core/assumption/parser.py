#!/usr/bin/env python3
# SHENRON: Assumption parser
# Loads defensive coverage assumption files (.yaml) and validates their structure.
# No subprocess, no network, no execution.

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

try:
    import yaml
except ImportError:
    yaml = None  # handled at load time


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class CoverageClaim:
    text:       str
    techniques: List[str] = field(default_factory=list)
    signals:    List[str] = field(default_factory=list)
    phases:     List[str] = field(default_factory=list)


@dataclass
class CoverageAssumption:
    name:                str
    description:         str                = ""
    claims:              List[str]          = field(default_factory=list)
    expected_techniques: List[str]          = field(default_factory=list)
    expected_signals:    List[str]          = field(default_factory=list)
    expected_phases:     List[str]          = field(default_factory=list)
    source_path:         Optional[str]      = None

    def summary(self) -> dict:
        return {
            "name":                self.name,
            "description":         self.description,
            "claims":              len(self.claims),
            "expected_techniques": len(self.expected_techniques),
            "expected_signals":    len(self.expected_signals),
            "expected_phases":     len(self.expected_phases),
        }


# ── Validation ────────────────────────────────────────────────────────────────

VALID_PHASES = {"OBSERVE", "SIMULATE", "EXECUTE", "ADAPT", "SCENARIO"}

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _validate_technique(t: str) -> bool:
    return bool(_TECHNIQUE_RE.match(t.strip()))


def _validate(assumption: CoverageAssumption) -> list:
    errors = []
    if not assumption.name:
        errors.append("'name' is required")
    if not assumption.claims:
        errors.append("'claims' must contain at least one entry")
    for t in assumption.expected_techniques:
        if not _validate_technique(t):
            errors.append(f"Invalid technique ID: '{t}' (expected T####.### format)")
    for p in assumption.expected_phases:
        if p.upper() not in VALID_PHASES:
            errors.append(f"Unknown phase: '{p}' (valid: {sorted(VALID_PHASES)})")
    return errors


# ── Loader ────────────────────────────────────────────────────────────────────

def load_assumption(path: str) -> CoverageAssumption:
    """
    Load a CoverageAssumption from a YAML file.
    Raises ValueError on parse or validation errors.
    """
    if yaml is None:
        raise ImportError(
            "PyYAML is required for assumption files. "
            "Run: pip install pyyaml --break-system-packages"
        )

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Assumption file not found: {path}")

    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Assumption file must be a YAML mapping: {path}")

    assumption = CoverageAssumption(
        name                = str(raw.get("name", "")),
        description         = str(raw.get("description", "")),
        claims              = [str(c) for c in raw.get("claims", [])],
        expected_techniques = [str(t).strip() for t in raw.get("expected_techniques", [])],
        expected_signals    = [str(s).strip() for s in raw.get("expected_signals", [])],
        expected_phases     = [str(p).strip().upper() for p in raw.get("expected_phases", [])],
        source_path         = str(path),
    )

    errors = _validate(assumption)
    if errors:
        raise ValueError(
            f"Assumption file validation failed ({path}):\n" +
            "\n".join(f"  - {e}" for e in errors)
        )

    return assumption


def load_assumption_from_dict(data: dict) -> CoverageAssumption:
    """Load a CoverageAssumption directly from a dict (for tests)."""
    assumption = CoverageAssumption(
        name                = str(data.get("name", "")),
        description         = str(data.get("description", "")),
        claims              = [str(c) for c in data.get("claims", [])],
        expected_techniques = [str(t).strip() for t in data.get("expected_techniques", [])],
        expected_signals    = [str(s).strip() for s in data.get("expected_signals", [])],
        expected_phases     = [str(p).strip().upper() for p in data.get("expected_phases", [])],
    )
    errors = _validate(assumption)
    if errors:
        raise ValueError("\n".join(errors))
    return assumption
