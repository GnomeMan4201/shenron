import json
import yaml
from pathlib import Path
from core.assumptions.model import Claim, ClaimType, ClaimSeverity


def _load_yaml_simple(path: Path) -> dict:
    """Load assumption YAML using PyYAML. Normalizes to expected structure."""
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        return {"id": "", "description": "", "claims": []}
    result = {
        "id":          str(data.get("id", "")),
        "description": str(data.get("description", "")),
        "claims":      [],
    }
    for claim in data.get("claims", []):
        if not isinstance(claim, dict):
            continue
        result["claims"].append({
            "id":                   str(claim.get("id", "")),
            "type":                 str(claim.get("type", "positive_evidence")),
            "severity":             str(claim.get("severity", "medium")),
            "description":          str(claim.get("description", "")),
            "requires_techniques":  [str(t) for t in claim.get("requires_techniques", [])],
            "requires_signals":     [str(s) for s in claim.get("requires_signals", [])],
            "requires_metrics":    list(claim.get("requires_metrics", [])),
        })
    return result


def load_assumption(path) -> tuple:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Assumption file not found: {path}")
    data = _load_yaml_simple(p)
    claims = []
    for c in data.get("claims", []):
        claims.append(Claim(
            id                  = c.get("id", ""),
            type                = ClaimType(c.get("type", "positive_evidence")),
            severity            = ClaimSeverity(c.get("severity", "medium")),
            description         = c.get("description", ""),
            requires_techniques = c.get("requires_techniques", []),
            requires_signals    = c.get("requires_signals", []),
            requires_metrics    = c.get("requires_metrics", []),
        ))
    return data.get("id", p.stem), data.get("description", ""), claims


def load_artifacts(path) -> list:
    p = Path(path)
    if not p.exists():
        return []
    records = []
    with open(p) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records
