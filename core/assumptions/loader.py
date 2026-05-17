import json
from pathlib import Path
from core.assumptions.model import Claim, ClaimType, ClaimSeverity


def _load_yaml_simple(path: Path) -> dict:
    lines = path.read_text().splitlines()
    result = {"id": "", "description": "", "claims": []}
    current_claim = None
    current_list_key = None
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            if ":" in stripped:
                k, _, v = stripped.partition(":")
                v = v.strip().strip('"')
                if k in ("id", "description"):
                    result[k] = v
        elif indent == 2:
            if stripped.startswith("- id:"):
                if current_claim:
                    result["claims"].append(current_claim)
                val = stripped.replace("- id:", "").strip().strip('"')
                current_claim = {"id": val, "type": "positive_evidence",
                                 "severity": "medium", "description": "",
                                 "requires_techniques": [], "requires_signals": []}
                current_list_key = None
        elif indent == 4 and current_claim is not None:
            if ":" in stripped:
                k, _, v = stripped.partition(":")
                v = v.strip().strip('"')
                if k in ("type", "severity", "description"):
                    current_claim[k] = v
                elif k in ("requires_techniques", "requires_signals"):
                    current_list_key = k
                else:
                    current_list_key = None
            elif stripped.startswith("- ") and current_list_key:
                current_claim[current_list_key].append(stripped[2:].strip().strip('"'))
        elif indent == 6 and current_claim and current_list_key:
            if stripped.startswith("- "):
                current_claim[current_list_key].append(stripped[2:].strip().strip('"'))
    if current_claim:
        result["claims"].append(current_claim)
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
