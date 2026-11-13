from core.ingest.jsonl import load_jsonl_objects, ArtifactInputError
import warnings
import yaml
from pathlib import Path
from core.assumptions.model import Claim, ClaimType, ClaimSeverity

CURRENT_SCHEMA_VERSION = "1.0"

# Every key a claim may carry. Anything else is rejected rather than ignored:
# a misspelled requirement or scope key would otherwise silently weaken the claim.
_CLAIM_KEYS = frozenset({
    "id", "type", "severity", "description", "requires_techniques",
    "requires_signals", "requires_metrics", "evidence_scope",
})

# Fields used by assumption matching must have interpretable types.
_EVIDENCE_FIELDS = frozenset({
    "mitre_techniques", "technique", "techniques", "behavior_class", "phase",
    "detection_opportunities", "expected_events", "alert_signatures",
})


def _load_yaml_simple(path: Path, *, require_current_schema: bool = False) -> dict:
    """Load assumption YAML using PyYAML. Normalizes to expected structure."""
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        if require_current_schema:
            raise ValueError(f"{path}: assumption YAML must contain a mapping")
        return {"id": "", "description": "", "schema_version": None, "claims": []}

    schema_version = data.get("schema_version")
    if require_current_schema and str(schema_version) != CURRENT_SCHEMA_VERSION:
        raise ValueError(
            f"{path}: schema_version {schema_version!r} is not qualified; "
            f"required {CURRENT_SCHEMA_VERSION!r}"
        )
    if schema_version is None:
        warnings.warn(
            f"[shenron] {path.name}: missing 'schema_version' field. "
            f"Expected '{CURRENT_SCHEMA_VERSION}'. "
            f"Add 'schema_version: \"{CURRENT_SCHEMA_VERSION}\"' to suppress this warning.",
            UserWarning,
            stacklevel=4,
        )
    elif str(schema_version) != CURRENT_SCHEMA_VERSION:
        warnings.warn(
            f"[shenron] {path.name}: schema_version '{schema_version}' != "
            f"current '{CURRENT_SCHEMA_VERSION}'. Validation results may be unreliable.",
            UserWarning,
            stacklevel=4,
        )

    result = {
        "id":             str(data.get("id", "")),
        "description":    str(data.get("description", "")),
        "schema_version": schema_version,
        "claims":         [],
    }
    for index, claim in enumerate(data.get("claims", []), 1):
        if not isinstance(claim, dict):
            raise ValueError(f"{path}: claim {index} must be a JSON-style object")
        unknown = sorted(str(k) for k in claim if k not in _CLAIM_KEYS)
        if unknown:
            raise ValueError(
                f"{path}: claim {index} has unknown claim key(s) {unknown}; "
                f"allowed: {sorted(_CLAIM_KEYS)}"
            )
        for field in ("requires_techniques", "requires_signals"):
            values = claim.get(field, [])
            if not isinstance(values, list) or any(
                not isinstance(item, str) or not item.strip() for item in values
            ):
                raise ValueError(
                    f"{path}: claim {index} {field} must be a list of nonblank strings"
                )
        metrics = claim.get("requires_metrics", [])
        if not isinstance(metrics, list) or any(
            not isinstance(item, dict) for item in metrics
        ):
            raise ValueError(f"{path}: claim {index} requires_metrics must be a list of objects")
        scope = claim.get("evidence_scope", "category")
        if scope not in ("category", "same_artifact"):
            raise ValueError(f"Invalid evidence_scope for {claim.get('id', '')}: {scope}")
        result["claims"].append({
            "id":                  str(claim.get("id", "")),
            "evidence_scope":      scope,
            "type":                str(claim.get("type", "positive_evidence")),
            "severity":            str(claim.get("severity", "medium")),
            "description":         str(claim.get("description", "")),
            "requires_techniques": claim.get("requires_techniques", []),
            "requires_signals":    claim.get("requires_signals", []),
            "requires_metrics":    metrics,
        })
    return result


def load_assumption(path, *, require_current_schema: bool = False) -> tuple:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Assumption file not found: {path}")
    data = _load_yaml_simple(p, require_current_schema=require_current_schema)
    claims = []
    for c in data.get("claims", []):
        claim = Claim(
            id                  = c.get("id", ""),
            type                = ClaimType(c.get("type", "positive_evidence")),
            severity            = ClaimSeverity(c.get("severity", "medium")),
            description         = c.get("description", ""),
            requires_techniques = c.get("requires_techniques", []),
            requires_signals    = c.get("requires_signals", []),
            requires_metrics    = c.get("requires_metrics", []),
            evidence_scope      = c.get("evidence_scope", "category"),
        )
        if claim.type in (ClaimType.POSITIVE_EVIDENCE, ClaimType.OUT_OF_SCOPE) and not (
            claim.requires_techniques or claim.requires_signals
        ):
            raise ValueError(f"{p}: claim {claim.id!r} has no requirements")
        if claim.type == ClaimType.METRIC_THRESHOLD and not claim.requires_metrics:
            raise ValueError(f"{p}: metric claim {claim.id!r} has no requirements")
        claims.append(claim)
    return data.get("id", p.stem), data.get("description", ""), claims


def load_artifacts(path) -> list:
    p = Path(path)
    if not p.exists():
        return []

    def check_evidence_types(record, line_number, source):
        for field in _EVIDENCE_FIELDS.intersection(record):
            value = record[field]
            if isinstance(value, str) or (
                isinstance(value, list) and all(isinstance(v, str) for v in value)
            ):
                continue
            raise ArtifactInputError(
                f"{source}: line {line_number}: {field} must be a string or list of strings"
            )

    return load_jsonl_objects(p, record_validator=check_evidence_types)
