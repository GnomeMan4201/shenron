import re
import json
from pathlib import Path
from datetime import datetime, timezone
from core.assumptions.model import (
    Claim, ClaimType, ClaimStatus, AssumptionStatus,
    ClaimResult, AssumptionResult,
)
from core.assumptions.loader import (
    load_assumption, load_artifacts as _load, qualify_evidence_record,
)
from core.ingest.jsonl import (
    ArtifactInputError, DuplicateKeyError, reject_duplicate_keys,
)


def _normalize(s: str) -> str:
    s = s.lower().strip()
    s = re.sub(r"-", "_", s)
    s = re.sub(r"[\s_]+", "_", s)
    return s


def _artifact_signals(art: dict) -> set:
    signals = set()
    for f in ["behavior_class", "phase", "detection_opportunities",
              "expected_events", "alert_signatures"]:
        val = art.get(f)
        if isinstance(val, str):
            signals.add(_normalize(val))
        elif isinstance(val, list):
            for v in val:
                signals.add(_normalize(str(v)))
    return signals


def _technique(value) -> str:
    return str(value).strip().upper()


def _artifact_techniques(art: dict) -> set:
    techs = set()
    for f in ["mitre_techniques", "mitre_technique", "technique", "techniques"]:
        val = art.get(f)
        if isinstance(val, str):
            techs.add(_technique(val))
        elif isinstance(val, list):
            for v in val:
                techs.add(_technique(v))
    return techs


def _prohibited_present(tech: str, observed: set) -> bool:
    # Absence checks only: a prohibited parent (T1048) is also violated by any
    # of its sub-techniques (T1048.003). The reverse is deliberately not
    # applied, and positive requirements remain exact.
    if tech in observed:
        return True
    return "." not in tech and any(t.startswith(tech + ".") for t in observed)


def _check_claim(claim: Claim, artifacts: list, graph: dict = None) -> ClaimResult:
    if claim.type == ClaimType.METRIC_THRESHOLD:
        return _check_metric_claim(claim, graph or {})
    result = ClaimResult(claim=claim)
    all_techniques, all_signals = set(), set()
    for art in artifacts:
        all_techniques |= _artifact_techniques(art)
        all_signals    |= _artifact_signals(art)

    # A positive claim may opt in to requiring all its evidence in ONE
    # artifact. Preserve category-wide aggregation for legacy claims and
    # out-of-scope checks (which must inspect every artifact).
    if claim.type == ClaimType.POSITIVE_EVIDENCE and claim.evidence_scope == "same_artifact":
        required_techs = {_technique(t) for t in claim.requires_techniques}
        required_signals = {_normalize(s) for s in claim.requires_signals}
        candidates = [
            (_artifact_techniques(art), _artifact_signals(art))
            for art in artifacts
        ]
        if candidates:
            all_techniques, all_signals = max(
                candidates,
                key=lambda pair: (
                    len(required_techs & pair[0]) + len(required_signals & pair[1]),
                    len(required_techs & pair[0]),
                ),
            )
        else:
            all_techniques, all_signals = set(), set()

    supported, unsupported = [], []

    for tech in claim.requires_techniques:
        if claim.type == ClaimType.OUT_OF_SCOPE:
            present = _prohibited_present(_technique(tech), all_techniques)
        else:
            present = _technique(tech) in all_techniques
        (supported if present else unsupported).append(tech)

    for sig in claim.requires_signals:
        norm = _normalize(sig)
        matched = norm in all_signals
        (supported if matched else unsupported).append(sig)

    result.supported         = supported
    result.unsupported       = unsupported
    result.matched_artifacts = len(artifacts)
    total                    = len(supported) + len(unsupported)

    if claim.type == ClaimType.OUT_OF_SCOPE:
        if supported:
            result.status = ClaimStatus.OUT_OF_SCOPE
            result.reason = f"Out-of-scope evidence found: {supported}"
        else:
            result.status = ClaimStatus.SUPPORTED
            result.reason = "Correctly absent"
    elif total == 0:
        result.status = ClaimStatus.UNRESOLVED
        result.reason = "No requirements specified"
    elif not unsupported:
        result.status = ClaimStatus.SUPPORTED
        result.reason = f"All {len(supported)} required signals present"
    elif not supported:
        result.status = ClaimStatus.UNSUPPORTED
        result.reason = f"No required signals found ({len(unsupported)} missing)"
    else:
        result.status = ClaimStatus.PARTIALLY_SUPPORTED
        result.reason = f"{len(supported)} of {total} signals present"

    return result


def _safe_conclusion(assumption_id: str, results: list) -> str:
    pos = [r for r in results if r.claim.type in (ClaimType.POSITIVE_EVIDENCE, ClaimType.METRIC_THRESHOLD)]
    supported   = [r for r in pos if r.status == ClaimStatus.SUPPORTED]
    unsupported = [r for r in pos if r.status != ClaimStatus.SUPPORTED]
    oos = [r for r in results if r.status == ClaimStatus.OUT_OF_SCOPE]

    if supported and not unsupported:
        base = f"This artifact supports validation claims about {assumption_id}-shaped telemetry."
    elif supported and unsupported:
        base = (f"This artifact partially supports {assumption_id} claims. "
                f"{len(supported)} supported, {len(unsupported)} not fully supported.")
    else:
        base = f"This artifact does not support {assumption_id} validation claims."

    caveat = "This artifact should not be used to claim broad detection coverage beyond what is explicitly supported above."
    if oos:
        warn = f"WARNING: {len(oos)} out-of-scope claim(s) detected."
        return f"{base} {warn} {caveat}"
    return f"{base} {caveat}"



def load_graph_artifact(path) -> dict:
    """Load a JSON graph artifact (e.g. Jaccard botnet result)."""
    p = Path(path)
    if not p.exists():
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            graph = json.load(f, object_pairs_hook=reject_duplicate_keys)
    except DuplicateKeyError as exc:
        raise ArtifactInputError(
            f"Malformed JSON: duplicate key {exc.args[0]!r} in {p}"
        ) from None
    if isinstance(graph, dict):
        # The graph object is matched as one evidence record, so it gets the
        # same qualification as each JSONL record.
        qualify_evidence_record(graph, str(p))
    return graph


def _evaluate_metric(operator: str, value: float, threshold: float) -> bool:
    ops = {
        "gte": value >= threshold,
        "lte": value <= threshold,
        "gt":  value > threshold,
        "lt":  value < threshold,
        "eq":  value == threshold,
    }
    return ops.get(operator, False)


def _check_metric_claim(claim: Claim, graph: dict) -> ClaimResult:
    result = ClaimResult(claim=claim)
    supported, unsupported = [], []

    for req in claim.requires_metrics:
        field     = req.get("field", "")
        operator  = req.get("operator", "gte")
        threshold = float(req.get("threshold", 0))
        value     = graph.get(field)

        if value is None:
            unsupported.append(f"{field} not present in artifact")
        elif _evaluate_metric(operator, float(value), threshold):
            supported.append(f"{field}={value} {operator} {threshold}")
        else:
            unsupported.append(f"{field}={value} failed {operator} {threshold}")

    result.supported   = supported
    result.unsupported = unsupported
    result.matched_artifacts = 1 if graph else 0
    total = len(supported) + len(unsupported)

    if total == 0:
        result.status = ClaimStatus.UNRESOLVED
        result.reason = "No metric requirements specified"
    elif not unsupported:
        result.status = ClaimStatus.SUPPORTED
        result.reason = f"All {len(supported)} metric(s) satisfied"
    elif not supported:
        result.status = ClaimStatus.UNSUPPORTED
        result.reason = f"No metrics satisfied ({len(unsupported)} failed)"
    else:
        result.status = ClaimStatus.PARTIALLY_SUPPORTED
        result.reason = f"{len(supported)} of {total} metrics satisfied"

    return result


def validate_assumption(assumption_path, artifact_path, *,
                        require_current_schema: bool = False) -> AssumptionResult:
    if require_current_schema:
        assumption_id, _, claims = load_assumption(
            assumption_path, require_current_schema=True
        )
    else:
        # Preserve the existing single-argument loader call contract.
        assumption_id, _, claims = load_assumption(assumption_path)
    p = Path(artifact_path)
    # A missing evidence file is not a valid empty or negative observation.
    # Keep the optional general-purpose load_artifacts() semantics unchanged.
    if not p.is_file():
        raise FileNotFoundError(
            f"Evidence file not found or not a regular file: {p}"
        )
    if p.suffix == ".json":
        graph     = load_graph_artifact(artifact_path)
        artifacts = [graph] if graph else []
    else:
        graph     = {}
        artifacts = _load(artifact_path)
    claim_results = [_check_claim(c, artifacts, graph=graph) for c in claims]

    pos = [r for r in claim_results if r.claim.type in (ClaimType.POSITIVE_EVIDENCE, ClaimType.METRIC_THRESHOLD)]
    supported_count   = sum(1 for r in pos if r.status == ClaimStatus.SUPPORTED)
    unsupported_count = sum(1 for r in pos if r.status in (
        ClaimStatus.UNSUPPORTED, ClaimStatus.PARTIALLY_SUPPORTED))
    unresolved_count = sum(1 for r in pos if r.status == ClaimStatus.UNRESOLVED)
    oos_violations = [r.claim.id for r in claim_results
                      if r.status == ClaimStatus.OUT_OF_SCOPE]

    total = supported_count + unsupported_count + unresolved_count
    if oos_violations:
        status = AssumptionStatus.OUT_OF_SCOPE_VIOLATION
    elif total == 0:
        status = AssumptionStatus.UNSUPPORTED
    elif unsupported_count == 0 and unresolved_count == 0:
        status = AssumptionStatus.SUPPORTED
    elif supported_count > 0:
        status = AssumptionStatus.PARTIALLY_SUPPORTED
    else:
        status = AssumptionStatus.UNSUPPORTED

    return AssumptionResult(
        assumption_id           = assumption_id,
        assumption_file         = str(assumption_path),
        artifact_file           = str(artifact_path),
        status                  = status,
        claim_results           = claim_results,
        supported_count         = supported_count,
        unsupported_count       = unsupported_count,
        out_of_scope_violations = oos_violations,
        safe_conclusion         = _safe_conclusion(assumption_id, claim_results),
        timestamp               = datetime.now(timezone.utc).isoformat(),
    )


def print_result(result: AssumptionResult):
    badge = {
        AssumptionStatus.SUPPORTED:              "SUPPORTED",
        AssumptionStatus.PARTIALLY_SUPPORTED:    "PARTIALLY SUPPORTED",
        AssumptionStatus.UNSUPPORTED:            "UNSUPPORTED",
        AssumptionStatus.OUT_OF_SCOPE_VIOLATION: "OUT-OF-SCOPE VIOLATION",
    }.get(result.status, result.status.value)

    print(f"\n  ASSUMPTION: {result.assumption_id}")
    print(f"  STATUS:     {badge}")
    print(f"  ARTIFACT:   {result.artifact_file}")
    print()

    pos = [r for r in result.claim_results if r.claim.type in (ClaimType.POSITIVE_EVIDENCE, ClaimType.METRIC_THRESHOLD)]
    oos = [r for r in result.claim_results if r.claim.type == ClaimType.OUT_OF_SCOPE]

    print("  Supported claims:")
    for r in pos:
        for s in r.supported:
            print(f"    + {s}")
    print()
    print("  Unsupported claims:")
    for r in pos:
        for u in r.unsupported:
            print(f"    - {u}")
    print()

    if oos:
        print("  Out-of-scope checks:")
        for r in oos:
            mark = "VIOLATION" if r.status == ClaimStatus.OUT_OF_SCOPE else "ok"
            print(f"    [{mark}] {r.claim.id} ({r.claim.severity.value})")
        print()

    print("  Boundary:")
    for line in result.safe_conclusion.split(". "):
        if line.strip():
            print(f"    {line.strip()}.")
    print()
