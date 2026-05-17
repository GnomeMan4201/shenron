import re
from datetime import datetime, timezone
from core.assumptions.model import (
    Claim, ClaimType, ClaimStatus, AssumptionStatus,
    ClaimResult, AssumptionResult,
)
from core.assumptions.loader import load_assumption, load_artifacts as _load


def _normalize(s: str) -> str:
    s = s.lower().strip()
    s = re.sub(r"-", "_", s)
    s = re.sub(r"[^a-z0-9_\s]", "", s)
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


def _artifact_techniques(art: dict) -> set:
    techs = set()
    for f in ["mitre_techniques", "technique", "techniques"]:
        val = art.get(f)
        if isinstance(val, str):
            techs.add(val.upper())
        elif isinstance(val, list):
            for v in val:
                techs.add(str(v).upper())
    return techs


def _check_claim(claim: Claim, artifacts: list) -> ClaimResult:
    result = ClaimResult(claim=claim)
    all_techniques, all_signals = set(), set()
    for art in artifacts:
        all_techniques |= _artifact_techniques(art)
        all_signals    |= _artifact_signals(art)

    supported, unsupported = [], []

    for tech in claim.requires_techniques:
        (supported if tech.upper() in all_techniques else unsupported).append(tech)

    for sig in claim.requires_signals:
        norm = _normalize(sig)
        matched = any(
            norm == s or norm in s or s in norm or
            len(set(norm.split("_")) & set(s.split("_"))) / max(len(norm.split("_")), 1) >= 0.5
            for s in all_signals
        )
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
    pos = [r for r in results if r.claim.type == ClaimType.POSITIVE_EVIDENCE]
    supported   = [r for r in pos if r.status == ClaimStatus.SUPPORTED]
    unsupported = [r for r in pos if r.status in (ClaimStatus.UNSUPPORTED,
                                                   ClaimStatus.PARTIALLY_SUPPORTED)]
    oos = [r for r in results if r.status == ClaimStatus.OUT_OF_SCOPE]

    if supported and not unsupported:
        base = f"This artifact supports validation claims about {assumption_id}-shaped telemetry."
    elif supported and unsupported:
        base = (f"This artifact partially supports {assumption_id} claims. "
                f"{len(supported)} supported, {len(unsupported)} unsupported.")
    else:
        base = f"This artifact does not support {assumption_id} validation claims."

    caveat = "This artifact should not be used to claim broad detection coverage beyond what is explicitly supported above."
    if oos:
        warn = f"WARNING: {len(oos)} out-of-scope claim(s) detected."
        return f"{base} {warn} {caveat}"
    return f"{base} {caveat}"


def validate_assumption(assumption_path, artifact_path) -> AssumptionResult:
    assumption_id, _, claims = load_assumption(assumption_path)
    artifacts     = _load(artifact_path)
    claim_results = [_check_claim(c, artifacts) for c in claims]

    pos = [r for r in claim_results if r.claim.type == ClaimType.POSITIVE_EVIDENCE]
    supported_count   = sum(1 for r in pos if r.status == ClaimStatus.SUPPORTED)
    unsupported_count = sum(1 for r in pos if r.status in (
        ClaimStatus.UNSUPPORTED, ClaimStatus.PARTIALLY_SUPPORTED))
    oos_violations = [r.claim.id for r in claim_results
                      if r.status == ClaimStatus.OUT_OF_SCOPE]

    total = supported_count + unsupported_count
    if oos_violations:
        status = AssumptionStatus.OUT_OF_SCOPE_VIOLATION
    elif total == 0:
        status = AssumptionStatus.UNSUPPORTED
    elif unsupported_count == 0:
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

    pos = [r for r in result.claim_results if r.claim.type == ClaimType.POSITIVE_EVIDENCE]
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
