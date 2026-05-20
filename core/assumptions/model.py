from dataclasses import dataclass, field
from enum import Enum
from typing import List

class ClaimType(str, Enum):
    POSITIVE_EVIDENCE = "positive_evidence"
    OUT_OF_SCOPE      = "out_of_scope_claim"
    METRIC_THRESHOLD  = "metric_threshold"

class ClaimSeverity(str, Enum):
    LOW    = "low"
    MEDIUM = "medium"
    HIGH   = "high"

class ClaimStatus(str, Enum):
    SUPPORTED           = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    UNSUPPORTED         = "UNSUPPORTED"
    OUT_OF_SCOPE        = "OUT_OF_SCOPE"
    UNRESOLVED          = "UNRESOLVED"

class AssumptionStatus(str, Enum):
    SUPPORTED              = "SUPPORTED"
    PARTIALLY_SUPPORTED    = "PARTIALLY_SUPPORTED"
    UNSUPPORTED            = "UNSUPPORTED"
    OUT_OF_SCOPE_VIOLATION = "OUT_OF_SCOPE_VIOLATION"

@dataclass
class Claim:
    id:                  str
    type:                ClaimType     = ClaimType.POSITIVE_EVIDENCE
    severity:            ClaimSeverity = ClaimSeverity.MEDIUM
    description:         str           = ""
    requires_techniques: List[str]     = field(default_factory=list)
    requires_signals:    List[str]     = field(default_factory=list)
    requires_metrics:   List[dict]    = field(default_factory=list)

@dataclass
class ClaimResult:
    claim:             Claim
    status:            ClaimStatus = ClaimStatus.UNRESOLVED
    supported:         List[str]   = field(default_factory=list)
    unsupported:       List[str]   = field(default_factory=list)
    matched_artifacts: int         = 0
    reason:            str         = ""

@dataclass
class AssumptionResult:
    assumption_id:           str
    assumption_file:         str
    artifact_file:           str
    status:                  AssumptionStatus  = AssumptionStatus.UNSUPPORTED
    claim_results:           List[ClaimResult] = field(default_factory=list)
    supported_count:         int = 0
    unsupported_count:       int = 0
    out_of_scope_violations: List[str] = field(default_factory=list)
    safe_conclusion:         str = ""
    timestamp:               str = ""

    def to_dict(self) -> dict:
        return {
            "assumption_id":          self.assumption_id,
            "assumption_file":        self.assumption_file,
            "artifact_file":          self.artifact_file,
            "status":                 self.status.value,
            "supported_count":        self.supported_count,
            "unsupported_count":      self.unsupported_count,
            "out_of_scope_violations":self.out_of_scope_violations,
            "safe_conclusion":        self.safe_conclusion,
            "timestamp":              self.timestamp,
            "claims": [
                {"id": r.claim.id, "type": r.claim.type.value,
                 "severity": r.claim.severity.value, "status": r.status.value,
                 "supported": r.supported, "unsupported": r.unsupported,
                 "reason": r.reason}
                for r in self.claim_results
            ],
        }
