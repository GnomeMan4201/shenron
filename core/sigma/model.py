from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any


class MatchStatus(str, Enum):
    TRIGGERED       = "TRIGGERED"
    NOT_TRIGGERED   = "NOT_TRIGGERED"
    PARTIAL         = "PARTIAL"
    UNSUPPORTED     = "UNSUPPORTED"   # rule uses fields SHENRON doesn't emit


class RuleVerdict(str, Enum):
    TRIGGERED       = "TRIGGERED"
    NOT_TRIGGERED   = "NOT_TRIGGERED"
    PARTIAL         = "PARTIAL"
    UNSUPPORTED     = "UNSUPPORTED"
    ERROR           = "ERROR"


@dataclass
class FieldMatch:
    field:          str
    expected:       Any
    found_in:       List[Any]   = field(default_factory=list)
    matched:        bool        = False
    artifact_count: int         = 0


@dataclass
class DetectionMatch:
    detection_name: str
    status:         MatchStatus
    field_matches:  List[FieldMatch] = field(default_factory=list)
    matched_artifacts: List[dict]    = field(default_factory=list)
    reason:         str              = ""


@dataclass
class SigmaResult:
    rule_id:        str
    rule_title:     str
    rule_file:      str
    artifact_file:  str
    verdict:        RuleVerdict
    detections:     List[DetectionMatch] = field(default_factory=list)
    triggered_count: int                 = 0
    missed_fields:  List[str]            = field(default_factory=list)
    coverage_note:  str                  = ""
    timestamp:      str                  = ""

    def to_dict(self) -> dict:
        return {
            "rule_id":        self.rule_id,
            "rule_title":     self.rule_title,
            "rule_file":      self.rule_file,
            "artifact_file":  self.artifact_file,
            "verdict":        self.verdict.value,
            "triggered_count":self.triggered_count,
            "missed_fields":  self.missed_fields,
            "coverage_note":  self.coverage_note,
            "timestamp":      self.timestamp,
            "detections": [
                {
                    "name":    d.detection_name,
                    "status":  d.status.value,
                    "reason":  d.reason,
                    "matched_artifact_count": len(d.matched_artifacts),
                    "field_matches": [
                        {"field": fm.field, "expected": fm.expected,
                         "matched": fm.matched, "found_in": fm.found_in[:3]}
                        for fm in d.field_matches
                    ]
                }
                for d in self.detections
            ]
        }
