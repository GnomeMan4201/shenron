#!/usr/bin/env python3
# SHENRON: Detector validation dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class DetectionStatus(str, Enum):
    PASS    = "PASS"
    MISS    = "MISS"
    PARTIAL = "PARTIAL"


@dataclass
class DetectionExpectation:
    name:             str
    normalized:       str
    layer:            Optional[str]  = None
    mitre_technique:  Optional[str]  = None
    artifact_field:   Optional[str]  = None
    artifact_value:   Optional[str]  = None
    phase:            Optional[str]  = None


@dataclass
class DetectionResult:
    expectation:      DetectionExpectation
    status:           DetectionStatus     = DetectionStatus.MISS
    matched_layer:    Optional[str]       = None
    matched_artifact: Optional[str]       = None
    match_reason:     str                 = ""
    evidence_count:   int                 = 0


@dataclass
class DetectionCoverageReport:
    run_id:               str        = ""
    campaign_name:        str        = ""
    scenario_path:        str        = ""
    expected_count:       int        = 0
    observed_count:       int        = 0
    missing_count:        int        = 0
    partial_count:        int        = 0
    coverage_percent:     float      = 0.0
    high_signal_count:    int        = 0
    safety_failure_count: int        = 0
    verdict:              str        = "UNKNOWN"
    results:              List[DetectionResult] = field(default_factory=list)

    def compute(self):
        self.expected_count  = len(self.results)
        self.observed_count  = sum(1 for r in self.results if r.status == DetectionStatus.PASS)
        self.partial_count   = sum(1 for r in self.results if r.status == DetectionStatus.PARTIAL)
        self.missing_count   = sum(1 for r in self.results if r.status == DetectionStatus.MISS)
        effective = self.observed_count + (self.partial_count * 0.5)
        self.coverage_percent = round(
            (effective / self.expected_count * 100) if self.expected_count > 0 else 0.0, 1
        )
        if self.safety_failure_count > 0:
            self.verdict = "UNSAFE"
        elif self.coverage_percent >= 80.0:
            self.verdict = "PASS"
        elif self.coverage_percent >= 50.0:
            self.verdict = "PARTIAL"
        else:
            self.verdict = "FAIL"

    def to_dict(self) -> dict:
        return {
            "run_id":               self.run_id,
            "campaign_name":        self.campaign_name,
            "scenario_path":        self.scenario_path,
            "expected_count":       self.expected_count,
            "observed_count":       self.observed_count,
            "partial_count":        self.partial_count,
            "missing_count":        self.missing_count,
            "coverage_percent":     self.coverage_percent,
            "high_signal_count":    self.high_signal_count,
            "safety_failure_count": self.safety_failure_count,
            "verdict":              self.verdict,
            "results": [
                {
                    "detection":     r.expectation.name,
                    "status":        r.status.value,
                    "layer":         r.matched_layer,
                    "reason":        r.match_reason,
                    "evidence_count":r.evidence_count,
                }
                for r in self.results
            ],
        }
