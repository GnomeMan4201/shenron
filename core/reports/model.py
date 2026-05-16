#!/usr/bin/env python3
# SHENRON: Report model dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional
import uuid


@dataclass
class SafetyVerification:
    simulation_only:        bool = False
    executable_false:       bool = False
    no_payload_present:     bool = False
    network_calls_false:    bool = False
    processes_spawned_false:bool = False
    all_passed:             bool = False
    violations:             List[str] = field(default_factory=list)

    def evaluate(self, artifacts: list) -> "SafetyVerification":
        for art in artifacts:
            if art.get("simulation_only") is not True:
                self.violations.append(f"simulation_only missing or false in {art.get('artifact_id','?')}")
            if art.get("executable") is not False:
                self.violations.append(f"executable not false in {art.get('artifact_id','?')}")
            if "no_payload_present" in art and art.get("no_payload_present") is not True:
                self.violations.append(f"no_payload_present false in {art.get('artifact_id','?')}")
            if art.get("network_calls_made") is True:
                self.violations.append(f"network_calls_made true in {art.get('artifact_id','?')}")
            if art.get("processes_spawned") is True:
                self.violations.append(f"processes_spawned true in {art.get('artifact_id','?')}")

        self.simulation_only        = all(a.get("simulation_only") is True for a in artifacts) if artifacts else True
        self.executable_false       = all(a.get("executable") is False for a in artifacts) if artifacts else True
        self.no_payload_present     = all(a.get("no_payload_present") is not False for a in artifacts) if artifacts else True
        self.network_calls_false    = all(a.get("network_calls_made") is not True for a in artifacts) if artifacts else True
        self.processes_spawned_false= all(a.get("processes_spawned") is not True for a in artifacts) if artifacts else True
        self.all_passed             = len(self.violations) == 0
        return self

    def to_dict(self) -> dict:
        return {
            "simulation_only":         self.simulation_only,
            "executable_false":        self.executable_false,
            "no_payload_present":      self.no_payload_present,
            "network_calls_false":     self.network_calls_false,
            "processes_spawned_false": self.processes_spawned_false,
            "all_passed":              self.all_passed,
            "violations":              self.violations,
        }


@dataclass
class MITRECoverage:
    techniques:  List[str] = field(default_factory=list)
    tactics:     List[str] = field(default_factory=list)
    by_layer:    dict      = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "techniques": sorted(set(self.techniques)),
            "technique_count": len(set(self.techniques)),
            "tactics":   sorted(set(self.tactics)),
            "by_layer":  self.by_layer,
        }


@dataclass
class DetectionOpportunity:
    layer:       str
    phase:       str
    opportunity: str
    mitre:       List[str] = field(default_factory=list)


@dataclass
class EvidenceRef:
    artifact_id: str
    layer:       str
    phase:       str
    timestamp:   str
    behavior:    str
    safe:        bool = True


@dataclass
class Finding:
    phase:       str
    layer:       str
    description: str
    mitre:       List[str]          = field(default_factory=list)
    evidence:    List[EvidenceRef]  = field(default_factory=list)
    detections:  List[str]          = field(default_factory=list)


@dataclass
class ShenronReport:
    report_id:      str  = field(default_factory=lambda: str(uuid.uuid4()))
    run_id:         str  = ""
    campaign_name:  str  = ""
    generated_at:   str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scenario_path:  str  = ""
    dry_run:        bool = True

    phases_run:     List[str]               = field(default_factory=list)
    layers_run:     List[str]               = field(default_factory=list)
    findings:       List[Finding]           = field(default_factory=list)
    detections:     List[DetectionOpportunity] = field(default_factory=list)
    mitre:          MITRECoverage           = field(default_factory=MITRECoverage)
    safety:         SafetyVerification      = field(default_factory=SafetyVerification)
    artifacts:      List[EvidenceRef]       = field(default_factory=list)
    total_events:   int  = 0
    alert_signatures: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "report_id":       self.report_id,
            "run_id":          self.run_id,
            "campaign_name":   self.campaign_name,
            "generated_at":    self.generated_at,
            "scenario_path":   self.scenario_path,
            "dry_run":         self.dry_run,
            "phases_run":      self.phases_run,
            "layers_run":      self.layers_run,
            "total_events":    self.total_events,
            "mitre":           self.mitre.to_dict(),
            "safety":          self.safety.to_dict(),
            "findings_count":  len(self.findings),
            "detections_count":len(self.detections),
        }
