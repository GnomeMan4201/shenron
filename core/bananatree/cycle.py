#!/usr/bin/env python3
# bananaTREE: Cycle — OBSERVE.SIMULATE.EXECUTE.ADAPT phase model
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Dict, Optional
import uuid


class Phase(str, Enum):
    OBSERVE  = "OBSERVE"
    SIMULATE = "SIMULATE"
    EXECUTE  = "EXECUTE"
    ADAPT    = "ADAPT"


PHASE_DESCRIPTIONS = {
    Phase.OBSERVE:  "Enumerate detection surface, map coverage gaps, identify blind spots",
    Phase.SIMULATE: "Generate synthetic adversarial-shaped telemetry for detector training",
    Phase.EXECUTE:  "Run simulation layers in dry-run/safe mode, collect JSONL artifacts",
    Phase.ADAPT:    "Analyze findings, update detection rules, close coverage gaps",
}

SAFETY_CONTRACT = {
    "simulation_only":        True,
    "executable":             False,
    "no_payload_present":     True,
    "network_calls_made":     False,
    "processes_spawned":      False,
    "files_modified":         False,
    "shell_commands_present": False,
}


@dataclass
class PhaseResult:
    phase:            Phase
    layers_run:       List[str]  = field(default_factory=list)
    artifacts:        List[dict] = field(default_factory=list)
    findings:         List[str]  = field(default_factory=list)
    mitre_techniques: List[str]  = field(default_factory=list)
    timestamp:        str        = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ok:               bool       = True
    errors:           List[str]  = field(default_factory=list)


@dataclass
class BananaTreeCycle:
    run_id:          str           = field(default_factory=lambda: str(uuid.uuid4()))
    campaign_name:   str           = "unnamed_campaign"
    started_at:      str           = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at:    Optional[str] = None
    dry_run:         bool          = True
    safety_contract: dict          = field(default_factory=lambda: dict(SAFETY_CONTRACT))
    phases:          Dict[Phase, PhaseResult] = field(default_factory=dict)
    scenario_path:   Optional[str] = None
    total_layers:    int           = 0
    total_artifacts: int           = 0
    all_mitre:       List[str]     = field(default_factory=list)

    def start_phase(self, phase: Phase) -> PhaseResult:
        result = PhaseResult(phase=phase)
        self.phases[phase] = result
        return result

    def complete(self):
        self.completed_at   = datetime.now(timezone.utc).isoformat()
        self.total_layers   = sum(len(r.layers_run) for r in self.phases.values())
        self.total_artifacts = sum(len(r.artifacts) for r in self.phases.values())
        seen = set()
        for r in self.phases.values():
            for t in r.mitre_techniques:
                if t not in seen:
                    seen.add(t)
                    self.all_mitre.append(t)

    def to_dict(self) -> dict:
        return {
            "run_id":          self.run_id,
            "campaign_name":   self.campaign_name,
            "started_at":      self.started_at,
            "completed_at":    self.completed_at,
            "dry_run":         self.dry_run,
            "safety_contract": self.safety_contract,
            "total_layers":    self.total_layers,
            "total_artifacts": self.total_artifacts,
            "all_mitre":       self.all_mitre,
            "phases": {
                phase.value: {
                    "layers_run":       result.layers_run,
                    "findings":         result.findings,
                    "mitre_techniques": result.mitre_techniques,
                    "artifacts_count":  len(result.artifacts),
                    "ok":               result.ok,
                    "errors":           result.errors,
                    "timestamp":        result.timestamp,
                }
                for phase, result in self.phases.items()
            },
        }
