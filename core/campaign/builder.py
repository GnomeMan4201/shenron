"""
SHENRON Campaign Builder.
Generates causally-linked telemetry chains representing multi-stage intrusion narratives.
"""
import uuid
import random
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from core.safety.contract import make_safe_record_fields


class CampaignStage(str, Enum):
    INITIAL_ACCESS = "INITIAL_ACCESS"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COLLECTION = "COLLECTION"
    EXFIL = "EXFIL"


@dataclass
class CampaignEvent:
    stage: CampaignStage
    layer_name: str
    artifact: dict        # primary artifact (first emitted)
    artifacts: List[dict] # all artifacts emitted by this layer run
    timestamp: str
    parent_event_id: Optional[str]
    event_id: str
    session_id: str
    actor_id: str
    campaign_id: str
    causal_chain_index: int


@dataclass
class Campaign:
    campaign_id: str
    scenario_name: str
    actor_id: str
    session_id: str
    start_timestamp: str
    duration_hours: int
    events: List[CampaignEvent] = field(default_factory=list)


SCENARIOS: dict[str, list[tuple[CampaignStage, str]]] = {
    "apt29-style": [
        (CampaignStage.INITIAL_ACCESS,        "passive_recon_harvester"),
        (CampaignStage.EXECUTION,             "lotl_execution_phantom"),
        (CampaignStage.PERSISTENCE,           "boot_persistence_anchor"),
        (CampaignStage.PRIVILEGE_ESCALATION,  "lsass_harvest_phantom"),
        (CampaignStage.LATERAL_MOVEMENT,      "smb_lateral_crawler"),
        (CampaignStage.COLLECTION,            "cognitive_replicator"),
        (CampaignStage.EXFIL,                 "transient_exfil_shell"),
    ],
    "ransomware-precursor": [
        (CampaignStage.INITIAL_ACCESS,   "beacon_emitter_cloak"),
        (CampaignStage.EXECUTION,        "payload_skinwalker"),
        (CampaignStage.PERSISTENCE,      "dormant_sleeper_seed"),
        (CampaignStage.LATERAL_MOVEMENT, "smb_lateral_crawler"),
        (CampaignStage.EXFIL,            "transient_exfil_shell"),
    ],
    "insider-threat": [
        (CampaignStage.INITIAL_ACCESS, "cognitive_replicator"),
        (CampaignStage.EXECUTION,      "lotl_execution_phantom"),
        (CampaignStage.COLLECTION,     "cognitive_replicator"),
        (CampaignStage.EXFIL,          "transient_exfil_shell"),
    ],
}


class CampaignBuilder:
    """
    Constructs campaigns from defined scenarios, threading session and actor IDs
    across all events and applying causally ordered timestamps.
    """

    def __init__(self, scenario_name: str, duration_hours: int = 72):
        self.scenario_name = scenario_name
        self.duration_hours = duration_hours
        self.campaign_id = str(uuid.uuid4())
        self.actor_id = f"actor-{uuid.uuid4().hex[:8]}"
        self.session_id = str(uuid.uuid4())
        self.start_timestamp = datetime.now(timezone.utc).isoformat()
        self.events: List[CampaignEvent] = []

    @staticmethod
    def from_scenario(name: str, duration_hours: int = 72) -> "CampaignBuilder":
        """Initialize a builder from a named scenario."""
        if name not in SCENARIOS:
            raise ValueError(f"Unknown scenario: {name}. Available: {list(SCENARIOS.keys())}")
        return CampaignBuilder(name, duration_hours)

    def _generate_artifacts(self, layer_name: str, stage: CampaignStage, ts: datetime) -> List[dict]:
        """Invoke the real layer generator and return all emitted artifacts."""
        from core.engine import payload_registry
        from core.engine.layer_loader import load_all
        import os

        log_path = os.path.expanduser("~/SHENRON/logs/simulation_artifacts.jsonl")
        if not os.path.exists(log_path):
            # fallback: check alternate path
            log_path = os.path.expanduser("~/.shenron/logs/simulation_artifacts.jsonl")

        # Count lines before
        try:
            with open(log_path) as f:
                before = f.readlines()
        except FileNotFoundError:
            before = []

        # Ensure layer is loaded and run it
        if layer_name not in payload_registry.list_registered():
            load_all()
        payload_registry.run(layer_name)

        # Read back new records
        try:
            with open(log_path) as f:
                after = f.readlines()
        except FileNotFoundError:
            after = []

        new_records = after[len(before):]
        import json as _json
        artifacts = []
        for line in new_records:
            line = line.strip()
            if line:
                try:
                    artifacts.append(_json.loads(line))
                except Exception:
                    pass

        if not artifacts:
            # Fallback stub if layer emits nothing
            artifacts = [{
                "artifact_id": str(uuid.uuid4()),
                "session_id": self.session_id,
                "layer": layer_name,
                "phase": stage.value,
                "mitre_techniques": ["T1000"],
                "behavior_class": f"{layer_name}_sim",
                "detection_opportunities": ["simulation_detection_opp"],
                "simulation_only": True,
                "safety": make_safe_record_fields(),
            }]

        # Inject campaign fields into all artifacts
        result = []
        for art in artifacts:
            art = art.copy()
            art["session_id"] = self.session_id
            art["actor_id"] = self.actor_id
            art["campaign_id"] = self.campaign_id
            art["stage"] = stage.value
            art["timestamp"] = ts.isoformat()
            art.setdefault("simulation_only", True)
            art.setdefault("safety", make_safe_record_fields())
            result.append(art)
        return result

    def build(self) -> Campaign:
        """Build the Campaign dataclass containing ordered events."""
        scenario = SCENARIOS[self.scenario_name]
        current_time = datetime.fromisoformat(self.start_timestamp.replace("Z", "+00:00"))
        parent_id: Optional[str] = None

        for idx, (stage, layer_name) in enumerate(scenario):
            event_id = str(uuid.uuid4())
            all_artifacts = self._generate_artifacts(layer_name, stage, current_time)
            event = CampaignEvent(
                stage=stage,
                layer_name=layer_name,
                artifact=all_artifacts[0],
                artifacts=all_artifacts,
                timestamp=current_time.isoformat(),
                parent_event_id=parent_id,
                event_id=event_id,
                session_id=self.session_id,
                actor_id=self.actor_id,
                campaign_id=self.campaign_id,
                causal_chain_index=idx,
            )
            self.events.append(event)
            parent_id = event_id
            jitter_mins = random.randint(15, 90)
            current_time += timedelta(minutes=jitter_mins)

        return Campaign(
            campaign_id=self.campaign_id,
            scenario_name=self.scenario_name,
            actor_id=self.actor_id,
            session_id=self.session_id,
            start_timestamp=self.start_timestamp,
            duration_hours=self.duration_hours,
            events=self.events,
        )

    def to_jsonl(self) -> list[dict]:
        """Convert the built campaign into JSONL-ready artifact dicts."""
        out = []
        for e in self.events:
            rec = e.artifact.copy()
            rec.update({
                "campaign_id": e.campaign_id,
                "actor_id": e.actor_id,
                "session_id": e.session_id,
                "stage": e.stage.value,
                "parent_event_id": e.parent_event_id,
                "event_id": e.event_id,
                "causal_chain_index": e.causal_chain_index,
            })
            out.append(rec)
        return out
