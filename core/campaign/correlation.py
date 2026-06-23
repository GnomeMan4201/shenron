"""
SHENRON Campaign-Level Correlation Brittleness.
Scores whether mutations on relationships between events break the ability
to correlate them into a coherent intrusion narrative.
"""
import copy
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import List

from core.campaign.builder import Campaign


class CampaignMutationStrategy(str, Enum):
    SESSION_ID_ROTATION = "SESSION_ID_ROTATION"
    TIMESTAMP_STRETCH   = "TIMESTAMP_STRETCH"
    STAGE_DROPOUT       = "STAGE_DROPOUT"
    ACTOR_DRIFT         = "ACTOR_DRIFT"


@dataclass
class CorrelationScore:
    strategy: str
    session_id_intact: bool
    temporal_coherent: bool
    stage_coverage_intact: bool
    actor_consistent: bool
    broken_link_count: int
    correlation_integrity: float


@dataclass
class CorrelationBrittlenessReport:
    campaign_id: str
    scenario_name: str
    generated_at: str
    per_strategy: List[CorrelationScore] = field(default_factory=list)
    overall_correlation_brittleness: float = 0.0
    most_fragile_strategy: str = ""
    gap_vs_artifact_brittleness: float = 0.0

    def report_to_dict(self) -> dict:
        return {
            "campaign_id": self.campaign_id,
            "scenario_name": self.scenario_name,
            "generated_at": self.generated_at,
            "per_strategy": [
                {
                    "strategy": ps.strategy,
                    "session_id_intact": ps.session_id_intact,
                    "temporal_coherent": ps.temporal_coherent,
                    "stage_coverage_intact": ps.stage_coverage_intact,
                    "actor_consistent": ps.actor_consistent,
                    "broken_link_count": ps.broken_link_count,
                    "correlation_integrity": ps.correlation_integrity,
                }
                for ps in self.per_strategy
            ],
            "overall_correlation_brittleness": self.overall_correlation_brittleness,
            "most_fragile_strategy": self.most_fragile_strategy,
            "gap_vs_artifact_brittleness": self.gap_vs_artifact_brittleness,
        }

    def report_to_markdown(self) -> str:
        lines = []
        lines.append("# Correlation Brittleness Report: " + self.scenario_name)
        lines.append("**Campaign ID:** " + self.campaign_id + "  ")
        lines.append("**Generated At:** " + self.generated_at + "  ")
        lines.append("**Overall Correlation Brittleness:** " + f"{self.overall_correlation_brittleness:.2f}" + "  ")
        lines.append("**Most Fragile Strategy:** " + self.most_fragile_strategy + "  ")
        lines.append("**Gap vs Artifact Brittleness:** " + f"{self.gap_vs_artifact_brittleness:.2f}" + "  ")
        lines.append("")
        lines.append("## Per-Strategy Breakdown")
        lines.append("")
        lines.append("| Strategy | Session ID | Temporal | Stage Coverage | Actor | Broken Links | Integrity |")
        lines.append("|---|---|---|---|---|---|---|")
        for ps in self.per_strategy:
            lines.append(
                "| " + ps.strategy +
                " | " + str(ps.session_id_intact) +
                " | " + str(ps.temporal_coherent) +
                " | " + str(ps.stage_coverage_intact) +
                " | " + str(ps.actor_consistent) +
                " | " + str(ps.broken_link_count) +
                " | " + f"{ps.correlation_integrity:.2f}" + " |"
            )
        return chr(10).join(lines)


class CampaignMutator:
    """Applies campaign-graph-level mutations to test correlation brittleness."""

    def mutate(self, campaign: Campaign, strategy: CampaignMutationStrategy,
               seed: int = 42) -> Campaign:
        """Returns a deep copy of the campaign with the mutation applied."""
        mutated = copy.deepcopy(campaign)
        rng = random.Random(seed)

        if strategy == CampaignMutationStrategy.SESSION_ID_ROTATION:
            self._apply_session_id_rotation(mutated, rng)
        elif strategy == CampaignMutationStrategy.TIMESTAMP_STRETCH:
            self._apply_timestamp_stretch(mutated, rng)
        elif strategy == CampaignMutationStrategy.STAGE_DROPOUT:
            self._apply_stage_dropout(mutated, rng)
        elif strategy == CampaignMutationStrategy.ACTOR_DRIFT:
            self._apply_actor_drift(mutated, rng)

        # Preserve safety contract on all artifacts
        for event in mutated.events:
            event.artifact.setdefault("simulation_only", True)
            for art in getattr(event, "artifacts", []):
                art.setdefault("simulation_only", True)

        return mutated

    def _apply_session_id_rotation(self, campaign: Campaign, rng: random.Random):
        if len(campaign.events) <= 1:
            return
        new_session_id = str(uuid.uuid4())
        n = rng.randint(1, len(campaign.events) - 1)
        indices = set(rng.sample(range(len(campaign.events)), n))
        for idx, event in enumerate(campaign.events):
            if idx in indices:
                event.session_id = new_session_id
                event.artifact["session_id"] = new_session_id
                for art in getattr(event, "artifacts", []):
                    art["session_id"] = new_session_id

    def _apply_timestamp_stretch(self, campaign: Campaign, rng: random.Random):
        if len(campaign.events) < 2:
            return
        max_gap = timedelta(0)
        max_gap_idx = 1
        for i in range(1, len(campaign.events)):
            t1 = datetime.fromisoformat(campaign.events[i - 1].timestamp)
            t2 = datetime.fromisoformat(campaign.events[i].timestamp)
            gap = t2 - t1
            if gap > max_gap:
                max_gap = gap
                max_gap_idx = i
        if max_gap.total_seconds() <= 0:
            return
        new_gap = max_gap * 10
        t1_base = datetime.fromisoformat(campaign.events[max_gap_idx - 1].timestamp)
        old_t2 = datetime.fromisoformat(campaign.events[max_gap_idx].timestamp)
        new_t2 = t1_base + new_gap
        shift = new_t2 - old_t2
        for i in range(max_gap_idx, len(campaign.events)):
            orig = datetime.fromisoformat(campaign.events[i].timestamp)
            new_ts = (orig + shift).isoformat()
            campaign.events[i].timestamp = new_ts
            campaign.events[i].artifact["timestamp"] = new_ts
            for art in getattr(campaign.events[i], "artifacts", []):
                art["timestamp"] = new_ts

    def _apply_stage_dropout(self, campaign: Campaign, rng: random.Random):
        if not campaign.events:
            return
        target_stage = rng.choice(campaign.events).stage
        for event in campaign.events:
            if event.stage == target_stage:
                event.stage = "UNKNOWN"
                event.artifact["stage"] = "UNKNOWN"
                for art in getattr(event, "artifacts", []):
                    art["stage"] = "UNKNOWN"

    def _apply_actor_drift(self, campaign: Campaign, rng: random.Random):
        if len(campaign.events) < 2:
            return
        new_actor_id = f"actor-{uuid.uuid4().hex[:8]}"
        midpoint = len(campaign.events) // 2
        for i in range(midpoint, len(campaign.events)):
            event = campaign.events[i]
            event.actor_id = new_actor_id
            event.artifact["actor_id"] = new_actor_id
            for art in getattr(event, "artifacts", []):
                art["actor_id"] = new_actor_id


class CorrelationBrittlenessScorer:
    """Scores campaign-level correlation brittleness across mutation strategies."""

    TIME_THRESHOLD_HOURS = 6

    def __init__(self, artifact_brittleness: float = 0.0):
        self.artifact_brittleness = artifact_brittleness

    def score_campaign(self, campaign: Campaign) -> CorrelationBrittlenessReport:
        """Apply each strategy and score correlation integrity."""
        report = CorrelationBrittlenessReport(
            campaign_id=campaign.campaign_id,
            scenario_name=campaign.scenario_name,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
        mutator = CampaignMutator()
        integrity_scores = []

        for strategy in CampaignMutationStrategy:
            seed = hash(campaign.campaign_id + strategy.value) % 10000
            mutated = mutator.mutate(campaign, strategy, seed=seed)
            score = self._score_correlation(campaign, mutated)
            score.strategy = strategy.value
            report.per_strategy.append(score)
            integrity_scores.append(score.correlation_integrity)

        if report.per_strategy:
            report.overall_correlation_brittleness = sum(
                1.0 - i for i in integrity_scores
            ) / len(integrity_scores)
            report.most_fragile_strategy = max(
                report.per_strategy, key=lambda s: 1.0 - s.correlation_integrity
            ).strategy
            report.gap_vs_artifact_brittleness = (
                report.overall_correlation_brittleness - self.artifact_brittleness
            )

        return report

    def _score_correlation(self, original: Campaign, mutated: Campaign) -> CorrelationScore:
        """Score correlation integrity of a mutated campaign vs the original."""
        if not mutated.events:
            return CorrelationScore(
                strategy="", session_id_intact=False, temporal_coherent=False,
                stage_coverage_intact=False, actor_consistent=False,
                broken_link_count=0, correlation_integrity=0.0,
            )

        orig_session = original.events[0].session_id
        orig_actor   = original.events[0].actor_id
        orig_stages  = {e.stage for e in original.events}

        session_id_intact = all(e.session_id == orig_session for e in mutated.events)

        temporal_coherent = True
        threshold = self.TIME_THRESHOLD_HOURS * 3600
        for i in range(1, len(mutated.events)):
            t1 = datetime.fromisoformat(mutated.events[i - 1].timestamp)
            t2 = datetime.fromisoformat(mutated.events[i].timestamp)
            if t2 <= t1 or (t2 - t1).total_seconds() > threshold:
                temporal_coherent = False
                break

        mut_stages = {e.stage for e in mutated.events}
        stage_coverage_intact = (orig_stages == mut_stages)

        actor_consistent = all(e.actor_id == orig_actor for e in mutated.events)

        broken_link_count = 0
        for i in range(1, len(mutated.events)):
            broken = False
            if mutated.events[i].session_id != mutated.events[i - 1].session_id:
                broken = True
            if not broken:
                t1 = datetime.fromisoformat(mutated.events[i - 1].timestamp)
                t2 = datetime.fromisoformat(mutated.events[i].timestamp)
                if (t2 - t1).total_seconds() > threshold:
                    broken = True
            if not broken:
                if mutated.events[i].stage == "UNKNOWN" or mutated.events[i - 1].stage == "UNKNOWN":
                    broken = True
            if broken:
                broken_link_count += 1

        checks_passed = sum([session_id_intact, temporal_coherent,
                             stage_coverage_intact, actor_consistent])
        correlation_integrity = checks_passed / 4

        return CorrelationScore(
            strategy="",
            session_id_intact=session_id_intact,
            temporal_coherent=temporal_coherent,
            stage_coverage_intact=stage_coverage_intact,
            actor_consistent=actor_consistent,
            broken_link_count=broken_link_count,
            correlation_integrity=correlation_integrity,
        )
