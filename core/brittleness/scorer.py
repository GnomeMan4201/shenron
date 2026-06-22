"""
SHENRON Detection Brittleness Scorer.
Combines campaign chains with Sigma-aware mutation to score detection fragility.
"""
import os
import json
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List
from core.campaign.builder import Campaign
from core.mutation.sigma_aware import SigmaAwareMutator
from core.sigma.evaluator import evaluate_sigma_rule
from core.sigma.model import RuleVerdict


@dataclass
class ArtifactBrittleness:
    event_id: str
    stage: str
    layer_name: str
    original_triggered: bool
    variants_that_evade: List[str]
    evasion_rate: float


@dataclass
class BrittlenessReport:
    campaign_id: str
    scenario_name: str
    generated_at: str
    rule_count: int
    artifact_count: int
    per_artifact: List[ArtifactBrittleness] = field(default_factory=list)
    overall_brittleness_score: float = 0.0
    most_brittle_stage: str = ""
    most_effective_strategy: str = ""
    correlation_break_count: int = 0

    def report_to_dict(self) -> dict:
        return {
            "campaign_id": self.campaign_id,
            "scenario_name": self.scenario_name,
            "generated_at": self.generated_at,
            "rule_count": self.rule_count,
            "artifact_count": self.artifact_count,
            "overall_brittleness_score": self.overall_brittleness_score,
            "most_brittle_stage": self.most_brittle_stage,
            "most_effective_strategy": self.most_effective_strategy,
            "correlation_break_count": self.correlation_break_count,
            "per_artifact": [
                {
                    "event_id": ab.event_id,
                    "stage": ab.stage,
                    "layer_name": ab.layer_name,
                    "original_triggered": ab.original_triggered,
                    "variants_that_evade": ab.variants_that_evade,
                    "evasion_rate": ab.evasion_rate,
                }
                for ab in self.per_artifact
            ],
        }

    def report_to_jsonl(self) -> str:
        return "\n".join(
            json.dumps({
                "campaign_id": self.campaign_id,
                "event_id": ab.event_id,
                "stage": ab.stage,
                "layer_name": ab.layer_name,
                "original_triggered": ab.original_triggered,
                "variants_that_evade": ab.variants_that_evade,
                "evasion_rate": ab.evasion_rate,
            })
            for ab in self.per_artifact
        )


class BrittlenessScorer:
    """Scores campaign artifacts against Sigma rules using mutation evasion rates."""

    STRATEGIES = ["value_swap", "field_omit", "case_flip", "unicode_substitute", "whitespace_inject"]

    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir
        self.rule_paths = (
            list(Path(rules_dir).rglob("*.yml")) +
            list(Path(rules_dir).rglob("*.yaml"))
        )
        self.mutator = SigmaAwareMutator(rules_dir)

    def _check_artifacts_against_rules(self, artifacts: list) -> bool:
        """Returns True if any rule triggers on any artifact."""
        if not artifacts or not self.rule_paths:
            return False
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            for a in artifacts:
                f.write(json.dumps(a) + "\n")
            temp_path = f.name
        triggered = False
        try:
            for rp in self.rule_paths:
                res = evaluate_sigma_rule(str(rp), temp_path, match_mode="strict")
                if res.verdict == RuleVerdict.TRIGGERED:
                    triggered = True
                    break
        finally:
            os.unlink(temp_path)
        return triggered

    def score_campaign(self, campaign: Campaign) -> BrittlenessReport:
        """Evaluate brittleness of all artifacts in a campaign."""
        report = BrittlenessReport(
            campaign_id=campaign.campaign_id,
            scenario_name=campaign.scenario_name,
            generated_at=datetime.now(timezone.utc).isoformat(),
            rule_count=len(self.rule_paths),
            artifact_count=len(campaign.events),
        )
        strategy_evade_counts = {s: 0 for s in self.STRATEGIES}
        stage_evasion_rates: dict[str, list[float]] = {}

        for event in campaign.events:
            all_arts = getattr(event, "artifacts", [event.artifact])
            variants = self.mutator.mutate_all_strategies(event.artifact)
            orig_triggered = self._check_artifacts_against_rules(all_arts)
            evade_list = []
            correlation_broken = False

            for i, variant in enumerate(variants):
                strat_name = self.STRATEGIES[i]
                if not self._check_artifacts_against_rules([variant]):
                    evade_list.append(strat_name)
                    strategy_evade_counts[strat_name] += 1
                if variant.get("campaign_id") != event.artifact.get("campaign_id"):
                    correlation_broken = True

            if correlation_broken:
                report.correlation_break_count += 1

            evasion_rate = len(evade_list) / len(self.STRATEGIES)
            report.per_artifact.append(ArtifactBrittleness(
                event_id=event.event_id,
                stage=event.stage.value,
                layer_name=event.layer_name,
                original_triggered=orig_triggered,
                variants_that_evade=evade_list,
                evasion_rate=evasion_rate,
            ))
            stage_evasion_rates.setdefault(event.stage.value, []).append(evasion_rate)

        if report.per_artifact:
            report.overall_brittleness_score = sum(
                ab.evasion_rate for ab in report.per_artifact
            ) / len(report.per_artifact)
            report.most_effective_strategy = max(
                strategy_evade_counts, key=strategy_evade_counts.get
            )
            report.most_brittle_stage = max(
                stage_evasion_rates,
                key=lambda s: sum(stage_evasion_rates[s]) / len(stage_evasion_rates[s])
            )
        return report
