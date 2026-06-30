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
    weighted_brittleness_score: float = 0.0
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
            "weighted_brittleness_score": self.weighted_brittleness_score,
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


    def report_to_markdown(self) -> str:
        """Generates a human-readable Markdown brittleness report."""
        lines = []
        lines.append("# Brittleness Report: " + self.scenario_name)
        lines.append("**Campaign ID:** " + self.campaign_id + "  ")
        lines.append("**Generated At:** " + self.generated_at + "  ")
        lines.append("**Overall Brittleness Score:** " + f"{self.overall_brittleness_score:.2f}" + "  ")
        lines.append("**Weighted Brittleness Score:** " + f"{self.weighted_brittleness_score:.2f}" + "  ")
        lines.append("**Most Brittle Stage:** " + self.most_brittle_stage + "  ")
        lines.append("**Most Effective Strategy:** " + self.most_effective_strategy + "  ")
        lines.append("**Correlation Breaks:** " + str(self.correlation_break_count) + "  ")
        lines.append("**Rules Evaluated:** " + str(self.rule_count) + "  ")
        lines.append("**Artifacts Scored:** " + str(self.artifact_count) + "  ")
        lines.append("")
        lines.append("## Per-Stage Breakdown")
        lines.append("")
        lines.append("| Stage | Layer | Detected | Evasion Rate | Evading Strategies |")
        lines.append("|---|---|---|---|---|")
        for ab in self.per_artifact:
            trig = "Yes" if ab.original_triggered else "No"
            evades = ", ".join(ab.variants_that_evade) if ab.variants_that_evade else "None"
            lines.append("| " + ab.stage + " | " + ab.layer_name + " | " + trig + " | " + f"{ab.evasion_rate:.2f}" + " | " + evades + " |")
        lines.append("")
        lines.append("## Remediation Guidance")
        lines.append("")
        for ab in self.per_artifact:
            if ab.variants_that_evade:
                strats = ", ".join(ab.variants_that_evade)
                lines.append("- **" + ab.stage + "** (" + ab.layer_name + "): evaded by " + strats + ".")
        return chr(10).join(lines)


class BrittlenessScorer:
    """Scores campaign artifacts against Sigma rules using mutation evasion rates."""

    STRATEGIES = ["value_swap", "field_omit", "case_flip", "unicode_substitute", "whitespace_inject", "combined_evasion"]

    ADVERSARY_WEIGHTS = {
        "case_flip":         1.0,
        "whitespace_inject": 0.8,
        "combined_evasion":  0.8,
        "unicode_substitute": 0.6,
        "field_omit":        0.4,
        "value_swap":        0.2,
    }

    @staticmethod
    def load_weights_from_config(config_path: str = "shenron.config.yml") -> dict:
        """Load adversary weight profile from config file. Falls back to defaults."""
        import os
        try:
            import yaml
            if os.path.exists(config_path):
                with open(config_path) as f:
                    cfg = yaml.safe_load(f)
                weights = cfg.get("brittleness", {}).get("weights", {})
                if weights:
                    return weights
        except Exception:
            pass
        return {}

    def __init__(self, rules_dir: str, config_path: str = "shenron.config.yml"):
        self.rules_dir = rules_dir
        self.rule_paths = (
            list(Path(rules_dir).rglob("*.yml")) +
            list(Path(rules_dir).rglob("*.yaml"))
        )
        self.mutator = SigmaAwareMutator(rules_dir)
        cfg_weights = self.load_weights_from_config(config_path)
        if cfg_weights:
            self.ADVERSARY_WEIGHTS = {**self.ADVERSARY_WEIGHTS, **cfg_weights}

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

    def _check_artifacts_per_rule(self, artifacts: list) -> dict:
        """Returns {rule_stem: bool} for every rule — no early exit."""
        results = {}
        if not artifacts or not self.rule_paths:
            return results
        import tempfile as _tf, os as _os, json as _json
        with _tf.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            for a in artifacts:
                f.write(_json.dumps(a) + "\n")
            temp_path = f.name
        try:
            for rp in self.rule_paths:
                res = evaluate_sigma_rule(str(rp), temp_path, match_mode="strict")
                results[Path(rp).stem] = (res.verdict == RuleVerdict.TRIGGERED)
        finally:
            _os.unlink(temp_path)
        return results

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
        weighted_scores = []
        total_weight = sum(self.ADVERSARY_WEIGHTS.values())

        for event in campaign.events:
            all_arts = getattr(event, "artifacts", [event.artifact])
            seed = hash(event.event_id) % 10000
            variants = self.mutator.mutate_all_strategies(event.artifact, seed=seed)
            orig_triggered = self._check_artifacts_against_rules(all_arts)
            orig_per_rule = self._check_artifacts_per_rule(all_arts)
            rule_evasion_counts: dict[str, int] = {r: 0 for r in orig_per_rule}
            evade_list = []
            correlation_broken = False
            weighted_evasion_sum = 0.0

            for i, variant in enumerate(variants):
                strat_name = self.STRATEGIES[i]
                variant_per_rule = self._check_artifacts_per_rule([variant])
                if not self._check_artifacts_against_rules([variant]):
                    evade_list.append(strat_name)
                    strategy_evade_counts[strat_name] += 1
                    weighted_evasion_sum += self.ADVERSARY_WEIGHTS.get(strat_name, 0.5)
                    for r, fired in variant_per_rule.items():
                        if not fired and r in rule_evasion_counts:
                            rule_evasion_counts[r] += 1
                if variant.get("campaign_id") != event.artifact.get("campaign_id"):
                    correlation_broken = True

            if correlation_broken:
                report.correlation_break_count += 1

            evasion_rate = len(evade_list) / len(self.STRATEGIES)
            weighted_scores.append(weighted_evasion_sum / total_weight)
            n_mutations = len(self.STRATEGIES)
            _rule_metrics = [
                {
                    "rule_name": r,
                    "stage_name": event.stage.value,
                    "triggered": 1 if orig_per_rule.get(r) else 0,
                    "evaded": rule_evasion_counts.get(r, 0),
                    "total_mutations": n_mutations,
                    "brittleness": rule_evasion_counts.get(r, 0) / n_mutations,
                }
                for r in orig_per_rule
            ]
            report.per_artifact.append(ArtifactBrittleness(
                event_id=event.event_id,
                stage=event.stage.value,
                layer_name=event.layer_name,
                original_triggered=orig_triggered,
                variants_that_evade=evade_list,
                evasion_rate=evasion_rate,
            ))
            report.per_artifact[-1]._rule_metrics = _rule_metrics
            stage_evasion_rates.setdefault(event.stage.value, []).append(evasion_rate)

        if report.per_artifact:
            report.overall_brittleness_score = sum(
                ab.evasion_rate for ab in report.per_artifact
            ) / len(report.per_artifact)
            report.weighted_brittleness_score = sum(weighted_scores) / len(weighted_scores)
            report.most_effective_strategy = max(
                strategy_evade_counts, key=strategy_evade_counts.get
            )
            report.most_brittle_stage = max(
                stage_evasion_rates,
                key=lambda s: sum(stage_evasion_rates[s]) / len(stage_evasion_rates[s])
            )
        return report
