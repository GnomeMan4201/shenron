"""
SHENRON Cross-Scenario Brittleness Comparator.
Evaluates and compares brittleness profiles across multiple adversary scenarios.
"""
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict
from core.campaign.builder import CampaignBuilder, SCENARIOS
from core.brittleness.scorer import BrittlenessScorer, BrittlenessReport


@dataclass
class ScenarioResult:
    scenario_name: str
    overall_brittleness: float
    per_stage: Dict[str, float]
    most_brittle_stage: str
    most_effective_strategy: str
    triggered_count: int
    total_stages: int


@dataclass
class ComparisonReport:
    scenarios: List[ScenarioResult]
    generated_at: str
    rules_evaluated: int
    universally_brittle_stages: List[str] = field(default_factory=list)
    universally_detected_stages: List[str] = field(default_factory=list)
    most_resilient_scenario: str = ""
    most_brittle_scenario: str = ""
    strategy_effectiveness: Dict[str, float] = field(default_factory=dict)

    def report_to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "rules_evaluated": self.rules_evaluated,
            "universally_brittle_stages": self.universally_brittle_stages,
            "universally_detected_stages": self.universally_detected_stages,
            "most_resilient_scenario": self.most_resilient_scenario,
            "most_brittle_scenario": self.most_brittle_scenario,
            "strategy_effectiveness": self.strategy_effectiveness,
            "scenarios": [
                {
                    "scenario_name": s.scenario_name,
                    "overall_brittleness": s.overall_brittleness,
                    "per_stage": s.per_stage,
                    "most_brittle_stage": s.most_brittle_stage,
                    "most_effective_strategy": s.most_effective_strategy,
                    "triggered_count": s.triggered_count,
                    "total_stages": s.total_stages,
                }
                for s in self.scenarios
            ],
        }

    def report_to_markdown(self) -> str:
        lines = []
        lines.append("# Cross-Scenario Brittleness Comparison")
        lines.append("")
        lines.append("**Generated At:** " + self.generated_at + "  ")
        lines.append("**Rules Evaluated:** " + str(self.rules_evaluated) + "  ")
        lines.append("**Most Brittle Scenario:** `" + self.most_brittle_scenario + "`  ")
        lines.append("**Most Resilient Scenario:** `" + self.most_resilient_scenario + "`  ")
        lines.append("")
        lines.append("## Scenario Breakdown")
        lines.append("")
        lines.append("| Scenario | Brittleness | Triggered | Most Brittle Stage | Most Effective Evasion |")
        lines.append("|---|---|---|---|---|")
        for s in self.scenarios:
            trig = str(s.triggered_count) + "/" + str(s.total_stages)
            lines.append("| " + s.scenario_name + " | " + f"{s.overall_brittleness:.2f}" + " | " + trig + " | " + s.most_brittle_stage + " | " + s.most_effective_strategy + " |")
        lines.append("")
        lines.append("## Universal Stages")
        lines.append("")
        brittle = ", ".join(self.universally_brittle_stages) if self.universally_brittle_stages else "None"
        detected = ", ".join(self.universally_detected_stages) if self.universally_detected_stages else "None"
        lines.append("**Universally Brittle (>0.5 evasion in all scenarios):** " + brittle + "  ")
        lines.append("**Universally Detected (0.0 evasion in all scenarios):** " + detected + "  ")
        lines.append("")
        lines.append("## Strategy Effectiveness (Mean Evasion Rate)")
        lines.append("")
        lines.append("| Strategy | Mean Evasion Rate |")
        lines.append("|---|---|")
        for strat, rate in sorted(self.strategy_effectiveness.items(), key=lambda x: x[1], reverse=True):
            lines.append("| " + strat + " | " + f"{rate:.2f}" + " |")
        return chr(10).join(lines)


class ScenarioComparator:
    """Builds, scores, and compares multiple campaigns side-by-side."""

    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir
        self.scorer = BrittlenessScorer(rules_dir)

    def _evaluate_scenario(self, name: str) -> ScenarioResult:
        builder = CampaignBuilder.from_scenario(name)
        campaign = builder.build()
        report: BrittlenessReport = self.scorer.score_campaign(campaign)

        per_stage = {}
        triggered_count = 0
        for ab in report.per_artifact:
            per_stage[ab.stage] = ab.evasion_rate
            if ab.original_triggered:
                triggered_count += 1

        return ScenarioResult(
            scenario_name=name,
            overall_brittleness=report.overall_brittleness_score,
            per_stage=per_stage,
            most_brittle_stage=report.most_brittle_stage,
            most_effective_strategy=report.most_effective_strategy,
            triggered_count=triggered_count,
            total_stages=len(campaign.events),
        )

    def _build_report(self, results: List[ScenarioResult]) -> ComparisonReport:
        report = ComparisonReport(
            scenarios=results,
            generated_at=datetime.now(timezone.utc).isoformat(),
            rules_evaluated=len(self.scorer.rule_paths),
        )
        if not results:
            return report

        report.most_brittle_scenario = max(results, key=lambda r: r.overall_brittleness).scenario_name
        report.most_resilient_scenario = min(results, key=lambda r: r.overall_brittleness).scenario_name

        strat_rates: Dict[str, List[float]] = {}
        for res in results:
            if res.most_effective_strategy:
                strat_rates.setdefault(res.most_effective_strategy, []).append(res.overall_brittleness)
        report.strategy_effectiveness = {
            s: sum(vals) / len(vals) for s, vals in strat_rates.items()
        }

        stage_sets = [set(r.per_stage.keys()) for r in results]
        if stage_sets:
            common_stages = set.intersection(*stage_sets)
            univ_brittle = []
            univ_detected = []
            for stage in common_stages:
                rates = [r.per_stage[stage] for r in results]
                if all(rate > 0.5 for rate in rates):
                    univ_brittle.append(stage)
                if all(rate == 0.0 for rate in rates):
                    univ_detected.append(stage)
            report.universally_brittle_stages = sorted(univ_brittle)
            report.universally_detected_stages = sorted(univ_detected)

        return report

    def run_all(self) -> ComparisonReport:
        """Runs all defined scenarios in SCENARIOS."""
        results = [self._evaluate_scenario(name) for name in SCENARIOS.keys()]
        return self._build_report(results)

    def run_selected(self, scenario_names: List[str]) -> ComparisonReport:
        """Runs a selected subset of scenarios."""
        results = [self._evaluate_scenario(name) for name in scenario_names if name in SCENARIOS]
        return self._build_report(results)
