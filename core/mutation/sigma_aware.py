from __future__ import annotations
"""
SHENRON Sigma-Aware Targeted Mutator.
Adds Sigma-targeted mutation capability on top of the existing engine.
"""
import copy
import random
from pathlib import Path
from typing import List, Dict
from core.mutation.engine import MutationResult
from core.sigma.loader import load_sigma_rule
from core.sigma.evaluator import FIELD_MAP


class SigmaTargetExtractor:
    """Extracts target fields and literal values from loaded Sigma rules."""

    def load_rules(self, rules_dir: str) -> list:
        rules = []
        for p in Path(rules_dir).glob("*.yml"):
            try:
                rules.append(load_sigma_rule(p))
            except Exception:
                pass
        for p in Path(rules_dir).glob("*.yaml"):
            try:
                rules.append(load_sigma_rule(p))
            except Exception:
                pass
        return rules

    def extract_targets(self, rules: list) -> Dict[str, List[str]]:
        targets = {}
        for rule in rules:
            detection = rule.get("detection", {})
            for block_name, block_def in detection.items():
                if block_name == "condition" or not isinstance(block_def, dict):
                    continue
                for sigma_field, expected_value in block_def.items():
                    shenron_fields = FIELD_MAP.get(sigma_field, [])
                    if not shenron_fields:
                        continue
                    values = []
                    if isinstance(expected_value, list):
                        values = [str(v) for v in expected_value if v]
                    elif isinstance(expected_value, str) and expected_value:
                        values = [expected_value]
                    for sf in shenron_fields:
                        if sf not in targets:
                            targets[sf] = []
                        targets[sf].extend(values)
        return targets


class SigmaAwareMutator:
    """Applies targeted mutations to artifacts based on Sigma rule targets."""

    PROTECTED_FIELDS = {
        "simulation_only", "artifact_id", "session_id", "mitre_techniques",
        "behavior_class", "detection_opportunities", "safety"
    }

    HOMOGLYPHS = {
        "a": "\u0430", "e": "\u0435", "o": "\u043e", "p": "\u0440",
        "c": "\u0441", "x": "\u0445", "i": "\u0456", "s": "\u0455"
    }

    def __init__(self, rules_dir: str):
        extractor = SigmaTargetExtractor()
        self.rules = extractor.load_rules(rules_dir)
        self.targets = extractor.extract_targets(self.rules)

    def _get_mutable_field(self, artifact: dict) -> str | None:
        for field in self.targets.keys():
            if field in artifact and field not in self.PROTECTED_FIELDS:
                return field
        for k, v in artifact.items():
            if isinstance(v, str) and k not in self.PROTECTED_FIELDS:
                return k
        return None

    def mutate_targeted(self, artifact: dict, strategy: str, seed: int = 42) -> dict:
        """Return a single mutated artifact variant with _mutation_meta."""
        target_field = self._get_mutable_field(artifact)
        if not target_field:
            return artifact
        original_val = artifact[target_field]
        mutated_val = original_val
        field_targeted = target_field

        if strategy == "value_swap":
            if isinstance(original_val, str):
                if original_val in self.targets.get(target_field, []):
                    if original_val.endswith(".exe"):
                        mutated_val = original_val[:-4] + " .exe"
                    elif "\\" in original_val:
                        mutated_val = original_val.replace("\\", "/")
                    else:
                        mutated_val = original_val + "\t"
                else:
                    mutated_val = original_val + "_alt"
            elif isinstance(original_val, list) and original_val:
                mutated_val = original_val + ["swapped_value_sim"]
        elif strategy == "field_omit":
            mutated_val = None
        elif strategy == "case_flip":
            if isinstance(original_val, str):
                rng = random.Random(seed)
                mutated_val = ''.join(c.upper() if rng.random() > 0.5 else c.lower() for c in original_val)
            elif isinstance(original_val, list):
                mutated_val = [v.upper() if isinstance(v, str) else v for v in original_val]
        elif strategy == "unicode_substitute":
            if isinstance(original_val, str):
                mutated_val = "".join(self.HOMOGLYPHS.get(c.lower(), c) for c in original_val)
        elif strategy == "whitespace_inject":
            if isinstance(original_val, str):
                mutated_val = "\u200b".join(original_val)

        out = copy.deepcopy(artifact)
        if strategy == "field_omit" and target_field not in self.PROTECTED_FIELDS:
            del out[target_field]
        else:
            out[target_field] = mutated_val
        out["_mutation_meta"] = {
            "strategy": strategy,
            "field_targeted": field_targeted,
            "original_value": original_val,
            "mutated_value": mutated_val if strategy != "field_omit" else None
        }
        return out

    def mutate_all_strategies(self, artifact: dict, seed: int = 42) -> List[dict]:
        """Returns one variant per strategy, list of 6 dicts."""
        strategies = ["value_swap", "field_omit", "case_flip", "unicode_substitute", "whitespace_inject", "combined_evasion"]
        return [self.mutate_targeted(artifact, s, seed + i) for i, s in enumerate(strategies)]
