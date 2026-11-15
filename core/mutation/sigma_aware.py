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
from core.sigma.pysigma_bridge import FIELD_MAP
from core.sigma.fields import base_field, get_path, has_path, set_path, del_path


class SigmaTargetExtractor:
    """Extracts target fields and literal values from loaded Sigma rules."""

    def load_rules(self, rules_dir: str) -> list:
        """Load rules from a directory (recursively) or from a single rule file."""
        root = Path(rules_dir)
        if root.is_file():
            paths = [root]
        else:
            paths = sorted(list(root.rglob("*.yml")) + list(root.rglob("*.yaml")))
        rules = []
        for p in paths:
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
                for raw_field, expected_value in block_def.items():
                    # Same resolution as the pySigma bridge: mapped Sigma
                    # fields expand, anything else is an event field by name.
                    sigma_field = base_field(raw_field)
                    shenron_fields = FIELD_MAP.get(sigma_field, [sigma_field])
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

    STRATEGIES = ("value_swap", "field_omit", "case_flip", "unicode_substitute",
                  "whitespace_inject", "combined_evasion")

    def _get_mutable_fields(self, artifact: dict) -> List[str]:
        """Every rule-referenced field present on the artifact that may be mutated.

        Falls back to the first unprotected string field when the artifact carries
        none of the fields the loaded rules reference.
        """
        fields = [f for f in self.targets
                  if has_path(artifact, f) and f.split(".")[0] not in self.PROTECTED_FIELDS]
        if fields:
            return fields
        for k, v in artifact.items():
            if isinstance(v, str) and k not in self.PROTECTED_FIELDS:
                return [k]
        return []

    def _get_mutable_field(self, artifact: dict) -> str | None:
        fields = self._get_mutable_fields(artifact)
        return fields[0] if fields else None

    def mutate_targeted(self, artifact: dict, strategy: str, seed: int = 42) -> dict:
        """Return a single mutated artifact variant with _mutation_meta.

        The strategy is applied to every rule-referenced, unprotected field on the
        artifact, not only the first one found.
        """
        if strategy not in self.STRATEGIES:
            raise ValueError(f"Unknown sigma-aware mutation strategy: {strategy!r}")
        fields = self._get_mutable_fields(artifact)
        if not fields:
            return artifact
        out = copy.deepcopy(artifact)
        originals, mutated_vals = {}, {}
        for i, field in enumerate(fields):
            original_val = get_path(artifact, field)
            mutated_val = self._mutate_value(original_val, field, strategy, seed + i)
            originals[field] = original_val
            if strategy == "field_omit":
                del_path(out, field)
                mutated_vals[field] = None
            else:
                set_path(out, field, mutated_val)
                mutated_vals[field] = mutated_val
        out["_mutation_meta"] = {
            "strategy": strategy,
            "field_targeted": fields[0],
            "fields_targeted": fields,
            "original_value": originals[fields[0]],
            "mutated_value": mutated_vals[fields[0]],
        }
        return out

    def _mutate_value(self, original_val, target_field: str, strategy: str, seed: int):
        mutated_val = original_val

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
        elif strategy == "combined_evasion":
            # Layer case flip, homoglyph substitution and zero-width injection.
            if isinstance(original_val, str):
                rng = random.Random(seed)
                flipped = ''.join(c.upper() if rng.random() > 0.5 else c.lower() for c in original_val)
                glyphs = "".join(self.HOMOGLYPHS.get(c, c) for c in flipped)
                mutated_val = "\u200b".join(glyphs)
            elif isinstance(original_val, list):
                mutated_val = [v.upper() if isinstance(v, str) else v for v in original_val] + ["swapped_value_sim"]

        return mutated_val

    def mutate_all_strategies(self, artifact: dict, seed: int = 42) -> List[dict]:
        """Returns one variant per strategy, list of 6 dicts."""
        return [self.mutate_targeted(artifact, s, seed + i) for i, s in enumerate(self.STRATEGIES)]
