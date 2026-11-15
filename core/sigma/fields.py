"""
Field policy for SHENRON detection rules and mutation.

LABEL_FIELDS are assigned by the simulator or an analysis pipeline. A real
adversary never emits them, so a rule that keys on them measures whether the
simulator labeled its own output, not whether the behavior is detectable.

Everything else on an event is treated as an observable: what the simulated
activity itself would show (the *_sim fields, nested request data, and so on).
Observables are what an adversary controls, so they are what mutation attacks.

See docs/OBSERVABLE_FIELDS.md.
"""
from typing import Any, List

LABEL_FIELDS = frozenset({
    "layer",
    "phase",
    "signal",
    "behavior_class",
    "detection_opportunities",
    "detection_opp",
    "mitre_technique",
    "mitre_techniques",
    "description",
    "category",
    "note",
})

# Rule folders already converted to observable-only detection. The guard
# test enforces the policy for these; add folders as they are converted.
OBSERVABLE_ONLY_RULE_DIRS = ("c2", "exfiltration", "llm")


def base_field(sigma_field: str) -> str:
    """Strip Sigma modifiers: 'channel_type_sim|contains' -> 'channel_type_sim'."""
    return sigma_field.split("|", 1)[0]


def get_path(event: dict, path: str) -> Any:
    """Read a dotted path ('beacon_data.method'); None if any part is missing."""
    cur: Any = event
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def has_path(event: dict, path: str) -> bool:
    cur: Any = event
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return False
        cur = cur[part]
    return True


def set_path(event: dict, path: str, value: Any) -> None:
    parts = path.split(".")
    cur = event
    for part in parts[:-1]:
        cur = cur[part]
    cur[parts[-1]] = value


def del_path(event: dict, path: str) -> None:
    parts = path.split(".")
    cur = event
    for part in parts[:-1]:
        cur = cur[part]
    cur.pop(parts[-1], None)


def detection_fields(rule: dict) -> List[str]:
    """Base field names referenced by a rule's detection blocks."""
    fields = []
    for name, block in (rule.get("detection") or {}).items():
        if name == "condition":
            continue
        blocks = block if isinstance(block, list) else [block]
        for b in blocks:
            if isinstance(b, dict):
                fields.extend(base_field(k) for k in b)
    return fields
