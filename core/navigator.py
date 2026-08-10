#!/usr/bin/env python3
# SHENRON: ATT&CK Navigator layer exporter
# PURPOSE: Export synthetic technique coverage as a Navigator-compatible JSON layer
# PRINCIPLE: Descriptor coverage only — not real ATT&CK validation
# Spec: https://github.com/mitre-attack/attack-navigator/blob/master/LAYER_FORMAT.md

import json
from datetime import datetime, timezone
from typing import List, Optional

from core.version import get_version


# Tactic ordering matches ATT&CK Enterprise matrix left-to-right
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

# Colour scale: intensity mapped to a coverage score 0.0–1.0
# Navigator uses hex colours per technique
_SCORE_COLOR_HIGH   = "#e05d44"   # red — high confidence descriptor match
_SCORE_COLOR_MED    = "#f8a11a"   # amber — partial match
_SCORE_COLOR_LOW    = "#4a90d9"   # blue — MITRE-only match
_SCORE_COLOR_DEFAULT = "#4a90d9"


def _make_technique_entry(
    technique_id: str,
    color: str = _SCORE_COLOR_DEFAULT,
    comment: str = "",
    score: int = 1,
    enabled: bool = True,
) -> dict:
    """Single technique entry in Navigator layer format."""
    entry = {
        "techniqueID": technique_id,
        "score": score,
        "color": color,
        "comment": comment or "SYNTHETIC — descriptor coverage only, not real ATT&CK validation",
        "enabled": enabled,
        "metadata": [],
        "links": [],
        "showSubtechniques": False,
    }
    # If it's a sub-technique (e.g. T1036.005), show parent subtechniques
    if "." in technique_id:
        entry["showSubtechniques"] = True
    return entry


def build_navigator_layer(
    techniques: List[str],
    run_id: str = "",
    campaign_name: str = "",
    description: str = "",
    partial_techniques: Optional[List[str]] = None,
    domain: str = "enterprise-attack",
    version: str = "4.5",
) -> dict:
    """
    Build an ATT&CK Navigator layer dict from a list of technique IDs.

    techniques:          full-coverage technique IDs (red)
    partial_techniques:  partial-match technique IDs (amber)
    """
    partial_techniques = partial_techniques or []
    partial_set = set(partial_techniques)

    now = datetime.now(timezone.utc).isoformat()

    technique_entries = []
    seen = set()

    for tid in techniques:
        if tid in seen:
            continue
        seen.add(tid)
        color  = _SCORE_COLOR_MED if tid in partial_set else _SCORE_COLOR_HIGH
        score  = 50 if tid in partial_set else 100
        comment = (
            f"SYNTHETIC partial-match coverage — {campaign_name} run {run_id[:8]}"
            if tid in partial_set
            else f"SYNTHETIC full-match coverage — {campaign_name} run {run_id[:8]}"
        )
        technique_entries.append(
            _make_technique_entry(tid, color=color, comment=comment, score=score)
        )

    # Partial-only techniques not already in full set
    for tid in partial_techniques:
        if tid not in seen:
            seen.add(tid)
            technique_entries.append(
                _make_technique_entry(
                    tid,
                    color=_SCORE_COLOR_MED,
                    comment=f"SYNTHETIC partial-match coverage — {campaign_name} run {run_id[:8]}",
                    score=50,
                )
            )

    layer_description = (
        description
        or (
            f"SHENRON synthetic telemetry coverage — {campaign_name} — run {run_id[:8]}. "
            f"MITRE-style descriptor coverage only. "
            f"Not real ATT&CK validation or detector coverage. "
            f"Generated {now[:10]}."
        )
    )

    return {
        "name": f"SHENRON — {campaign_name or 'synthetic coverage'} [{run_id[:8]}]",
        "versions": {
            "attack": "14",
            "navigator": version,
            "layer": "4.5",
        },
        "domain": domain,
        "description": layer_description,
        "filters": {
            "platforms": [
                "Linux", "macOS", "Windows",
                "Network", "PRE", "Containers",
                "Office Suite", "Identity Provider",
            ]
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "max",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
        "techniques": technique_entries,
        "gradient": {
            "colors": ["#ffffff", _SCORE_COLOR_MED, _SCORE_COLOR_HIGH],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Full descriptor match (synthetic)", "color": _SCORE_COLOR_HIGH},
            {"label": "Partial descriptor match (synthetic)", "color": _SCORE_COLOR_MED},
        ],
        "metadata": [
            {"name": "generated_by",    "value": f"SHENRON v{get_version()}"},
            {"name": "run_id",          "value": run_id},
            {"name": "campaign",        "value": campaign_name},
            {"name": "simulation_only", "value": "true"},
            {"name": "generated_at",    "value": now},
            {"name": "warning",
             "value": "SYNTHETIC descriptor coverage. Not real ATT&CK validation."},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1a1a2e",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }


def export_navigator_layer(
    techniques: List[str],
    output_path: str,
    run_id: str = "",
    campaign_name: str = "",
    partial_techniques: Optional[List[str]] = None,
) -> str:
    """Write Navigator layer JSON to output_path. Returns the path."""
    layer = build_navigator_layer(
        techniques=techniques,
        run_id=run_id,
        campaign_name=campaign_name,
        partial_techniques=partial_techniques,
    )
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)
    return output_path


def print_navigator_summary(techniques: List[str], run_id: str, campaign: str):
    print()
    print(f"  [NAVIGATOR]   ATT&CK Navigator layer export")
    print(f"  [RUN]         {run_id[:8]}  {campaign}")
    print(f"  [TECHNIQUES]  {len(techniques)} descriptor IDs")
    print(f"  [NOTE]        SYNTHETIC coverage — not real ATT&CK validation")
    print()
