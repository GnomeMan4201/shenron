#!/usr/bin/env python3
# bananaTREE: Taxonomy — map Shenron layer categories to bananaTREE phases
from core.bananatree.cycle import Phase

CATEGORY_PHASE_MAP: dict = {
    "c2":          Phase.OBSERVE,
    "entropy":     Phase.OBSERVE,
    "identity":    Phase.OBSERVE,
    "evasion":     Phase.SIMULATE,
    "payload":     Phase.SIMULATE,
    "llm":         Phase.SIMULATE,
    "persistence": Phase.EXECUTE,
    "meta":        Phase.ADAPT,
}

PHASE_INTENT = {
    Phase.OBSERVE:  "Map adversarial signal surface. Enumerate C2, entropy, and identity patterns.",
    Phase.SIMULATE: "Generate defender-observable synthetic telemetry. Train SIEM rules.",
    Phase.EXECUTE:  "Run simulation layers in safe mode. Produce JSONL artifact timelines.",
    Phase.ADAPT:    "Consume findings. Update detection rules. Close coverage gaps.",
}

PHASE_MITRE_TACTICS = {
    Phase.OBSERVE:  ["command-and-control", "collection", "defense-evasion"],
    Phase.SIMULATE: ["defense-evasion", "execution", "impact"],
    Phase.EXECUTE:  ["persistence", "privilege-escalation", "lateral-movement"],
    Phase.ADAPT:    ["defense-evasion", "collection"],
}


def get_phase(category: str) -> Phase:
    return CATEGORY_PHASE_MAP.get(category.lower(), Phase.SIMULATE)


def get_layers_by_phase(manifest: list) -> dict:
    result = {p: [] for p in Phase}
    for layer in manifest:
        cat = layer.get("category", "")
        phase = get_phase(cat)
        result[phase].append(layer)
    return result


def build_phase_summary(manifest: list) -> dict:
    grouped = get_layers_by_phase(manifest)
    summary = {}
    for phase, layers in grouped.items():
        techniques = set()
        for layer in layers:
            mitre = layer.get("mitre", {})
            if isinstance(mitre, dict):
                techniques_list = mitre.get("techniques", [])
            elif isinstance(mitre, list):
                techniques_list = mitre
            else:
                techniques_list = []
            for t in techniques_list:
                techniques.add(t)
        summary[phase.value] = {
            "layer_count":     len(layers),
            "layer_names":     [l["name"] for l in layers],
            "mitre_techniques": sorted(techniques),
            "intent":          PHASE_INTENT[phase],
        }
    return summary
