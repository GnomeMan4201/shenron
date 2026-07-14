"""
core/sigma/generator.py

SHENRON Sigma Rule Generator.

Consumes a SHENRON campaign JSONL artifact and produces candidate Sigma rules
grounded in the telemetry that generated them. Rules are validated against the
same artifact using the existing evaluator before being written to disk.

This closes the loop:
  SHENRON generates campaign → generator proposes Sigma rules →
  evaluator validates rules fire on the generating artifact →
  rules written with validation verdict in metadata.

No LLM. Fully deterministic. Rules are assembled from the signal vocabulary
already present in the artifact and the manifest.

Design constraints:
- New file only. Zero modifications to existing core files.
- Uses only: core/sigma/evaluator.py, core/sigma/loader.py,
  core/sigma/model.py, core/engine/layer_loader.py, shenron_manifest.json
- No subprocess, no network, no execution.
"""

import json
import os
import uuid
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

# Reuse existing evaluator and loader
from core.sigma.evaluator import evaluate_sigma_rule
from core.sigma.model import RuleVerdict


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class GeneratedRule:
    rule_id: str
    title: str
    layer: str
    mitre_techniques: List[str]
    detection_opportunities: List[str]
    behavior_class: str
    phase: str
    sigma_yaml: str
    validation_verdict: str       # TRIGGERED / PARTIAL / NOT_TRIGGERED / UNSUPPORTED
    validated_against: str        # artifact path used for validation
    generated_at: str
    confidence: str               # HIGH / MEDIUM / LOW


@dataclass
class GenerationReport:
    artifact_path: str
    generated_at: str
    rules_generated: int
    rules_validated_triggered: int
    rules_validated_partial: int
    rules_not_triggered: int
    rules: List[GeneratedRule] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "artifact_path": self.artifact_path,
            "generated_at": self.generated_at,
            "rules_generated": self.rules_generated,
            "rules_validated_triggered": self.rules_validated_triggered,
            "rules_validated_partial": self.rules_validated_partial,
            "rules_not_triggered": self.rules_not_triggered,
            "rules": [
                {
                    "rule_id": r.rule_id,
                    "title": r.title,
                    "layer": r.layer,
                    "mitre_techniques": r.mitre_techniques,
                    "detection_opportunities": r.detection_opportunities,
                    "behavior_class": r.behavior_class,
                    "phase": r.phase,
                    "validation_verdict": r.validation_verdict,
                    "confidence": r.confidence,
                    "generated_at": r.generated_at,
                }
                for r in self.rules
            ],
        }

    def to_markdown(self) -> str:
        lines = [
            "# SHENRON Sigma Rule Generation Report",
            "",
            f"**Artifact:** {self.artifact_path}  ",
            f"**Generated:** {self.generated_at}  ",
            f"**Rules Generated:** {self.rules_generated}  ",
            f"**Validated TRIGGERED:** {self.rules_validated_triggered}  ",
            f"**Validated PARTIAL:** {self.rules_validated_partial}  ",
            f"**Not Triggered:** {self.rules_not_triggered}  ",
            "",
            "## Rules",
            "",
            "| Title | Layer | Techniques | Verdict | Confidence |",
            "|-------|-------|-----------|---------|-----------|",
        ]
        for r in self.rules:
            techs = ", ".join(r.mitre_techniques[:3])
            lines.append(
                f"| {r.title} | {r.layer} | {techs} | "
                f"{r.validation_verdict} | {r.confidence} |"
            )
        return "\n".join(lines)


# ── Manifest loader ────────────────────────────────────────────────────────────

def _load_manifest_index(manifest_path: str = "shenron_manifest.json") -> Dict[str, dict]:
    """Load manifest and index by layer name."""
    p = Path(manifest_path)
    if not p.exists():
        # Try relative to repo root
        p = Path(__file__).parent.parent.parent / "shenron_manifest.json"
    if not p.exists():
        return {}
    data = json.loads(p.read_text(encoding="utf-8"))
    return {layer["name"]: layer for layer in data.get("layers", [])}


# ── Artifact analysis ──────────────────────────────────────────────────────────

def _load_artifact(path: str) -> List[dict]:
    """Load SHENRON JSONL artifact."""
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events


def _group_by_layer(events: List[dict]) -> Dict[str, List[dict]]:
    """Group events by layer name."""
    groups: Dict[str, List[dict]] = {}
    for ev in events:
        layer = ev.get("layer", "unknown")
        groups.setdefault(layer, []).append(ev)
    return groups


def _extract_signal_vocabulary(events: List[dict]) -> Dict[str, Any]:
    """Extract all signal vocabulary from a group of events for one layer."""
    behavior_classes = list({ev.get("behavior_class", "") for ev in events if ev.get("behavior_class")})
    detection_opps = []
    for ev in events:
        opps = ev.get("detection_opportunities", [])
        if isinstance(opps, list):
            detection_opps.extend(opps)
    detection_opps = list(dict.fromkeys(detection_opps))  # dedup preserving order

    techniques = []
    for ev in events:
        techs = ev.get("mitre_techniques", [])
        if isinstance(techs, list):
            techniques.extend(techs)
        t = ev.get("mitre_technique")
        if t:
            techniques.append(t)
    techniques = list(dict.fromkeys(techniques))

    phases = list({ev.get("phase", "") for ev in events if ev.get("phase")})
    layers = list({ev.get("layer", "") for ev in events if ev.get("layer")})

    return {
        "behavior_classes": behavior_classes,
        "detection_opportunities": detection_opps,
        "mitre_techniques": techniques,
        "phases": phases,
        "layer": layers[0] if layers else "unknown",
    }


# ── MITRE tactic mapping ───────────────────────────────────────────────────────

_TECHNIQUE_TO_TACTIC = {
    "T1071": "command-and-control",
    "T1071.001": "command-and-control",
    "T1071.004": "command-and-control",
    "T1132": "command-and-control",
    "T1095": "command-and-control",
    "T1572": "command-and-control",
    "T1048": "exfiltration",
    "T1041": "exfiltration",
    "T1020": "exfiltration",
    "T1027": "defense-evasion",
    "T1027.002": "defense-evasion",
    "T1036": "defense-evasion",
    "T1036.005": "defense-evasion",
    "T1070": "defense-evasion",
    "T1070.004": "defense-evasion",
    "T1014": "defense-evasion",
    "T1564": "defense-evasion",
    "T1055": "privilege-escalation",
    "T1055.012": "privilege-escalation",
    "T1068": "privilege-escalation",
    "T1134": "privilege-escalation",
    "T1053": "persistence",
    "T1053.003": "persistence",
    "T1053.005": "persistence",
    "T1547": "persistence",
    "T1547.001": "persistence",
    "T1543": "persistence",
    "T1543.003": "persistence",
    "T1021": "lateral-movement",
    "T1021.001": "lateral-movement",
    "T1021.002": "lateral-movement",
    "T1059": "execution",
    "T1059.001": "execution",
    "T1059.007": "execution",
    "T1047": "execution",
    "T1082": "discovery",
    "T1135": "discovery",
    "T1110": "credential-access",
    "T1003": "credential-access",
    "T1589": "reconnaissance",
    "T1590": "reconnaissance",
    "T1595": "reconnaissance",
    "T1573": "command-and-control",
    "T1573.001": "command-and-control",
    "T1497": "defense-evasion",
    "T1622": "defense-evasion",
    "T1574": "persistence",
    "T1574.002": "persistence",
    "T1205": "command-and-control",
    "T1046": "discovery",
}

def _get_tactic(technique: str) -> str:
    return _TECHNIQUE_TO_TACTIC.get(technique, "defense-evasion")


def _get_attack_tags(techniques: List[str]) -> List[str]:
    tags = []
    seen_tactics = set()
    for t in techniques:
        tactic = _get_tactic(t)
        tags.append(f"attack.{t.lower()}")
        if tactic not in seen_tactics:
            tags.append(f"attack.{tactic}")
            seen_tactics.add(tactic)
    return tags


# ── Rule assembler ─────────────────────────────────────────────────────────────

def _confidence_from_vocab(vocab: dict) -> str:
    """Estimate rule confidence based on signal vocabulary richness."""
    opp_count = len(vocab["detection_opportunities"])
    bc_count = len(vocab["behavior_classes"])
    tech_count = len(vocab["mitre_techniques"])

    score = opp_count * 2 + bc_count * 3 + tech_count
    if score >= 8:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def _build_sigma_yaml(
    rule_id: str,
    title: str,
    description: str,
    layer: str,
    vocab: dict,
    manifest_entry: Optional[dict],
    generated_at: str,
) -> str:
    """Assemble a Sigma YAML rule string from signal vocabulary."""

    techniques = vocab["mitre_techniques"]
    behavior_classes = vocab["behavior_classes"]
    detection_opps = vocab["detection_opportunities"]
    phases = vocab["phases"]
    attack_tags = _get_attack_tags(techniques)

    # Build logsource
    logsource_lines = [
        "logsource:",
        "    product: shenron",
        "    category: simulation",
    ]
    if manifest_entry:
        log_sources = manifest_entry.get("detection", {}).get("log_sources", [])
        if log_sources:
            logsource_lines.append(f"    service: {log_sources[0]}")

    # Build detection block
    detection_lines = ["detection:"]

    # Primary selection: layer + behavior_class
    detection_lines.append("    selection_layer:")
    detection_lines.append(f"        layer: {layer}")
    if behavior_classes:
        if len(behavior_classes) == 1:
            detection_lines.append(f"        behavior_class: {behavior_classes[0]}")
        else:
            detection_lines.append("        behavior_class|contains:")
            for bc in behavior_classes[:4]:
                detection_lines.append(f"            - {bc}")

    # Secondary selection: detection opportunities
    if detection_opps:
        detection_lines.append("    selection_signals:")
        detection_lines.append("        detection_opp:")
        for opp in detection_opps[:5]:
            detection_lines.append(f"            - {opp}")

    # Tertiary selection: MITRE techniques
    if techniques:
        detection_lines.append("    selection_techniques:")
        detection_lines.append("        mitre_technique:")
        for t in techniques[:4]:
            detection_lines.append(f"            - {t}")

    # Phase filter if available
    if phases:
        detection_lines.append("    filter_phase:")
        detection_lines.append("        phase:")
        for ph in phases[:3]:
            detection_lines.append(f"            - {ph}")

    # Condition: require layer match, optionally combine with signals
    if detection_opps and techniques:
        condition = "selection_layer and (selection_signals or selection_techniques)"
    elif detection_opps:
        condition = "selection_layer and selection_signals"
    elif techniques:
        condition = "selection_layer and selection_techniques"
    else:
        condition = "selection_layer"

    detection_lines.append(f"    condition: {condition}")

    # False positives from manifest or generic
    fp_list = []
    if manifest_entry:
        fps = manifest_entry.get("detection", {}).get("falsepositives", [])
        fp_list.extend(fps)
    if not fp_list:
        fp_list = ["Authorized security testing", "SHENRON synthetic telemetry validation runs"]

    fp_lines = ["falsepositives:"]
    for fp in fp_list[:3]:
        fp_lines.append(f"    - {fp}")

    # Tags block
    tag_lines = ["tags:"]
    for tag in attack_tags[:6]:
        tag_lines.append(f"    - {tag}")
    tag_lines.append("    - shenron.generated")

    # Assemble
    yaml_parts = [
        f"title: {title}",
        f"id: {rule_id}",
        "status: experimental",
        f"description: >",
        f"    {description}",
        f"author: shenron-generator / gnomeman4201 / badBANANA Research Collective",
        f"date: {generated_at[:10]}",
        "references:",
        "    - https://github.com/GnomeMan4201/shenron",
        "\n".join(tag_lines),
        "\n".join(logsource_lines),
        "\n".join(detection_lines),
        "\n".join(fp_lines),
        "level: medium",
        "fields:",
        "    - artifact_id",
        "    - layer",
        "    - phase",
        "    - behavior_class",
        "    - detection_opportunities",
        "    - mitre_techniques",
        "    - simulation_only",
        f"# Generated by SHENRON sigma generator from artifact telemetry",
        f"# Validation verdict will be appended after generation",
    ]

    return "\n".join(yaml_parts)


# ── Validator ──────────────────────────────────────────────────────────────────

def _validate_rule(sigma_yaml: str, artifact_path: str) -> str:
    """Write rule to temp file, evaluate against artifact, return verdict string."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", delete=False, encoding="utf-8"
    ) as f:
        f.write(sigma_yaml)
        tmp_path = f.name
    try:
        result = evaluate_sigma_rule(tmp_path, artifact_path, match_mode="tolerant")
        return result.verdict.value
    except Exception as e:
        return f"ERROR: {e}"
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


# ── Main generator ─────────────────────────────────────────────────────────────

def generate_rules(
    artifact_path: str,
    output_dir: str = "sigma/rules/generated",
    manifest_path: str = "shenron_manifest.json",
    validate: bool = True,
    min_confidence: str = "LOW",
    verbose: bool = True,
) -> GenerationReport:
    """
    Generate Sigma rules from a SHENRON JSONL artifact.

    Args:
        artifact_path: Path to SHENRON JSONL artifact
        output_dir: Directory to write generated .yml rules
        manifest_path: Path to shenron_manifest.json
        validate: Whether to validate rules against the generating artifact
        min_confidence: Minimum confidence level to write (LOW/MEDIUM/HIGH)
        verbose: Print progress

    Returns:
        GenerationReport with all generated rules and validation results
    """
    now = datetime.now(timezone.utc).isoformat()
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    manifest = _load_manifest_index(manifest_path)
    events = _load_artifact(artifact_path)
    by_layer = _group_by_layer(events)

    conf_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    min_conf_val = conf_order.get(min_confidence, 0)

    report = GenerationReport(
        artifact_path=artifact_path,
        generated_at=now,
        rules_generated=0,
        rules_validated_triggered=0,
        rules_validated_partial=0,
        rules_not_triggered=0,
    )

    if verbose:
        print(f"\n  [SIGMA-GEN] Artifact: {artifact_path}")
        print(f"  [SIGMA-GEN] Layers found: {len(by_layer)}")
        print(f"  [SIGMA-GEN] Validate: {validate}")
        print()

    for layer, layer_events in sorted(by_layer.items()):
        # Skip non-telemetry or meta layers
        manifest_entry = manifest.get(layer, {})
        if not manifest_entry.get("telemetry_layer", True) and layer != "unknown":
            if verbose:
                print(f"  [SKIP] {layer} (non-telemetry layer)")
            continue

        vocab = _extract_signal_vocabulary(layer_events)

        if not vocab["mitre_techniques"] and not vocab["behavior_classes"]:
            if verbose:
                print(f"  [SKIP] {layer} (no signal vocabulary)")
            continue

        confidence = _confidence_from_vocab(vocab)
        if conf_order.get(confidence, 0) < min_conf_val:
            if verbose:
                print(f"  [SKIP] {layer} (confidence {confidence} below minimum {min_confidence})")
            continue

        rule_id = f"shenron-gen-{layer[:20].replace('_', '-')}-{uuid.uuid4().hex[:6]}"
        title = f"SHENRON Generated — {layer.replace('_', ' ').title()}"

        # Build description from manifest or vocab
        if manifest_entry.get("description"):
            description = f"Generated rule for {layer}. {manifest_entry['description'][:120]}"
        else:
            techs = ", ".join(vocab["mitre_techniques"][:3])
            description = f"Generated rule for {layer} layer. Techniques: {techs}."

        sigma_yaml = _build_sigma_yaml(
            rule_id=rule_id,
            title=title,
            description=description,
            layer=layer,
            vocab=vocab,
            manifest_entry=manifest_entry,
            generated_at=now,
        )

        # Validate
        verdict = "NOT_VALIDATED"
        if validate:
            verdict = _validate_rule(sigma_yaml, artifact_path)

        # Append validation verdict to YAML as comment
        sigma_yaml_final = sigma_yaml + f"\n# validation_verdict: {verdict}\n"

        # Write rule file
        out_path = Path(output_dir) / f"{layer}.yml"
        out_path.write_text(sigma_yaml_final, encoding="utf-8")

        generated_rule = GeneratedRule(
            rule_id=rule_id,
            title=title,
            layer=layer,
            mitre_techniques=vocab["mitre_techniques"],
            detection_opportunities=vocab["detection_opportunities"],
            behavior_class=vocab["behavior_classes"][0] if vocab["behavior_classes"] else "",
            phase=vocab["phases"][0] if vocab["phases"] else "",
            sigma_yaml=sigma_yaml_final,
            validation_verdict=verdict,
            validated_against=artifact_path if validate else "",
            generated_at=now,
            confidence=confidence,
        )
        report.rules.append(generated_rule)
        report.rules_generated += 1

        if verdict in ("TRIGGERED",):
            report.rules_validated_triggered += 1
        elif verdict == "PARTIAL":
            report.rules_validated_partial += 1
        elif verdict == "NOT_TRIGGERED":
            report.rules_not_triggered += 1

        if verbose:
            mark = {"TRIGGERED": "+", "PARTIAL": "~", "NOT_TRIGGERED": "-",
                    "UNSUPPORTED": "?", "NOT_VALIDATED": " "}.get(verdict, " ")
            print(
                f"  [{mark}] {layer:<40} conf={confidence:<6} "
                f"techs={len(vocab['mitre_techniques']):<3} "
                f"opps={len(vocab['detection_opportunities']):<3} "
                f"verdict={verdict}"
            )

    if verbose:
        print()
        print(f"  [SIGMA-GEN] Generated : {report.rules_generated}")
        print(f"  [SIGMA-GEN] TRIGGERED : {report.rules_validated_triggered}")
        print(f"  [SIGMA-GEN] PARTIAL   : {report.rules_validated_partial}")
        print(f"  [SIGMA-GEN] NOT HIT   : {report.rules_not_triggered}")
        print(f"  [SIGMA-GEN] Output    : {output_dir}")
        print()

    return report
