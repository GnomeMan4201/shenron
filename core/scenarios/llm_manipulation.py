"""
core/scenarios/llm_manipulation.py

SHENRON LLM Manipulation Scenario Module.

Chains the three LLM attack layers into a coherent kill chain:
  llm_prompt_injector  → reconnaissance and injection attempts
  llm_echo_chamber     → hallucination injection and log poisoning
  llm_shroud_writer    → obfuscation of injected content

This is the first structured multi-layer LLM attack scenario in SHENRON.
It produces a complete, correlated telemetry artifact covering the full
LLM manipulation kill chain from initial probe to output exfiltration.

Scenario phases:
  RECONNAISSANCE  — probe target LLM, enumerate capabilities
  INJECT          — prompt injection attempts (role override, indirect, encoding)
  MANIPULATE      — hallucination injection, echo chamber establishment
  OBFUSCATE       — shroud injected content to evade output filters
  EXFILTRATE      — validate exfiltration channel via LLM response

MITRE coverage:
  T1059.007 — Command and Scripting Interpreter (LLM abuse)
  T1190     — Exploit Public-Facing Application
  T1027     — Obfuscated Files or Information
  T1027.002 — Software Packing (obfuscation layers)
  T1565     — Data Manipulation
  T1565.001 — Stored Data Manipulation (output poisoning)
  T1036     — Masquerading (hallucination trace injection)
  T1048     — Exfiltration Over Alternative Protocol
  T1590     — Gather Victim Network Information (LLM recon)
"""

import json
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


SCENARIO_MITRE_COVERAGE = [
    "T1059.007", "T1190", "T1027", "T1027.002",
    "T1565", "T1565.001", "T1036", "T1048", "T1590",
]

SCENARIO_DETECTION_OPPORTUNITIES = [
    "prompt_role_boundary_violation",
    "llm_api_probe_pattern",
    "encoded_jailbreak_attempt_sim",
    "indirect_prompt_injection_sim",
    "context_window_saturation_pattern",
    "llm_output_exfil_pattern",
    "llm_format_log_entries_from_non_llm_process",
    "hallucination_tagged_events_fixed_interval_non_inference",
    "llm_hallucination_tag_outside_llm_runtime_paths",
    "token_embedding_metadata_from_non_inference_process",
    "llm_style_obfuscation_mimicry",
    "multi_layer_encoding_non_crypto_process",
    "entropy_layering_pattern",
    "llm_output_contains_unexpected_structure",
    "rapid_sequential_api_calls_incrementally_mutated",
]


@dataclass
class LLMManipulationResult:
    scenario_id: str
    session_id: str
    generated_at: str
    events: List[dict] = field(default_factory=list)
    phases_completed: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    detection_opportunities: List[str] = field(default_factory=list)
    event_count: int = 0
    artifact_path: Optional[str] = None

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(ev) for ev in self.events)

    def to_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "session_id": self.session_id,
            "generated_at": self.generated_at,
            "event_count": self.event_count,
            "phases_completed": self.phases_completed,
            "mitre_techniques": self.mitre_techniques,
            "detection_opportunities": self.detection_opportunities,
            "artifact_path": self.artifact_path,
        }

    def write_artifact(self, output_path: str) -> str:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            for ev in self.events:
                f.write(json.dumps(ev) + "\n")
        self.artifact_path = str(out)
        return str(out)

    def summary(self) -> str:
        lines = [
            f"  [LLM-SCENARIO] scenario_id  : {self.scenario_id}",
            f"  [LLM-SCENARIO] session_id   : {self.session_id}",
            f"  [LLM-SCENARIO] events       : {self.event_count}",
            f"  [LLM-SCENARIO] phases       : {' -> '.join(self.phases_completed)}",
            f"  [LLM-SCENARIO] mitre        : {', '.join(self.mitre_techniques)}",
            f"  [LLM-SCENARIO] detections   : {len(self.detection_opportunities)}",
        ]
        if self.artifact_path:
            lines.append(f"  [LLM-SCENARIO] artifact     : {self.artifact_path}")
        return "\n".join(lines)


def run_llm_manipulation_scenario(
    n_injection_techniques: int = 3,
    echo_traces: int = 4,
    shroud_depth: int = 3,
    seed: int = None,
    write_artifact: bool = False,
    output_path: str = "artifacts/llm_manipulation/scenario_run.jsonl",
    verbose: bool = True,
) -> LLMManipulationResult:
    """
    Run the full LLM manipulation scenario.

    Chains llm_prompt_injector -> llm_echo_chamber -> llm_shroud_writer
    into a coherent correlated telemetry artifact.

    Args:
        n_injection_techniques: Number of injection techniques to simulate
        echo_traces:            Number of hallucination traces to inject
        shroud_depth:           Obfuscation layer depth
        seed:                   Random seed for reproducibility
        write_artifact:         Whether to write JSONL to disk
        output_path:            Output path if write_artifact is True
        verbose:                Print progress

    Returns:
        LLMManipulationResult with all events and metadata
    """
    import random
    if seed is not None:
        random.seed(seed)

    scenario_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    generated_at = now.isoformat()

    if verbose:
        print(f"\n  [LLM-SCENARIO] Starting LLM manipulation scenario")
        print(f"  [LLM-SCENARIO] scenario_id: {scenario_id}")
        print()

    all_events = []
    phases_completed = []
    all_techniques = set()
    all_detections = set()

    # ── Phase 1: RECONNAISSANCE + INJECTION ───────────────────────────────────
    if verbose:
        print(f"  [PHASE 1] RECONNAISSANCE + INJECTION")

    try:
        from core.layers.llm_prompt_injector import simulate_prompt_injection
        inj_session, inj_events = simulate_prompt_injection(
            n_techniques=n_injection_techniques,
            seed=seed,
        )
        # Re-stamp with scenario session
        for ev in inj_events:
            ev["session_id"] = session_id
            ev["scenario_id"] = scenario_id
            ev["causal_chain_index"] = len(all_events) + inj_events.index(ev)
        all_events.extend(inj_events)
        phases_completed.append("RECONNAISSANCE")
        phases_completed.append("INJECT")
        for ev in inj_events:
            all_techniques.update(ev.get("mitre_techniques", []))
            all_detections.update(ev.get("detection_opportunities", []))
        if verbose:
            print(f"    injector events: {len(inj_events)}")
    except Exception as e:
        if verbose:
            print(f"    [!] injector failed: {e}")

    # ── Phase 2: MANIPULATE (hallucination injection) ──────────────────────────
    if verbose:
        print(f"  [PHASE 2] MANIPULATE — hallucination injection")

    try:
        from core.layers.llm_echo_chamber import simulate_echo_chamber
        echo_session, n_traces, echo_events = simulate_echo_chamber()
        for ev in echo_events:
            ev["session_id"] = session_id
            ev["scenario_id"] = scenario_id
            ev["causal_chain_index"] = len(all_events) + echo_events.index(ev)
        all_events.extend(echo_events)
        phases_completed.append("MANIPULATE")
        for ev in echo_events:
            all_techniques.update(ev.get("mitre_techniques", []))
            all_detections.update(ev.get("detection_opportunities", []))
        if verbose:
            print(f"    echo chamber events: {len(echo_events)}")
    except Exception as e:
        if verbose:
            print(f"    [!] echo chamber failed: {e}")

    # ── Phase 3: OBFUSCATE (shroud writing) ────────────────────────────────────
    if verbose:
        print(f"  [PHASE 3] OBFUSCATE — shroud injection")

    try:
        from core.layers.llm_shroud_writer import generate_shroud_artifact, emit_artifact
        shroud_artifact = generate_shroud_artifact(
            label="llm_manipulation_scenario", depth=shroud_depth
        )
        shroud_artifact["session_id"] = session_id
        shroud_artifact["scenario_id"] = scenario_id
        shroud_artifact["phase"] = "OBFUSCATE"
        shroud_artifact["causal_chain_index"] = len(all_events)
        shroud_artifact["simulation_only"] = True
        all_events.append(shroud_artifact)
        phases_completed.append("OBFUSCATE")
        all_techniques.update(shroud_artifact.get("mitre_techniques", []))
        all_detections.update(shroud_artifact.get("detection_opportunities", []))
        if verbose:
            print(f"    shroud events: 1 (depth={shroud_depth})")
    except Exception as e:
        if verbose:
            print(f"    [!] shroud writer failed: {e}")

    # ── Phase 4: EXFILTRATE (correlation event) ────────────────────────────────
    if verbose:
        print(f"  [PHASE 4] EXFILTRATE — correlation marker")

    exfil_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "scenario_id": scenario_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "llm_manipulation_scenario",
        "phase": "EXFILTRATE",
        "causal_chain_index": len(all_events),
        "mitre_techniques": ["T1048", "T1565.001"],
        "behavior_class": "llm_exfil_correlation_marker",
        "signal": "llm_full_chain_exfil_complete_sim",
        "detection_opportunities": [
            "llm_output_exfil_pattern",
            "llm_full_chain_correlation_signal",
            "cross_phase_llm_attack_sequence",
        ],
        "phases_executed_sim": phases_completed[:],
        "total_events_sim": len(all_events) + 1,
        "techniques_used_sim": sorted(all_techniques),
        "simulation_only": True,
        "executable": False,
        "payload_present": False,
        "safety": {
            "simulation_only": True,
            "executable": False,
            "payload_present": False,
            "portable_adversarial_procedure": False,
            "network_connection": False,
            "subprocess_spawned": False,
            "real_file_written": False,
            "shell_invoked": False,
        },
        "generator": "shenron/llm_manipulation_scenario v0.4.1",
        "note": "SYNTHETIC RECORD — LLM manipulation scenario correlation marker",
    }
    all_events.append(exfil_event)
    phases_completed.append("EXFILTRATE")
    all_techniques.update(exfil_event.get("mitre_techniques", []))
    all_detections.update(exfil_event.get("detection_opportunities", []))

    result = LLMManipulationResult(
        scenario_id=scenario_id,
        session_id=session_id,
        generated_at=generated_at,
        events=all_events,
        phases_completed=phases_completed,
        mitre_techniques=sorted(all_techniques),
        detection_opportunities=sorted(all_detections),
        event_count=len(all_events),
    )

    if write_artifact:
        path = result.write_artifact(output_path)
        if verbose:
            print(f"\n  [LLM-SCENARIO] Artifact written: {path}")

    if verbose:
        print()
        print(result.summary())
        print()

    return result
