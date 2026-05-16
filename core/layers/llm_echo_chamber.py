from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: LLM Echo Chamber — synthetic AI inference manipulation telemetry simulator
# PURPOSE: Emit defender-observable telemetry for LLM hallucination injection patterns
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1565 (Data Manipulation), T1036 (Masquerading)
# DETECTION NOTES:
#   - Blue teams should alert on: structured LLM-format log entries from non-LLM processes
#   - Hallucination-labeled events at fixed intervals from non-inference process
#   - Log files containing [LLM-HALLUCINATION] tags outside LLM runtime paths
#   - Synthetic AI reasoning traces injected into monitored log directories
#   - Token/embedding metadata fields in logs from processes that don't run inference

import os
import json
import uuid
import random
import hashlib
from datetime import datetime, timezone
from pathlib import Path

ARTIFACT_LOG = Path("/home/gnomeman4201/SHENRON/logs/simulation_artifacts.jsonl")

def _get_artifact_log():
    ARTIFACT_LOG.parent.mkdir(parents=True, exist_ok=True)
    return ARTIFACT_LOG

FAKE_HALLUCINATION_CLASSES = [
    {"class": "query_vector_misalignment_sim",       "desc": "Query vector misalignment at token window"},
    {"class": "self_reflection_confidence_spiral_sim","desc": "Self-reflection loop triggered confidence spiral"},
    {"class": "embedding_drift_goal_state_sim",       "desc": "Embeddings drifted from goal state — recalibrating"},
    {"class": "hallucination_threshold_exceeded_sim", "desc": "Hallucination probability exceeded 0.87 threshold"},
    {"class": "contradictory_pattern_match_sim",      "desc": "Contradictory pattern matching — confusion fallback"},
    {"class": "spurious_corpus_alignment_sim",        "desc": "Spurious alignment with unrelated corpus detected"},
    {"class": "thought_vector_recursion_sim",         "desc": "Thought vector recursion depth exceeds stability bounds"},
    {"class": "decoding_stream_abort_sim",            "desc": "Decoding stream aborted — residual bias overflow"},
    {"class": "coherence_score_anomaly_sim",          "desc": "Coherence score normalized to 0.133 (expected 0.98)"},
    {"class": "agent_reflection_fork_sim",            "desc": "Agent reflection loop: critical logic fork unresolved"},
]

ECHO_BEHAVIOR_CLASSES = [
    "llm_hallucination_trace_inject_sim",
    "synthetic_inference_log_write_sim",
    "fake_reasoning_trace_emit_sim",
]

DETECTION_OPPORTUNITIES = [
    "llm_format_log_entries_from_non_llm_process",
    "hallucination_tagged_events_fixed_interval_non_inference",
    "llm_hallucination_tag_outside_llm_runtime_paths",
    "synthetic_ai_reasoning_traces_injected_monitored_logs",
    "token_embedding_metadata_from_non_inference_process",
]

def _sim_token_window():
    return random.randint(8, 64)

def _sim_coherence():
    return round(random.uniform(0.08, 0.45), 3)

def simulate_echo_chamber():
    session_id = str(uuid.uuid4())
    events = []

    n_traces = random.randint(3, 6)
    selected = random.choices(FAKE_HALLUCINATION_CLASSES, k=n_traces)
    behavior = random.choice(ECHO_BEHAVIOR_CLASSES)

    # Phase 1: Echo session init
    init_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "llm_echo_chamber",
        "phase": "echo_session_init",
        "mitre_techniques": ["T1565"],
        "behavior_class": behavior,
        "target_log_sim": "~/SHENRON/logs/llm_echo_chamber_sim.log",
        "planned_traces_sim": n_traces,
        "write_interval_sim": 1.0,
        "detection_opportunities": [
            "llm_format_log_entries_from_non_llm_process",
            "hallucination_tagged_events_fixed_interval_non_inference",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "files_written": False,
    }
    events.append(init_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(init_event) + "\n")

    # Phase 2: Hallucination trace sequence
    for i, trace_class in enumerate(selected):
        trace_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "llm_echo_chamber",
            "phase": "hallucination_trace_sim",
            "mitre_techniques": ["T1036"],
            "behavior_class": "llm_hallucination_trace_inject_sim",
            "trace_index": i + 1,
            "hallucination_class_sim": trace_class["class"],
            "hallucination_desc_sim": trace_class["desc"],
            "token_window_sim": _sim_token_window(),
            "coherence_score_sim": _sim_coherence(),
            "log_tag_sim": "[LLM-HALLUCINATION]",
            "write_target_sim": "~/SHENRON/logs/llm_echo_chamber_sim.log",
            "interval_sim": 1.0,
            "detection_opportunities": [
                "llm_hallucination_tag_outside_llm_runtime_paths",
                "synthetic_ai_reasoning_traces_injected_monitored_logs",
                "token_embedding_metadata_from_non_inference_process",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "files_written": False,
        }
        events.append(trace_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(trace_event) + "\n")

    return session_id, n_traces, events

def print_simulation(session_id, n_traces, events):
    print(f"\n  [SIMULATION]  llm_echo_chamber")
    print(f"  [SESSION]     {session_id}")
    print(f"  [TRACES_SIM]  {n_traces}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1565, T1036")
    print(f"  [FILES]       NOT WRITTEN — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no file writes, no sleep loops")
    print()
    for e in events:
        if e["phase"] == "echo_session_init":
            print(f"  [PHASE 1: ECHO SESSION INIT]")
            print(f"    behavior      : {e['behavior_class']}")
            print(f"    target_sim    : {e['target_log_sim']}")
            print(f"    interval_sim  : {e['write_interval_sim']}s")
            print(f"    detection     : {e['detection_opportunities'][0]}")
        elif e["phase"] == "hallucination_trace_sim":
            print(f"\n  [TRACE #{e['trace_index']}] {e['hallucination_class_sim']}")
            print(f"    desc_sim      : {e['hallucination_desc_sim']}")
            print(f"    token_win_sim : {e['token_window_sim']}")
            print(f"    coherence_sim : {e['coherence_score_sim']}")
            print(f"    tag_sim       : {e['log_tag_sim']}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no file writes, no sleep — telemetry only")

@register_payload(name="llm_echo_chamber")
def main():
    session_id, n_traces, events = simulate_echo_chamber()
    print_simulation(session_id, n_traces, events)

if __name__ == "__main__":
    main()
