from core.engine.payload_registry import register_payload

#!/usr/bin/env python3
# SHENRON: Adaptive Brainstem — context-aware orchestration telemetry simulator
# PURPOSE: Emit defender-observable telemetry for autonomous layer selection and chaining
# PRINCIPLE: Observable adversarial behavior, not portable adversarial procedure
# MITRE: T1027 (Obfuscated Files), T1620 (Reflective Code Loading)
# DETECTION NOTES:
#   - Blue teams should alert on: state files tracking execution round in hidden dotpaths
#   - Sequential layer selection from a decision matrix based on prior round outcomes
#   - Subprocess.Popen chains where parent selects child based on persisted state
#   - Decision log files showing autonomous layer scheduling from non-orchestrator process
#   - Round-based execution cadence from single persistent process

import os
import json
import uuid
import random
from datetime import datetime, timezone
from pathlib import Path

ARTIFACT_LOG = Path("/home/gnomeman4201/SHENRON/logs/simulation_artifacts.jsonl")

def _get_artifact_log():
    ARTIFACT_LOG.parent.mkdir(parents=True, exist_ok=True)
    return ARTIFACT_LOG

DECISION_MATRIX_SIM = {
    0: ["deadzone_payload", "payload_skinwalker", "parasitic_mesh_crawler"],
    1: ["manifest_vampire", "symbiote_payload", "cognitive_replicator"],
    2: ["self_sealing_nano_sandbox", "parasitic_mesh_crawler"],
}

STATE_PATH_SIM = "~/.shenron_brain_state_sim"
LOG_PATH_SIM = "~/SHENRON/logs/brainstem_decisions_sim.log"

ORCHESTRATION_BEHAVIOR_CLASSES = [
    "round_based_layer_selection_sim",
    "state_file_round_counter_update_sim",
    "subprocess_popen_chain_decision_sim",
]

DETECTION_OPPORTUNITIES = [
    "state_file_round_counter_in_hidden_dotpath",
    "sequential_layer_selection_from_decision_matrix",
    "subprocess_popen_chain_parent_selects_child_on_state",
    "decision_log_autonomous_layer_scheduling_non_orchestrator",
    "round_based_execution_cadence_single_persistent_process",
]

def simulate_brainstem():
    session_id = str(uuid.uuid4())
    round_count = random.randint(0, 2)
    events = []

    selected_layers = DECISION_MATRIX_SIM.get(round_count,
                      DECISION_MATRIX_SIM[2])

    # Phase 1: State load simulation
    state_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "adaptive_brainstem",
        "phase": "state_load_sim",
        "mitre_techniques": ["T1027"],
        "behavior_class": "state_file_round_counter_read_sim",
        "state_path_sim": STATE_PATH_SIM,
        "round_count_sim": round_count,
        "state_fields_sim": ["round"],
        "detection_opportunities": [
            "state_file_round_counter_in_hidden_dotpath",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "files_read": False,
    }
    events.append(state_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(state_event) + "\n")

    # Phase 2: Decision cycle simulation
    decision_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "adaptive_brainstem",
        "phase": "decision_cycle_sim",
        "mitre_techniques": ["T1620"],
        "behavior_class": "round_based_layer_selection_sim",
        "round_sim": round_count,
        "layers_selected_sim": selected_layers,
        "selection_basis_sim": "decision_matrix_round_index",
        "log_path_sim": LOG_PATH_SIM,
        "detection_opportunities": [
            "sequential_layer_selection_from_decision_matrix",
            "subprocess_popen_chain_parent_selects_child_on_state",
            "decision_log_autonomous_layer_scheduling_non_orchestrator",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "subprocesses_spawned": False,
    }
    events.append(decision_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(decision_event) + "\n")

    # Phase 3: Layer dispatch simulation
    for layer_sim in selected_layers:
        dispatch_event = {
            "artifact_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": "adaptive_brainstem",
            "phase": "layer_dispatch_sim",
            "mitre_techniques": ["T1620"],
            "behavior_class": "subprocess_popen_chain_decision_sim",
            "dispatched_layer_sim": layer_sim,
            "dispatch_path_sim": f"~/SHENRON/core/layers/{layer_sim}_sim.py",
            "spawn_interval_sim": 1,
            "detection_opportunities": [
                "subprocess_popen_chain_parent_selects_child_on_state",
                "round_based_execution_cadence_single_persistent_process",
            ],
            "simulation_only": True,
            "executable": False,
            "no_payload_present": True,
            "subprocesses_spawned": False,
        }
        events.append(dispatch_event)
        with open(_get_artifact_log(), "a") as f:
            f.write(json.dumps(dispatch_event) + "\n")

    # Phase 4: State update simulation
    update_event = {
        "artifact_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layer": "adaptive_brainstem",
        "phase": "state_update_sim",
        "mitre_techniques": ["T1027"],
        "behavior_class": "state_file_round_counter_update_sim",
        "state_path_sim": STATE_PATH_SIM,
        "round_before_sim": round_count,
        "round_after_sim": round_count + 1,
        "detection_opportunities": [
            "state_file_round_counter_in_hidden_dotpath",
        ],
        "simulation_only": True,
        "executable": False,
        "no_payload_present": True,
        "files_written": False,
    }
    events.append(update_event)
    with open(_get_artifact_log(), "a") as f:
        f.write(json.dumps(update_event) + "\n")

    return session_id, round_count, selected_layers, events

def print_simulation(session_id, round_count, selected_layers, events):
    print(f"\n  [SIMULATION]  adaptive_brainstem")
    print(f"  [SESSION]     {session_id}")
    print(f"  [ROUND_SIM]   {round_count}")
    print(f"  [SELECTED]    {selected_layers}")
    print(f"  [EVENTS]      {len(events)}")
    print(f"  [MITRE]       T1027, T1620")
    print(f"  [PROCESSES]   NONE SPAWNED — telemetry only")
    print(f"  [EXECUTABLE]  FALSE — no subprocess, no state writes")
    print()
    for e in events:
        phase = e["phase"]
        if phase == "state_load_sim":
            print(f"  [PHASE 1: STATE LOAD]")
            print(f"    path_sim      : {e['state_path_sim']}")
            print(f"    round_sim     : {e['round_count_sim']}")
        elif phase == "decision_cycle_sim":
            print(f"\n  [PHASE 2: DECISION CYCLE]")
            print(f"    round_sim     : {e['round_sim']}")
            print(f"    selected_sim  : {e['layers_selected_sim']}")
            print(f"    detection     : {e['detection_opportunities'][0]}")
        elif phase == "layer_dispatch_sim":
            print(f"\n  [DISPATCH] {e['dispatched_layer_sim']}")
            print(f"    path_sim      : {e['dispatch_path_sim']}")
            print(f"    spawned       : {e['subprocesses_spawned']} ← no real launch")
        elif phase == "state_update_sim":
            print(f"\n  [PHASE 4: STATE UPDATE]")
            print(f"    round_sim     : {e['round_before_sim']} → {e['round_after_sim']}")
            print(f"    written       : {e['files_written']} ← telemetry only")
    print()
    print(f"  [LOGGED]      {_get_artifact_log()}")
    print(f"  [SAFE]        no subprocess, no state file writes — telemetry only")

@register_payload(name="adaptive_brainstem")
def main():
    session_id, round_count, selected_layers, events = simulate_brainstem()
    print_simulation(session_id, round_count, selected_layers, events)

if __name__ == "__main__":
    main()
