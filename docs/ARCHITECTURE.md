# SHENRON Architecture

## Overview

SHENRON is organized as a pipeline: synthetic telemetry generation → validation → reporting.
shenron.py              — CLI entrypoint (~37KB, legacy dispatch preserved)
core/
cli/                  — subcommand grammar (Priority 1)
commands/           — run, sigma, assumption, schema, export, history, artifact, report
layers/               — 50 canonical simulation layers
engine/               — layer loader, payload registry, scenario engine
layer_loader.py     — discover_canonical() filters mutation variants
payload_registry.py — @register_payload decorator
scenario_engine.py  — chains layers into kill chain timelines
assumptions/          — evidence discipline layer
validator.py        — validate_assumption(), safe_conclusion
model.py            — AssumptionResult, ClaimStatus, AssumptionStatus
scope.py            — out-of-scope violation detection
loader.py           — JSONL artifact ingestion
sigma/                — Sigma rule evaluation engine
evaluator.py        — evaluate_sigma_rule(), TRIGGERED/PARTIAL/NOT_TRIGGERED/UNSUPPORTED
validation/           — detector validation scoring and history
history.py          — record_validation(), load_history(), print_history()
reports/              — HTML and markdown report generation
html_report.py      — standalone HTML, no external deps
formats/              — ECS and Splunk HEC export
adapter.py          — to_ecs(), to_splunk_hec(), write_* bulk writers
schema/               — stdlib-only JSON schema validator
validator.py        — validate_event(), validate_events_file()
safety/               — safety contract definition
contract.py         — required fields, safe defaults
bananatree/           — campaign model (OBSERVE/SIMULATE/EXECUTE/ADAPT)
config.py             — centralized path configuration
quickstart.py         — one-command evidence bundleschemas/                — 4 JSON schemas (event, assumption, sigma_result, safety_contract)
sigma/rules/            — 7 Sigma rules (persistence, c2, evasion)
assumptions/examples/   — 14 assumption YAML files
artifacts/demo/         — committed demo artifact (102 events, 23 MITRE techniques)
tests/                  — 335 tests
## Layer system

`discover_canonical()` in `core/engine/layer_loader.py` filters the 50 canonical layers
from mutation variants using a naming convention heuristic. Variants have 6-character
alphanumeric suffixes (e.g. `adaptive_layer_selector_PTYLo3.py`). Only the shortest-named
file per layer type is loaded and executed.

Layers emit synthetic telemetry as dicts with flat safety fields:
- `simulation_only: true`
- `executable: false`
- `no_payload_present: true`
- `subprocess_spawned: false`

## Campaign model (bananaTREE)
OBSERVE   — enumerate the signal surface, identify detection opportunities
SIMULATE  — generate synthetic telemetry representing adversarial behavior
EXECUTE   — produce artifact timelines (JSONL)
ADAPT     — score coverage, validate assumptions, identify gaps
## Data flow
Layer execution → JSONL artifact → Schema validation → Assumption validation
→ Sigma rule evaluation
→ ECS / HEC export
→ HTML report
→ ATT&CK Navigator layer
## Safety architecture

The safety contract is enforced at three levels:
1. Layer output — every event carries flat boolean safety fields
2. Schema validation — `shenron schema validate` checks all required fields
3. Safety contract module — `core/safety/contract.py` defines required safe defaults

No canonical layer performs real subprocess execution, real filesystem writes outside
the SHENRON log directory, real network connections, or real process spawning.
