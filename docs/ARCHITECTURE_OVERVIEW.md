# SHENRON Architecture Overview

## Design intent

SHENRON is built around a single structural constraint: the safety boundary is an
architectural feature, not a disclaimer.

Every component is designed so that adversarial telemetry can be generated, organized,
validated, and reported without any component requiring real network access, process
execution, filesystem modification, or payload delivery.

---

## End-to-end pipeline
Scenario JSON
|
v
bananaTREE Runner          core/scenarios/runner.py
load -> validate -> phase-order -> execute
|
v
bananaTREE Cycle           core/bananatree/OBSERVE -> SIMULATE -> EXECUTE -> ADAPTcycle.py    Phase enum, BananaTreeCycle
taxonomy.py category -> phase mapping
|
v
Layer Loader               core/engine/layer_loader.py
discover canonical -> exec into registry -> log load
|
v
50 Simulation Layers       core/layers/Each layer emits structured JSONL:
{
artifact_id, session_id, layer, phase,
timestamp, behavior_class,
simulation_only: true,       <- safety contract
executable: false,           <- safety contract
no_payload_present: true,    <- safety contract
detection_opportunities: [...]
}
|
v
JSONL Artifact Log         $SHENRON_HOME/logs/
simulation_artifacts.jsonl
scenario_timelines.jsonl
|
+----------------------+
v                      v
Evidence Loader         Safety Verifier
core/reports/           core/reports/model.py
evidence.py             SafetyVerification.evaluate()group by run            flags: simulation_only != true
load timeline           flags: executable == true
flags: network_calls_made == true
|                      |
+----------+-----------+
|
v
Detector Validation        core/validation/expectations.py  load expected signals from scenario
scorer.py        exact / partial / MITRE match
coverage.py      PASS/PARTIAL/MISS, coverage %, verdict
|
v
Report Generator v2        core/reports/markdown.py10 sections:
Executive Summary
bananaTREE Cycle
Scenario Metadata
Layer Execution Summary
MITRE Coverage
Synthetic Telemetry Timeline
Detection Opportunities
Defensive Runbook
Safety Contract Verification
Evidence Appendix
[Detector Validation -- optional]
|
v
reports/<run_id>_<campaign>.md
---

## Component responsibilities

**core/config.py** — All log and report paths. Respects SHENRON_HOME and
SHENRON_REPORT_DIR. No component uses hardcoded paths.

**core/engine/layer_loader.py** — Discovers canonical simulation layers. Filters
mutation variant suffixes. Loads layers via exec() into isolated namespaces.

**core/engine/payload_registry.py** — Holds the registered main() for the currently
loaded layer. Provides run(name) which calls main() and logs execution.

**core/bananatree/cycle.py** — Phase enum, BananaTreeCycle dataclass, SAFETY_CONTRACT
dict. Every campaign produces a cycle with run_id, phase results, MITRE aggregation.

**core/bananatree/taxonomy.py** — Maps 8 layer categories to bananaTREE phases.

**core/scenarios/runner.py** — Loads scenario JSON, validates layer names, executes
phases in order, writes timeline records, returns BananaTreeCycle.

**core/layers/ (50 files)** — Each layer has a @register_payload-decorated main().
Generates synthetic JSONL, writes to simulation_artifacts.jsonl. Every artifact
carries the safety contract. No layer performs real I/O beyond writing to the log.

**core/reports/evidence.py** — Reads both log files. Groups artifacts by layer.
Reconstructs campaign runs from timeline records.

**core/reports/model.py** — ShenronReport, Finding, DetectionOpportunity, EvidenceRef,
SafetyVerification, MITRECoverage dataclasses. SafetyVerification.evaluate() scans
every artifact and flags contract violations.

**core/reports/markdown.py** — Renders ShenronReport into 10-section markdown.

**core/validation/expectations.py** — Loads expected detection signals from scenario
expected_findings and manifest expected_events. Normalizes and deduplicates.

**core/validation/scorer.py** — Exact match -> partial token overlap (>=50%) ->
MITRE technique match. Produces DetectionResult per expectation.

**core/validation/coverage.py** — DetectionCoverageReport with compute(). Calculates
coverage percentage, assigns verdict.

---

## The safety boundary as architecture

The safety boundary is structural, not conventional.

No real I/O path exists for the behaviors being simulated. A layer that represents
C2 beaconing contains data structures describing what C2 beaconing looks like to a
network monitor. Not socket calls. A layer that represents persistence installation
describes what cron modification looks like as a log event sequence. It does not
write to cron.

The artifact format enforces the boundary. Every artifact must carry
simulation_only: true and executable: false. Absence of simulation_only is treated
as a violation. Any violation produces VERDICT: UNSAFE.

The layer loader enforces isolation. Layers are exec'd into isolated namespaces.
They cannot import from each other. They have no access to the runner's context.

The test suite enforces correctness. 117 tests verify that safety violations are
caught, unknown layers are rejected, phase mappings are correct, report sections
are present, and path configuration respects environment variables.

---

## Data flow in one line

Scenario JSON -> runner -> bananaTREE phases -> 50 layers -> JSONL artifacts ->
evidence loader + safety verifier -> expectation scorer -> coverage report ->
10-section markdown report.

All local. No network. No subprocess. No real system modification.
