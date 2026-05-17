# SHENRON

SHENRON is a safe synthetic telemetry and blue-team reasoning tool.

It does not prove that a detection stack is effective.

It helps answer a narrower and more honest question:

> Does this artifact support the validation claim being made about it?

---

## Quick start

```bash
git clone https://github.com/GnomeMan4201/shenron
cd shenron
python3 shenron.py --run persistence
python3 shenron.py --validate-assumption assumptions/examples/persistence_coverage.yaml \
  --events ~/SHENRON/logs/simulation_artifacts.jsonl
python3 shenron.py --compare-assumptions \
  assumptions/examples/persistence_coverage.yaml \
  assumptions/examples/c2_coverage.yaml \
  --events ~/SHENRON/logs/simulation_artifacts.jsonl
```

---

---

## Safety boundary

SHENRON does not contain:

- Executable payloads or shellcode
- Real network connections or socket bindings
- Subprocess spawning or shell command execution
- Real file writes outside its own log directory
- Exploit code of any kind

This is an architectural constraint, not a disclaimer. The safety verifier scans every artifact and flags violations. A single violation produces `VERDICT: UNSAFE` regardless of coverage score.

---

## Quick start

```bash
git clone https://github.com/GnomeMan4201/shenron
cd shenron
python3 -m pytest tests/ -q
python3 shenron.py --run all --dry-run
python3 shenron.py --validate latest
```

---

## Reproducible demo

One command produces the complete artifact bundle:

```bash
python3 shenron.py --release-demo
```

Output — `release/shenron-v0.3.3-demo/`:

```
shenron_demo_run.jsonl          40 synthetic telemetry events
shenron_demo_report.md          human-readable run report
safety_verification.md          safety contract field-by-field verification
navigator_layer.json            ATT&CK Navigator import layer (synthetic)
shenron_demo_run_ecs.json       ECS-formatted events
shenron_demo_run_ecs_bulk.ndjson  Elastic bulk API format
shenron_demo_run_splunk_hec.json  Splunk HEC format
narrative.md                    tactic profile narrative
charts/                         5 dark-mode PNGs
MANIFEST.md                     bundle index with import commands
```

Every record carries:

```json
"safety": {
  "simulation_only": true,
  "executable": false,
  "payload_present": false,
  "portable_adversarial_procedure": false,
  "network_connection": false,
  "subprocess_spawned": false,
  "real_file_written": false,
  "shell_invoked": false
}
```

---

## Safety verification

Inspect the safety contract on any JSONL artifact:

```bash
python3 shenron.py --verify-safety artifacts/demo/shenron_demo_run.jsonl
```

```
  [RECORDS]     40
  executable                           PASS
  network_connection                   PASS
  payload_present                      PASS
  portable_adversarial_procedure       PASS
  real_file_written                    PASS
  shell_invoked                        PASS
  simulation_only                      PASS
  subprocess_spawned                   PASS
  [VERDICT]     PASS
```

---

## bananaTREE campaign model

| Phase | Intent |
|-------|--------|
| **OBSERVE** | Map adversarial signal surface — C2, entropy, identity patterns |
| **SIMULATE** | Generate synthetic telemetry for detector training |
| **EXECUTE** | Run simulation layers, produce JSONL artifact timelines |
| **ADAPT** | Score detection coverage, identify gaps |

Run a built-in scenario:

```bash
python3 shenron.py --scenarios
python3 shenron.py --scenario apt_kill_chain --dry-run
python3 shenron.py --scenario persistence_runbook --dry-run
```

Built-in scenarios: `basic_c2_persistence`, `recon_to_exfil`, `persistence_runbook`, `evasion_stress_test`, `apt_kill_chain`.

---

## Detector validation

```bash
python3 shenron.py --validate latest
```

```
  [VALIDATION]  c2_shape_detection_test
  [EXPECTED]    31
  [OBSERVED]    31
  [COVERAGE]    100.0%
  [SAFETY FAIL] 0
  [VERDICT]     PASS
```

PASS requires ≥80% coverage AND zero safety violations.

---

## Run comparison

Compare two runs to track detection coverage changes over time:

```bash
python3 shenron.py --compare <run_a> <run_b>
python3 shenron.py --compare <run_a> <run_b> --narrate
python3 shenron.py --compare <run_a> <run_b> --navigator-out reports/gap_layer.json
```

The `--narrate` flag generates an analyst-language defensive narrative that names the specific tactic families missing between runs, provides analyst concern language for each gap, and recommends which scenarios to run next.

Example output — `apt_kill_chain` vs `persistence_runbook`:

```
  [NARRATIVE]   apt_kill_chain → persistence_runbook

  Coverage gap families (4):
    ✗  Command-and-Control
    ✗  Defense Evasion
    ✗  Lateral Movement
    ✗  Discovery

  Primary concern:
    If C2-shaped telemetry is not in your validation set, your detectors
    have not been tested against the phase where most APT campaigns are
    first visible — initial callback after compromise.
```

---

## Coverage assumption auditing

Define what you believe your detection stack covers, then audit it against synthetic telemetry:

```bash
# Create an assumption file
cat > assumptions/my_assumption.yaml << 'EOF'
name: persistence_coverage_assumption
description: We can detect persistence-shaped adversarial telemetry
claims:
  - "We can observe persistence-shaped telemetry"
  - "We can detect suspicious scheduled task behavior"
expected_techniques:
  - T1053.005
  - T1543.003
  - T1547.001
expected_signals:
  - scheduled_task_creation
  - service_install_signal
expected_phases:
  - EXECUTE
EOF

# Audit it
python3 shenron.py --assumption assumptions/my_assumption.yaml \
  --events artifacts/demo/shenron_demo_run.jsonl
```

SHENRON scores each claim against artifact evidence, identifies missing technique descriptors, and produces a markdown report with a "what this proves / what this does not prove" section.

Example output:

```
  [ASSUMPTION]  persistence_coverage_assumption
  [RECORDS]     40

  Claims        0 supported  0 partial  2 unsupported
  Techniques    3 observed   3 missing
  Signals       2 observed   3 missing

  [COVERAGE]    38.9%
  [VERDICT]     FAIL
```

See `assumptions/examples/` for complete example files.

---

## Coverage history

Track technique coverage drift across all your runs:

```bash
python3 shenron.py --coverage-history --out-dir reports/history
python3 shenron.py --coverage-history --history-campaign c2_shape_detection_test
```

Output:
- `coverage_history.md` — trend table per campaign, drift events, technique sets
- `coverage_history.json` — machine-readable snapshot index
- `coverage_history_trend.png` — technique count chart over time

With 256 runs across 8 campaigns, SHENRON can show you whether your detection signal vocabulary has expanded, contracted, or stayed consistent across repeated validation runs.

---

## Format export

Export synthetic events into formats your SIEM can ingest:

```bash
# Elastic Common Schema
python3 shenron.py --export-format ecs \
  --events artifacts/demo/shenron_demo_run.jsonl \
  --out-dir artifacts/demo

# Splunk HEC
python3 shenron.py --export-format splunk \
  --events artifacts/demo/shenron_demo_run.jsonl \
  --out-dir artifacts/demo
```

Elastic import:

```bash
curl -X POST 'http://localhost:9200/_bulk' \
     -H 'Content-Type: application/x-ndjson' \
     --data-binary @artifacts/demo/shenron_demo_run_ecs_bulk.ndjson
```

All ECS events carry `event.dataset: shenron.synthetic`, `labels.simulation_only: true`, and the full safety contract in `labels.*` fields. Every event includes `[SHENRON SYNTHETIC]` in the `message` field. These are not real events.

---

## Mutation variants

Test whether your analysis pipeline is brittle to incomplete, noisy, or mislabeled telemetry:

```bash
python3 shenron.py --mutate \
  --events artifacts/demo/shenron_demo_run.jsonl \
  --out-dir artifacts/mutations

# Run specific mutation types
python3 shenron.py --mutate \
  --mutation-types field_drop,timing_jitter,label_ambiguity \
  --events artifacts/demo/shenron_demo_run.jsonl
```

Available mutation types:

| Type | What it does | Tests |
|------|-------------|-------|
| `field_drop` | Remove non-critical fields | Optional field dependencies |
| `timing_jitter` | Add random timestamp offset | Timing-sensitive correlation rules |
| `label_ambiguity` | Replace specific signals with generic names | Signal specificity requirements |
| `signal_density_high` | 3× record duplication | High-volume burst handling |
| `signal_density_low` | Drop 50% of records | Sparse telemetry detection |
| `phase_imbalance` | Relabel all records to one phase | Phase-aware analysis brittleness |
| `technique_noise` | Add unrelated technique IDs | MITRE-based correlation robustness |

All safe mutation types preserve `simulation_only: true`. The `missing_safety_fields` type (opt-in only) intentionally violates the safety contract — use it only with `--verify-safety` to test contract validation.

After mutation:

```bash
python3 shenron.py --verify-safety artifacts/mutations/mutation_field_drop.jsonl
```

---

## ATT&CK Navigator export

```bash
python3 shenron.py --navigator latest
python3 shenron.py --navigator <run_id> --navigator-out reports/my_layer.json

# Gap layer from compare
python3 shenron.py --compare <run_a> <run_b> --navigator-out reports/gap_layer.json
```

Import at https://mitre-attack.github.io/attack-navigator/ → Open Existing Layer → Upload File.

Navigator layers carry synthetic coverage metadata. They represent MITRE-style descriptor coverage from synthetic telemetry — not real ATT&CK validation.

---

## Full workflow

```bash
# 1. Run the safe demo pipeline
python3 shenron.py --demo --charts --out-dir artifacts/demo

# 2. Verify safety contract
python3 shenron.py --verify-safety artifacts/demo/shenron_demo_run.jsonl

# 3. Export to SIEM formats
python3 shenron.py --export-format ecs --events artifacts/demo/shenron_demo_run.jsonl

# 4. Run scenarios
python3 shenron.py --scenario apt_kill_chain --dry-run
python3 shenron.py --scenario persistence_runbook --dry-run

# 5. Compare and narrate
python3 shenron.py --compare <apt_id> <persistence_id> --narrate \
  --navigator-out reports/gap_layer.json

# 6. Audit a coverage assumption
python3 shenron.py --assumption assumptions/examples/persistence_coverage.yaml \
  --events artifacts/demo/shenron_demo_run.jsonl

# 7. Track coverage history
python3 shenron.py --coverage-history --out-dir reports/history

# 8. Generate mutation variants
python3 shenron.py --mutate --events artifacts/demo/shenron_demo_run.jsonl

# 9. Build the full release bundle
python3 shenron.py --release-demo
```

---

## CLI reference

**Demo and safety**

```
--demo                    Run safe 40-event demo pipeline
--charts                  Generate charts from demo JSONL (use with --demo)
--verify-safety [PATH]    Verify safety contract on JSONL or 'latest'
--out-dir DIR             Output directory (default: artifacts/demo)
--release-demo            Build complete 9-file release artifact bundle
```

**Scenarios and validation**

```
--scenario NAME           Run a built-in or custom scenario
--scenarios               List available scenarios
--run TARGET              Run a layer, category, or 'all'
--dry-run                 Validate without executing
--validate [RUN_ID]       Run detector validation
--report-v2 [RUN_ID]      Generate markdown report
--include-validation      Include validation results in report
```

**Comparison and analysis**

```
--compare RUN_A RUN_B     Diff two validation runs by run ID prefix
--narrate                 Generate analyst narrative from --compare
--navigator [RUN_ID]      Export ATT&CK Navigator layer
--navigator-out PATH      Output path for Navigator JSON
--assumption YAML_PATH    Audit a coverage assumption file
--events JSONL_PATH       JSONL events file for --assumption or --export-format
```

**History and mutation**

```
--coverage-history        Build coverage trend report from all timeline runs
--history-campaign NAME   Filter --coverage-history to a specific campaign
--mutate                  Generate safe telemetry mutation variants
--mutation-types TYPES    Comma-separated mutation types (default: all safe)
```

**Format export**

```
--export-format FORMAT    Export events as ECS or Splunk HEC (ecs|splunk)
```

---

## What SHENRON does not do

- Test network-layer controls — no real network calls are made
- Validate EDR behavioral detection — no real process execution occurs
- Substitute for adversarial emulation where real execution is required
- Prove that detection rules fire on production telemetry
- Measure detection of kernel-level artifacts
- Replace a red team

SHENRON tests the telemetry pipeline layer: logging, SIEM ingestion, correlation rules, analyst workflows, and detection assumptions. It is complementary to adversarial emulation, not a substitute.

---

## Tests

```bash
python3 -m pytest tests/ -q
```

283 tests. Covers safety contracts, format adapters, assumption auditing, narration engine, coverage history, mutation engine, and validation scoring.

---

## Project structure

```
shenron.py                    CLI entrypoint
core/
  engine/
    scenario_engine.py        bananaTREE campaign runner
    layer_loader.py           canonical layer discovery
    payload_registry.py       layer execution registry
  reports/
    evidence.py               artifact loader, run parser
    model.py                  report dataclasses
    markdown.py               markdown renderer
  validation/
    coverage.py               detection coverage dataclasses
    scorer.py                 validation scorer
    expectations.py           expected detection loader
  safety/
    contract.py               shared safety contract — single source of truth
  compare.py                  run comparison engine
  navigator.py                ATT&CK Navigator exporter
  narration/
    engine.py                 deterministic analyst-language narrative generator
  assumption/
    parser.py                 YAML assumption loader and validator
    evaluator.py              claim scorer against JSONL artifact records
    reporter.py               markdown + JSON report writer
  formats/
    adapter.py                ECS and Splunk HEC format adapters
  history/
    tracker.py                coverage trend tracking and drift detection
  mutation/
    engine.py                 7 safe telemetry mutation variant generators
scripts/
  generate_demo_artifacts.py  safe 40-event JSONL generator
  generate_charts.py          publication chart generator
  release_demo.py             complete release bundle generator
assumptions/examples/         example assumption YAML files
scenarios/                    custom scenario JSON files
tests/                        283 tests
```

---

## Version

`v0.3.3` — 50 layers · 283 tests · zero hardcoded paths · PASS verdict

*gnomeman4201 / badBANANA Research Collective*

> Observable adversarial behavior, not portable adversarial procedure.
