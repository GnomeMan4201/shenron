# SHENRON

**Observable adversarial behavior, not portable adversarial procedure.**

A Python-based defensive adversarial telemetry simulation platform. SHENRON generates structured synthetic telemetry across 50 technique categories, organized through a four-phase campaign model called bananaTREE: OBSERVE, SIMULATE, EXECUTE, ADAPT.

Every artifact carries an explicit safety contract. No real network calls, no subprocess spawning, no executable payloads, no file writes outside the log directory.

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
python3 shenron.py --report-v2 latest --include-validation
```

---

## Reproducible demo

Clone the repo and run one command to produce the full safe demo artifact set:

```bash
python3 shenron.py --demo --charts --out-dir artifacts/demo
```

Output:

```
artifacts/demo/shenron_demo_run.jsonl       — 40 synthetic events, 4 phases
artifacts/demo/shenron_demo_report.md       — markdown report with MITRE descriptor table
artifacts/demo/safety_verification.md       — safety contract verification, all 8 fields
docs/assets/shenron-demo/phase_frequency.png
docs/assets/shenron-demo/technique_frequency.png
docs/assets/shenron-demo/signal_frequency.png
docs/assets/shenron-demo/event_timeline.png
docs/assets/shenron-demo/safety_boundary.png
```

Every record in the JSONL carries:

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

Output:

```
  [SOURCE]      artifacts/demo/shenron_demo_run.jsonl
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

bananaTREE organizes SHENRON campaigns into four phases:

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

Built-in scenarios:

- `basic_c2_persistence` — C2 establishment, lateral movement, dual persistence
- `recon_to_exfil` — Network recon, C2 check-in, data staging
- `persistence_runbook` — All six persistence mechanisms in sequence
- `evasion_stress_test` — Anti-forensics, log manipulation, masquerading
- `apt_kill_chain` — Full APT kill chain: C2, recon, lateral, persistence, evasion, exfil

---

## Detector validation

```bash
python3 shenron.py --validate latest
```

Output:

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
python3 shenron.py --compare <run_id_a> <run_id_b>
```

Example — `apt_kill_chain` vs `persistence_runbook`:

```
  [COMPARE]
  RUN A         1972a90e  apt_kill_chain        100.0%  PASS
  RUN B         32491bae  persistence_runbook   100.0%  PASS
  DELTA         ▲ +0.0%

  [LOST -13]
    ✗  dns_subdomain_query
    ✗  periodic_outbound_connection
    ✗  subnet_sweep
    ✗  smb_port_probe
    ✗  timestamp_rollback
    ... 8 more

  [MITRE LOST]  T1021, T1036, T1046, T1070, T1071, T1132, T1135
```

A detection stack validated only against `persistence_runbook` has no coverage signal for C2 beaconing, lateral movement, DNS tunneling, or anti-forensics. The compare output makes that gap explicit before an incident does.

Export a coverage gap as an ATT&CK Navigator layer:

```bash
python3 shenron.py --compare <run_a> <run_b> --navigator-out reports/gap_layer.json
```

Import at https://mitre-attack.github.io/attack-navigator/ → Open Existing Layer → Upload File.

---

## ATT&CK Navigator export

Export any run as a Navigator layer:

```bash
python3 shenron.py --navigator latest
python3 shenron.py --navigator <run_id> --navigator-out reports/my_layer.json
```

Navigator layers carry synthetic coverage metadata. They are MITRE-style descriptor coverage from synthetic telemetry — not real ATT&CK validation or confirmed detector coverage.

---

## Report generation

```bash
python3 shenron.py --report-v2 latest --include-validation
```

Reports are written to `reports/` as markdown. Each report includes executive summary, bananaTREE phase breakdown, layer execution table, MITRE descriptor table, safety contract verification, and detection opportunity list.

---

## Full workflow

```bash
# 1. Reproducible safe demo
python3 shenron.py --demo --charts --out-dir artifacts/demo

# 2. Verify safety contract
python3 shenron.py --verify-safety artifacts/demo/shenron_demo_run.jsonl

# 3. Run scenarios
python3 shenron.py --scenario apt_kill_chain --dry-run
python3 shenron.py --scenario persistence_runbook --dry-run

# 4. Compare coverage profiles
python3 shenron.py --compare <apt_run_id> <persistence_run_id> \
  --navigator-out reports/gap_layer.json

# 5. Export Navigator layer
python3 shenron.py --navigator latest

# 6. Generate report
python3 shenron.py --report-v2 latest --include-validation
```

---

## CLI reference

```
--demo                    Run safe 40-event demo pipeline
--charts                  Generate charts from demo JSONL (use with --demo)
--out-dir DIR             Output directory for --demo (default: artifacts/demo)
--verify-safety [PATH]    Verify safety contract on JSONL file or 'latest'
--run TARGET              Run a layer, category, or 'all'
--dry-run                 Validate without executing
--scenario NAME           Run a built-in or custom scenario
--scenarios               List available scenarios
--validate [RUN_ID]       Run detector validation
--compare RUN_A RUN_B     Diff two validation runs by run ID prefix
--navigator [RUN_ID]      Export ATT&CK Navigator layer
--navigator-out PATH      Output path for Navigator JSON
--report-v2 [RUN_ID]      Generate markdown report
--include-validation      Include validation results in report
--stats                   Show operational dashboard
--list                    List all canonical layers
```

---

## What SHENRON does not do

- Test network-layer controls — no real network calls are made
- Validate EDR behavioral detection — no real process execution occurs
- Substitute for adversarial emulation where real execution is required
- Prove that detection rules fire on production telemetry
- Measure detection of kernel-level artifacts

SHENRON tests the telemetry pipeline layer: logging, SIEM ingestion, correlation rules, analyst workflows. It is complementary to adversarial emulation, not a substitute.

---

## Tests

```bash
python3 -m pytest tests/ -q
```

154 tests. 35 specifically cover validation and safety systems.

---

## Project structure

```
shenron.py                  — CLI entrypoint
core/
  engine/
    scenario_engine.py      — bananaTREE campaign runner
    layer_loader.py         — canonical layer discovery
    payload_registry.py     — layer execution registry
  reports/
    evidence.py             — artifact loader, run parser
    model.py                — report dataclasses
    markdown.py             — markdown renderer
  validation/
    coverage.py             — detection coverage dataclasses
    scorer.py               — validation scorer
    expectations.py         — expected detection loader
  compare.py                — run comparison engine
  navigator.py              — ATT&CK Navigator exporter
  safety/
    contract.py             — shared safety contract, single source of truth
scripts/
  generate_demo_artifacts.py  — safe 40-event JSONL generator
  generate_charts.py          — publication chart generator
scenarios/                  — custom scenario JSON files
artifacts/                  — generated JSONL and reports
docs/assets/shenron-demo/   — chart PNGs
```

---

## Tag

`v0.1.0` — 50 layers · 154 tests · zero hardcoded paths · PASS verdict

*gnomeman4201 / badBANANA Research Collective*

> Observable adversarial behavior, not portable adversarial procedure.
