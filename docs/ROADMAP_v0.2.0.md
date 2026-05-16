# SHENRON Roadmap — v0.2.0

**Status:** Planning
**Baseline:** v0.1.0 (2dffe06)

---

## Design constraints (unchanged from v0.1.0)

v0.2.0 will not add real network calls, subprocess execution, socket bindings,
executable payloads, shellcode, exploit material, malware emulation, or operational
offensive features. The safety boundary does not move between versions.

---

## Planned features

### 1. Higher-fidelity telemetry modeling

Current: All 50 layers emit minimal JSONL (3-12 events). Timing is not modeled.

v0.2.0:
- Realistic event volume per layer (10-100 events per run)
- Configurable timing model: inter-event intervals with jitter profiles
- Correlation fields: related events share session_id and cause_id chains
- Phase transitions produce observable artifact sequences rather than single events
- Fidelity selector: low / medium / high per layer or per campaign

### 2. Validation history and run comparison

Current: `--validate` reads the live JSONL log. No result persistence.

v0.2.0:
- `core/validation/history.py` — persist results per run_id to `~/.shenron/validation_history.jsonl`
- `shenron.py --compare <run_id_1> <run_id_2>` — diff two validation reports
- Coverage delta: which detections moved MISS -> PARTIAL -> PASS between runs
- Coverage trend across repeated runs of the same scenario

### 3. Custom scenario CLI support

Current: Custom scenarios require a Python import. No CLI path argument.

v0.2.0:
- `shenron.py --scenario-file scenarios/my_scenario.json`
- `shenron.py --scenario-file ... --dry-run`
- `shenron.py --scenario-file ... --validate`
- Clear validation errors for malformed scenario files

### 4. Expanded scenario library

Current: 4 bananaTREE example scenarios + 5 built-in scenarios.

v0.2.0:
- 8-12 additional scenarios: credential harvesting telemetry, living-off-the-land
  patterns, supply chain artifact sequences, cloud API enumeration shapes,
  container escape telemetry
- Scenario tagging: `--scenarios --tag lateral-movement`
- Community scenario contribution format with schema validation

### 5. Terminal dashboard improvements

Current: `--stats` produces a static text summary.

v0.2.0:
- Live campaign progress during multi-layer runs
- Per-phase artifact count running total
- Safety contract status indicator during execution
- `--quiet` mode for CI/CD pipeline integration

### 6. Report output formats

Current: Markdown only.

v0.2.0:
- `--format json` — structured JSON for SIEM ingestion
- `--format html` — standalone HTML with inline CSS
- ATT&CK Navigator layer export: `shenron.py --navigator-export <run_id>`

---

## Not planned for v0.2.0

Real network activity, process execution, kernel-level integration, distributed
campaigns, GUI interface. The safety boundary does not move.
