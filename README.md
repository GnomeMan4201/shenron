![SHENRON](assets/shenron_banner.png)

# SHENRON

SHENRON is a safe synthetic telemetry and blue-team reasoning tool.

It does not prove that a detection stack is effective.

It helps answer a narrower and more honest question:

> Does this artifact support the validation claim being made about it?

---

## Core principle

**Observable adversarial behavior, not portable adversarial procedure.**

SHENRON generates structured synthetic JSONL telemetry representing adversarial behavior across 50 simulation layers. It does not contain payloads, exploit code, or operational malware logic. Every artifact is synthetic. Every layer carries an explicit safety contract. Generated telemetry never represents or performs real subprocess execution. CLI utility commands may invoke local SHENRON helper scripts, but no adversarial subprocess behavior is executed or simulated as live activity.

---

## Safety boundary

SHENRON does not contain:

- Executable payloads or shellcode
- Real network connections or socket bindings
- Subprocess spawning or shell command execution
- Real file writes outside its own log directory
- Exploit code of any kind

This is not a disclaimer. It is an architectural constraint.

---

## Quickstart — one command, complete evidence bundle

```bash
git clone https://github.com/GnomeMan4201/shenron
cd shenron
python3 shenron.py --quickstart
```

Produces in `reports/demo/`:
- `sigma_validation.txt` — which detection rules fire on synthetic telemetry
- `assumption_validation.txt` — which claims the artifact supports
- `attack_navigator_layer.json` — import into ATT&CK Navigator
- `shenron_report.html` — open in any browser

No setup. No external dependencies. No prior knowledge required.

---

## Full CLI

```bash
git clone https://github.com/GnomeMan4201/shenron
cd shenron
python3 -m pytest tests/ -q                         # 319 tests

# Run a campaign
python3 shenron.py --run persistence
python3 shenron.py --run c2
python3 shenron.py --run all --dry-run              # 50 ok | 0 failed

# Validate Sigma rules against synthetic telemetry
python3 shenron.py --validate-sigma-dir sigma/rules/ \
  --events ~/SHENRON/logs/simulation_artifacts.jsonl

# Validate assumption claims against artifact
python3 shenron.py --validate-assumption \
  assumptions/examples/persistence_coverage.yaml \
  --events ~/SHENRON/logs/simulation_artifacts.jsonl

# Compare multiple assumptions — same artifact, different claims
python3 shenron.py --compare-assumptions \
  assumptions/examples/persistence_coverage.yaml \
  assumptions/examples/c2_coverage.yaml \
  --events ~/SHENRON/logs/simulation_artifacts.jsonl

# Generate standalone HTML report
python3 shenron.py --report-html

# View validation history
python3 shenron.py --history
python3 shenron.py --history-compare persistence_coverage
```

---

## What it does

**Synthetic telemetry generation** — 50 simulation layers across 8 categories (c2, entropy, identity, evasion, payload, llm, persistence, meta), organized through the bananaTREE four-phase campaign model: OBSERVE → SIMULATE → EXECUTE → ADAPT.

**Sigma rule validation** — evaluates whether your detection rules would fire on realistic synthetic telemetry. Verdicts: TRIGGERED, PARTIAL, NOT_TRIGGERED, UNSUPPORTED.

**Assumption validation** — checks whether a JSONL artifact supports, partially supports, or violates the claims being made about it. Includes out-of-scope violation detection.

**Evidence discipline** — generates scope-bounded reports that tell you exactly what your artifact can and cannot honestly support. Prevents overclaiming.

**HTML report output** — standalone HTML report with MITRE coverage, sigma results, assumption validation, and safe conclusion. No external dependencies.

**Validation history** — persists results per run for delta tracking and comparison over time.

---

## Repository structure
core/
assumptions/    — evidence discipline layer (validate, scope, index)
sigma/          — Sigma rule evaluation engine
validation/     — detector validation scoring and history
reports/        — markdown and HTML report generation
bananatree/     — campaign model (phases, taxonomy, cycle)
layers/         — 50 canonical simulation layers
engine/         — layer loader and payload registry
config.py       — centralized path configuration
assumptions/examples/   — 12 assumption YAML files
sigma/rules/            — Sigma rules (persistence, c2, evasion, entropy)
artifacts/demo/         — committed demo artifact for immediate use
scenarios/examples/     — bananaTREE scenario JSON files
tests/                  — 319 tests

---

## Demo — no setup required

```bash
# Immediate demo from fresh clone
python3 shenron.py --compare-assumptions \
  assumptions/examples/persistence_coverage.yaml \
  assumptions/examples/c2_coverage.yaml \
  --events artifacts/demo/shenron_demo_run.jsonl

python3 shenron.py --validate-sigma-dir sigma/rules/ \
  --events artifacts/demo/shenron_demo_run.jsonl
```

---

## Verified state

| Check | Result |
|-------|--------|
| Test suite | 319 passed |
| Layer dry-run | 50 ok, 0 failed |
| Hardcoded paths | 0 |
| Safety failures | 0 |
| Sigma rules | 7 |
| Assumption YAMLs | 12 |
| Simulation layers | 50 |

---

## Launch Article

[Observable Adversarial Behavior, Not Portable Adversarial Procedure](https://dev.to/gnomeman4201/observable-adversarial-behavior-not-portable-adversarial-procedure-4mo6)

---

*gnomeman4201 / badBANANA Research Collective*

> Observable adversarial behavior, not portable adversarial procedure.
