![SHENRON](assets/shenron_banner.png)

# SHENRON

SHENRON is a safe synthetic telemetry and blue-team reasoning tool.

It does not prove that a detection stack is effective.

It helps answer a narrower and more honest question:

> Does this artifact support the validation claim being made about it?

---

## Core principle

**Observable adversarial behavior, not portable adversarial procedure.**

SHENRON generates structured synthetic JSONL telemetry representing adversarial behavior across 51 simulation layers. It does not contain payloads, exploit code, or operational malware logic. Every artifact is synthetic. Every layer carries an explicit safety contract. Generated telemetry never represents or performs real subprocess execution. CLI utility commands may invoke local SHENRON helper scripts, but no adversarial subprocess behavior is executed or simulated as live activity.

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
python3 -m pytest tests/ -q                         # 350 tests

# Run a campaign
python3 shenron.py run persistence
python3 shenron.py run c2
python3 shenron.py run all --dry-run                # 51 ok | 0 failed

# Validate Sigma rules against synthetic telemetry
python3 shenron.py sigma validate-dir sigma/rules/ \
  --events artifacts/demo/shenron_demo_run.jsonl

# Validate assumption claims against artifact
python3 shenron.py assumption validate \
  assumptions/examples/persistence_coverage.yaml \
  --events artifacts/demo/shenron_demo_run.jsonl

# Diff two assumptions against the same artifact
python3 shenron.py assumption diff \
  assumptions/examples/persistence_coverage.yaml \
  assumptions/examples/broad_detection_claim.yaml \
  --events artifacts/demo/shenron_demo_run.jsonl

# Compare multiple assumptions — same artifact, different claims
python3 shenron.py assumption compare \
  assumptions/examples/persistence_coverage.yaml \
  assumptions/examples/c2_coverage.yaml \
  --events artifacts/demo/shenron_demo_run.jsonl

# Validate events against JSON schema
python3 shenron.py schema validate \
  --events artifacts/demo/shenron_demo_run.jsonl

# Export to Elastic ECS or Splunk HEC
python3 shenron.py export ecs \
  --events artifacts/demo/shenron_demo_run.jsonl --out reports/ecs.json
python3 shenron.py export hec \
  --events artifacts/demo/shenron_demo_run.jsonl --out reports/hec.ndjson

# Generate standalone HTML report
python3 shenron.py report html

# View validation history
python3 shenron.py history show
```

---

## What it does

**Synthetic telemetry generation** — 51 simulation layers across 8 categories (c2, entropy, identity, evasion, payload, llm, persistence, meta), organized through the bananaTREE four-phase campaign model: OBSERVE → SIMULATE → EXECUTE → ADAPT.

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
layers/         — 51 canonical simulation layers
engine/         — layer loader and payload registry
config.py       — centralized path configuration
assumptions/examples/   — 14 assumption YAML files
sigma/rules/            — Sigma rules (persistence, c2, evasion, entropy)
artifacts/demo/         — committed demo artifact for immediate use
scenarios/examples/     — bananaTREE scenario JSON files
tests/                  — 350 tests

---

## Demo — no setup required

```bash
# Immediate demo from fresh clone
python3 shenron.py assumption compare \
  assumptions/examples/persistence_coverage.yaml \
  assumptions/examples/c2_coverage.yaml \
  --events artifacts/demo/shenron_demo_run.jsonl

python3 shenron.py sigma validate-dir sigma/rules/ \
  --events artifacts/demo/shenron_demo_run.jsonl
```

---

## Verified state

| Check | Result |
|-------|--------|
| Test suite | 350 passed |
| Layer dry-run | 51 ok, 0 failed |
| Hardcoded paths | 0 |
| Safety failures | 0 |
| Sigma rules | 7 |
| Assumption YAMLs | 14 |
| Simulation layers | 51 |

---

## Launch Article

[Observable Adversarial Behavior, Not Portable Adversarial Procedure](https://dev.to/gnomeman4201/observable-adversarial-behavior-not-portable-adversarial-procedure-4mo6)

---
