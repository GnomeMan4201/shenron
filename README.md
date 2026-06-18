# SHENRON

![SHENRON](assets/shenron_banner.png)

SHENRON is a safe synthetic telemetry and blue-team reasoning tool.

It does not prove that a detection stack is effective.

It helps answer a narrower and more honest question:
> Does this artifact support the validation claim being made about it?

---

## Core principle

**Observable adversarial behavior, not portable adversarial procedure.**

SHENRON generates structured synthetic JSONL telemetry representing adversarial behavior across 52 simulation layers. It does not contain payloads, exploit code, real network calls, subprocess execution, or operational malware logic. Every artifact is synthetic. Every layer carries an explicit safety contract.

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

## System health check

```bash
python3 shenron.py health
```

Runs all four validation dimensions in ~7 seconds:

```
  [✓] tests                PASS    390 passed
  [✓] doctor               PASS    52 layers OK, 0 gaps
  [✓] mitre-drift          PASS    110/110 current, v3.3.0
  [✓] assumptions          PASS    7/7 categories SUPPORTED
  [✓] VERDICT: HEALTHY — all 4 checks passed
```

---

## Full CLI

```bash
git clone https://github.com/GnomeMan4201/shenron
cd shenron
python3 -m pytest tests/ -q                         # 390 tests

# Run a category
python3 shenron.py --run persistence
python3 shenron.py --run c2
python3 shenron.py --run all --dry-run              # 52 ok | 0 failed

# Scoped run — output to separate file for clean assumption validation
python3 shenron.py --run persistence \
  --scope-out /tmp/persistence_scoped.jsonl

# Validate all category assumptions in one command
python3 shenron.py --validate-all-assumptions

# Validate a single assumption against scoped artifact
python3 shenron.py --validate-assumption \
  assumptions/examples/persistence_coverage.yaml \
  --events /tmp/persistence_scoped.jsonl

# Validate Sigma rules against synthetic telemetry
python3 shenron.py --validate-sigma-dir sigma/rules/ \
  --events ~/SHENRON/logs/simulation_artifacts.jsonl

# MITRE ATT&CK drift check (detects stale/renamed technique IDs)
python3 shenron.py --check-mitre-drift \
  --drift-cache .cache/attack_bundle.json

# Field emission coverage audit
python3 shenron.py doctor

# Generate standalone HTML report
python3 shenron.py --report-html

# View validation history
python3 shenron.py --history
python3 shenron.py --history-compare persistence_coverage
```

---

## What it does

**Synthetic telemetry generation** — 52 simulation layers across 8 categories (c2, entropy, identity, evasion, payload, llm, persistence, meta), organized through the bananaTREE four-phase campaign model: OBSERVE → SIMULATE → EXECUTE → ADAPT.

**Sigma rule validation** — evaluates whether your detection rules would fire on realistic synthetic telemetry. Verdicts: TRIGGERED, PARTIAL, NOT_TRIGGERED, UNSUPPORTED. 19 rules across simulation and live categories.

**Assumption validation** — checks whether a JSONL artifact supports, partially supports, or violates the claims being made about it. Includes out-of-scope violation detection. All 7 categories validated and SUPPORTED.

**MITRE ATT&CK drift detection** — `--check-mitre-drift` fetches the current ATT&CK STIX bundle and compares all 110 pinned technique IDs against the live release. Exits non-zero on stale or renamed techniques. Runs in CI on every push.

**Evidence discipline** — generates scope-bounded reports that tell you exactly what your artifact can and cannot honestly support. Prevents overclaiming.

**Scoped artifact validation** — `--scope-out` runs a category and writes output to a dedicated file, enabling clean per-category assumption validation without full-log contamination.

**HTML report output** — standalone HTML report with MITRE coverage, sigma results, assumption validation, and safe conclusion.

**Validation history** — persists results per run for delta tracking and comparison over time.

---

## Live telemetry integration

SHENRON accepts live telemetry from [bpf-watch](https://github.com/GnomeMan4201/bpf-watch), an eBPF rootkit detection daemon that emits Shenron-compatible JSONL.

```bash
# Run bpf-watch and feed live output into Shenron validation
sudo python3 bpfwatch.py --check \
  --out ~/SHENRON/logs/bpfwatch_live.jsonl

python3 shenron.py --validate-sigma-dir sigma/rules/ \
  --events ~/SHENRON/logs/bpfwatch_live.jsonl

python3 shenron.py --validate-assumption \
  assumptions/examples/assumption_bpfwatch_live_coverage.yaml \
  --events ~/SHENRON/logs/bpfwatch_live.jsonl
```

5 live Sigma rules in `sigma/rules/live/` fire against real kernel telemetry. The kprobe sentinel rule has been confirmed TRIGGERED against real kernel execve hooks on kernel 6.18.7.

---

## Repository structure

```
core/
  assumptions/     — evidence discipline layer (validate, scope, index)
  sigma/           — Sigma rule evaluation engine
  validation/      — detector validation scoring and history
  reports/         — markdown and HTML report generation
  bananatree/      — campaign model (phases, taxonomy, cycle)
  layers/          — 52 canonical simulation layers
  engine/          — layer loader and payload registry
  mitre/           — ATT&CK STIX drift checker
  cli/commands/    — subcommand handlers (health, doctor, validate_all, ...)
  config.py        — centralized path configuration
assumptions/examples/  — 15 assumption YAML files (7 categories + live)
sigma/rules/           — 19 Sigma rules (simulation + live bpf-watch)
sigma/rules/live/      — 5 live rules for bpf-watch telemetry
artifacts/demo/        — committed demo artifact for immediate use
scenarios/examples/    — bananaTREE scenario JSON files
tests/                 — 390 tests
```

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
|---|---|
| Test suite | 390 passed (Python 3.9–3.12) |
| Layer dry-run | 52 ok, 0 failed |
| Field emission coverage | 52 layers OK, 0 gaps |
| Safety failures | 0 |
| Sigma rules | 19 (14 simulation, 5 live) |
| Assumption YAMLs | 15 |
| Simulation layers | 52 |
| MITRE techniques | 110/110 current |
| Category assumptions | 7/7 SUPPORTED |
| CI jobs | 8/8 green |

---

## CI

8-job pipeline runs on every push and PR to main:

- **Test** (Python 3.9, 3.10, 3.11, 3.12) — full pytest suite
- **Safety audit** — dry-run all layers, schema validation, audit bundle
- **Package build** — wheel build and install verification
- **MITRE ATT&CK drift** — live STIX bundle check, exits non-zero on stale techniques
- **Assumption coverage** — `--validate-all-assumptions` across all 7 categories

---

## Launch Article

[Observable Adversarial Behavior, Not Portable Adversarial Procedure](https://dev.to/gnomeman4201/observable-adversarial-behavior-not-portable-adversarial-procedure-4mo6)

---

*gnomeman4201 / badBANANA Research Collective*
> Observable adversarial behavior, not portable adversarial procedure.


---

## Part of the BANANA_TREE Research Ecosystem

| | |
|--|--|
| **Research Hub** | [GnomeMan4201](https://github.com/GnomeMan4201/GnomeMan4201) |
| **Corpus & Discovery** | [r4b1t](https://gnomeman4201.github.io/r4b1t) — 53,869 verified OSINT/security URLs |
| **Investigation Management** | [inv-hub](https://github.com/GnomeMan4201/inv-hub) |
| **Knowledge Base** | [PRAXIS](https://github.com/GnomeMan4201/PRAXIS) |
| **Detection Engineering** | [SHENRON](https://github.com/GnomeMan4201/SHENRON) |
| **Kernel Telemetry** | [bpf-watch](https://github.com/GnomeMan4201/bpf-watch) |

*badBANANA Research Collective · [dev.to/gnomeman4201](https://dev.to/gnomeman4201)*
