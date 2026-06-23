
![SHENRON](assets/shenron_banner.png)

SHENRON is a safe synthetic telemetry and detection engineering research tool.

It does not prove that a detection stack is effective.

It helps answer a harder question:
> How durable are your detection rules under adversarial pressure?

Rule coverage is table stakes. Rule durability is the harder problem.

---

## Core principle

**Observable adversarial behavior, not portable adversarial procedure.**

SHENRON generates structured synthetic JSONL telemetry representing adversarial behavior across 59 simulation layers. It does not contain payloads, exploit code, real network calls, subprocess execution, or operational malware logic. Every artifact is synthetic. Every layer carries an explicit safety contract.

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

## Quickstart

```bash
git clone https://github.com/GnomeMan4201/shenron
cd shenron
pip install pyyaml pytest --break-system-packages

# See available commands
python3 shenron.py

# Run a campaign and score brittleness across all three dimensions
python3 shenron.py campaign --scenario apt29-style --stress-test

# Compare all six adversary archetypes side by side
python3 shenron.py compare-scenarios

# Compare specific scenarios
python3 shenron.py compare-scenarios --scenarios ransomware-precursor fin7-style
```

**Custom weight profiles** — edit `shenron.config.yml` to reflect your pipeline's normalization. Set `case_flip: 0.0` if your SIEM normalizes case before rules fire. The weighted brittleness score updates automatically.

---

## What it does

SHENRON scores detection brittleness across three dimensions:

**Artifact-level brittleness** — does a mutation on a single event cause a Sigma rule to stop firing? Six mutation strategies targeting fields your rules actually reference: `value_swap`, `field_omit`, `case_flip`, `unicode_substitute`, `whitespace_inject`, `combined_evasion`. Strategies are weighted by adversary accessibility — `case_flip` requires zero sophistication, `value_swap` requires knowledge of the detection stack.

**Campaign-level correlation brittleness** — do mutations on the relationships between events break the ability to correlate them into a coherent intrusion narrative? Four campaign-graph mutations: `SESSION_ID_ROTATION`, `TIMESTAMP_STRETCH`, `STAGE_DROPOUT`, `ACTOR_DRIFT`. Scores four correlation dimensions: session identity, temporal coherence, stage coverage, actor attribution.

**Gap metric** — the difference between artifact brittleness and correlation brittleness. A campaign where every individual event is detected but session IDs can be rotated to break correlation is a qualitatively different security posture than one where both are low. The gap makes that visible.

---

## Adversary archetypes

Six scenarios covering distinct kill chain shapes:

| Scenario | Stages | Shape |
|---|---|---|
| apt29-style | 7 | Full kill chain with recon |
| ransomware-precursor | 5 | Beacon → payload → persistence → lateral → exfil |
| insider-threat | 4 | No initial access, direct collection |
| fin7-style | 6 | Execution-first, credential harvest heavy |
| supply-chain | 4 | Dependency confusion as initial access vector |
| living-off-the-land | 4 | Pure LOtL, native tools throughout |

---

## Sample output

```
  SCENARIO                RAW   WEIGHTED  CORR  TRIGGERED  MOST BRITTLE
  ---------------------- ----- --------- ----- ---------- ------------
  apt29-style             0.50    0.37    0.25  7/7        INITIAL_ACCESS
  ransomware-precursor    0.40    0.29    0.25  5/5        INITIAL_ACCESS
  insider-threat          0.50    0.37    0.25  4/4        INITIAL_ACCESS
  fin7-style              0.42    0.31    0.25  6/6        EXECUTION
  supply-chain            0.46    0.36    0.25  4/4        EXECUTION
  living-off-the-land     0.50    0.37    0.25  4/4        EXECUTION
```

Key findings across 6 scenarios, 27 Sigma rules:
- EXECUTION and EXFIL are universally brittle at the artifact level
- Correlation brittleness is 0.25 across all archetypes — consistent and exploitable
- Gap: -0.15 to -0.25 (correlation more resilient than individual rule detection)
- No stage achieves universal detection with zero evasion

---

## Configuration

`shenron.config.yml` controls weight profiles and correlation thresholds:

```yaml
brittleness:
  weights:
    case_flip: 1.0          # trivial — zero adversary sophistication
    whitespace_inject: 0.8
    combined_evasion: 0.8
    unicode_substitute: 0.6
    field_omit: 0.4         # pipeline-dependent
    value_swap: 0.2         # informed — requires detection stack knowledge
  correlation_time_threshold_hours: 6

campaign:
  default_scenario: apt29-style
  default_length_hours: 72
```

Set any weight to `0.0` to exclude it from the weighted score — use this when your pipeline normalizes that transformation before rules fire.

---

## Full CLI

```bash
# Campaign generation and brittleness scoring
python3 shenron.py campaign --scenario apt29-style --length 72 --stress-test
python3 shenron.py campaign --list-scenarios

# Cross-scenario comparison (three-column: raw / weighted / correlation)
python3 shenron.py compare-scenarios
python3 shenron.py compare-scenarios --scenarios apt29-style fin7-style supply-chain

# System health and coverage
python3 shenron.py health
python3 shenron.py doctor --campaign

# Sigma rule evaluation
python3 shenron.py sigma --validate-dir sigma/rules/

# Legacy layer runner
python3 shenron.py run --target persistence
python3 shenron.py run --target all --dry-run

# Assumption validation
python3 shenron.py assumption --validate assumptions/examples/persistence_coverage.yaml

# MITRE ATT&CK drift check
python3 shenron.py --check-mitre-drift --drift-cache .cache/attack_bundle.json

# Reports and export
python3 shenron.py report
python3 shenron.py audit
python3 shenron.py export
```

---

## Verified state

| Check | Result |
|---|---|
| Test suite | 443 passed (Python 3.12) |
| Simulation layers | 59 |
| Sigma rules | 27 |
| Adversary scenarios | 6 |
| Artifact mutation strategies | 6 |
| Correlation mutation strategies | 4 |
| Correlation dimensions scored | 4 |
| Safety failures | 0 |

---

## Repository structure

```
core/
  campaign/        — CampaignBuilder, ScenarioComparator, CorrelationBrittlenessScorer
  brittleness/     — BrittlenessScorer, ArtifactBrittleness, weighted scoring
  mutation/        — SigmaAwareMutator, combined evasion, deterministic seeding
  sigma/           — Sigma rule evaluation engine with NFKC normalization
  layers/          — 59 canonical simulation layers
  engine/          — layer loader and payload registry
  assumptions/     — evidence discipline layer (validate, scope, index)
  validation/      — detector validation scoring and history
  reports/         — markdown and HTML report generation
  bananatree/      — campaign model (phases, taxonomy, cycle)
  mitre/           — ATT&CK STIX drift checker
  cli/commands/    — subcommand handlers
  config.py        — centralized path configuration
sigma/rules/           — 27 Sigma rules
assumptions/examples/  — assumption YAML files
artifacts/demo/        — committed demo artifact for immediate use
shenron.config.yml     — weight profiles and correlation thresholds
tests/                 — 443 tests
```

---

## Live telemetry integration

SHENRON accepts live telemetry from [bpf-watch](https://github.com/GnomeMan4201/bpf-watch), an eBPF rootkit detection daemon that emits SHENRON-compatible JSONL.

```bash
sudo python3 bpfwatch.py --check \
  --out ~/SHENRON/logs/bpfwatch_live.jsonl

python3 shenron.py sigma --validate-dir sigma/rules/live/ \
  --events ~/SHENRON/logs/bpfwatch_live.jsonl
```

5 live Sigma rules in `sigma/rules/live/` fire against real kernel telemetry. The kprobe sentinel rule has been confirmed TRIGGERED against real kernel execve hooks on kernel 6.18.7.

---

## Launch Articles

[Observable Adversarial Behavior, Not Portable Adversarial Procedure](https://dev.to/gnomeman4201/observable-adversarial-behavior-not-portable-adversarial-procedure-4mo6)

[I Built a Tool That Scores How Fragile Your Detection Rules Are](https://dev.to/gnomeman4201)

---

*gnomeman4201 / badBANANA Research Collective*
> Observable adversarial behavior, not portable adversarial procedure.

---

## Part of the BANANA_TREE Research Ecosystem

| | |
|--|--|
| **Research Hub** | [GnomeMan4201](https://github.com/GnomeMan4201/GnomeMan4201) |
| **Corpus & Discovery** | [r4b1t](https://gnomeman4201.github.io/r4b1t) — 119k verified OSINT/security URLs |
| **Investigation Management** | [inv-hub](https://github.com/GnomeMan4201/inv-hub) |
| **Knowledge Base** | [PRAXIS](https://github.com/GnomeMan4201/PRAXIS) |
| **Detection Engineering** | [SHENRON](https://github.com/GnomeMan4201/shenron) |
| **Kernel Telemetry** | [bpf-watch](https://github.com/GnomeMan4201/bpf-watch) |

*badBANANA Research Collective · [dev.to/gnomeman4201](https://dev.to/gnomeman4201)*
