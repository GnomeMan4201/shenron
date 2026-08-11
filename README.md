![SHENRON](assets/shenron_banner.png)

# SHENRON

[![CI](https://github.com/GnomeMan4201/shenron/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/GnomeMan4201/shenron/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/GnomeMan4201/shenron)](https://github.com/GnomeMan4201/shenron/releases/latest)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status: Beta](https://img.shields.io/badge/Status-Beta-orange.svg)](pyproject.toml)

SHENRON is a safe synthetic telemetry and detection engineering research tool.

It does not prove that a detection stack is effective.

It helps answer a harder question:
> How durable are your detection rules under adversarial pressure?

Rule coverage is table stakes. Rule durability is the harder problem.

---

## Core principle

**Observable adversarial behavior, not portable adversarial procedure.**

SHENRON generates structured synthetic JSONL telemetry representing adversarial behavior across its [canonical simulation layers](core/layers). It does not contain payloads, exploit code, real network calls, subprocess execution, or operational malware logic. Every artifact is synthetic. Every layer carries an explicit safety contract.

---

## Safety boundary

SHENRON does not contain:

- Executable payloads or shellcode
- Real network connections or socket bindings
- Subprocess spawning or shell command execution
- Real file writes outside its own log directory
- Exploit code of any kind

This is not a disclaimer. It is an architectural constraint enforced by the [canonical-layer static safety gate](tests/test_all_layers_safety_static.py).

---

## Quickstart

~~~bash
git clone https://github.com/GnomeMan4201/shenron.git
cd shenron

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

# Run a campaign
python3 shenron.py campaign --scenario apt29-style --stress-test

# Compare scenarios
python3 shenron.py compare-scenarios

# Evaluate Sigma rules through pySigma
python3 shenron.py sigma \
  --validate-dir sigma/rules/ \
  --events artifacts/demo/shenron_demo_run.jsonl

# Run the MITRE ATT&CK drift CI gate
python3 -m core.ci.drift_gate
~~~

---

## What it does

SHENRON generates structured synthetic telemetry across its canonical layer corpus and scores detection brittleness across three dimensions:

**Artifact-level brittleness** -- does a mutation on a single event cause a Sigma rule to stop firing? Six mutation strategies targeting fields your rules actually reference: value_swap, field_omit, case_flip, unicode_substitute, whitespace_inject, combined_evasion. Strategies are weighted by adversary accessibility -- case_flip requires zero sophistication, value_swap requires knowledge of the detection stack.

**Campaign-level correlation brittleness** -- do mutations on the relationships between events break the ability to correlate them into a coherent intrusion narrative? Four campaign-graph mutations: SESSION_ID_ROTATION, TIMESTAMP_STRETCH, STAGE_DROPOUT, ACTOR_DRIFT.

**Gap metric** -- the difference between artifact brittleness and correlation brittleness.

---

## Sigma evaluation -- pySigma by default

evaluate_sigma_rule() routes through the pySigma bridge by default:

- All modifiers: contains, startswith, endswith, re, all, base64, cidr, exists
- All condition operators: 1 of, all of, N of, wildcards in names, not, and, or
- Windows Event Log fields: EventID, Channel, Provider_Name, Computer, SubjectUserName, ServiceName, TaskName, RegistryKey
- LLM attack fields: injection_technique, target_model

Falls back to the custom evaluator if pySigma is unavailable.

### Windows Event Log telemetry

core/layers/windows_event_log_sim.py emits real EventID, Channel, and Provider_Name fields.
EventID 4698 + TaskName *update* Sigma rules fire correctly through the default evaluator path.

### SHENRON to real log field mapping

| Sigma field | SHENRON field(s) | Real log source |
|---|---|---|
| EventID | event_id_sim, windows_event_id, EventID | Windows Security/System |
| Channel | channel_sim, windows_channel | Windows Event Log |
| Provider_Name | provider_sim, windows_provider | Windows Event Log |
| CommandLine | behavior_class, command_sim | Sysmon EID 1, Security EID 4688 |
| Image | layer, exe_sim | Sysmon EID 1 |
| TaskName | task_name_sim | Security EID 4698 |
| ServiceName | service_name_sim | Security EID 4697, System EID 7045 |
| SubjectUserName | user_sim, subject_user_sim | Security auth events |
| TargetFilename | target_path_sim, synthetic_path | Sysmon EID 11 |

---

## Feedback-driven adversary adaptation

The adaptation engine (`core/campaign/adaptation.py`) implements feedback-driven strategy selection:

1. Inspect which Sigma rules are still firing after each iteration.
2. Extract the SHENRON event fields referenced by those rules.
3. Score mutation strategies by field coverage against the still-firing rules.
4. Apply a diversity penalty to overused strategies.
5. Select the highest-scoring strategy that is not exhausted.

Example output:

~~~text
[ADAPT] Iter 01/8 -- strategy: sigma_aware_field_omit (feedback-selected)
[ADAPT] Top candidates: [(sigma_aware_field_omit, 2), (sigma_aware_value_swap, 2)]
[ADAPT] Firing: 1 | Evaded: 3 | Rate: 0.75
~~~

---

## LLM manipulation telemetry

SHENRON includes a structured, multi-layer LLM manipulation scenario for detection-engineering experiments:

- 7 injection techniques: role override, indirect RAG pipeline, jailbreak encoding, output poisoning, prompt fuzzing, context window overflow, multimodal injection
- 5-phase kill chain: RECONNAISSANCE -> INJECT -> MANIPULATE -> OBFUSCATE -> EXFILTRATE
- 9 MITRE techniques: T1059.007, T1190, T1027, T1565.001, T1036, T1048, T1590, T1565, T1027.002
- 25 detection opportunities per scenario run
- Detection coverage: [LLM manipulation Sigma rule](sigma/rules/llm/shenron_llm_manipulation.yml) with [scenario regression tests](tests/test_llm_manipulation.py)

[Platform log schema mappers](core/formats/llm_platform_logs.py):

| Platform | Schema | Key fields |
|---|---|---|
| Azure OpenAI | azureDiagnostics table | TimeGenerated, OperationName, ResultType, properties_totalTokens_d |
| AWS Bedrock | CloudTrail bedrock.amazonaws.com | eventSource, eventName, requestParameters.modelId, errorCode |
| Anthropic API | Messages API audit log | model, stop_reason, usage.input_tokens, request_latency_ms |

Role override injection: ResultType ContentFilter (Azure) / errorCode ValidationException (Bedrock) / stop_reason stop_sequence (Anthropic).

---

## Output format adapters

| Format | Module | Target |
|---|---|---|
| ECS Elastic Common Schema | core/formats/adapter.py | Elastic / OpenSearch |
| Splunk HEC | core/formats/adapter.py | Splunk HTTP Event Collector |
| CEF | core/formats/cef_adapter.py | ArcSight, IBM QRadar, HP Logger |
| Azure OpenAI logs | core/formats/llm_platform_logs.py | Azure Monitor / Log Analytics |
| AWS Bedrock CloudTrail | core/formats/llm_platform_logs.py | AWS Security Lake / Athena |
| Anthropic audit logs | core/formats/llm_platform_logs.py | Any SIEM with JSON ingest |

---

## Adversary archetypes

| Scenario | Stages | Shape |
|---|---|---|
| apt29-style | 7 | Full kill chain with recon |
| ransomware-precursor | 5 | Beacon to payload to persistence to lateral to exfil |
| insider-threat | 4 | No initial access, direct collection |
| fin7-style | 6 | Execution-first, credential harvest heavy |
| supply-chain | 4 | Dependency confusion as initial access vector |
| living-off-the-land | 4 | Pure LOtL, native tools throughout |

The named `*-style` scenarios are synthetic shorthand for experiment shapes. They do not claim behavioral fidelity to, emulation of, or attribution involving the named real-world actors.

---

## Verification surfaces

| Surface | Repository evidence |
|---|---|
| CI | [Python 3.10–3.12 test matrix plus safety, package, ATT&CK drift, and assumption jobs](.github/workflows/ci.yml) |
| Safety contract | [Static forbidden-call and forbidden-import gate](tests/test_all_layers_safety_static.py) |
| Simulation corpus | [Canonical layer implementations](core/layers) and [committed demonstration telemetry](artifacts/demo/shenron_demo_run.jsonl) |
| Sigma evaluation | [Rule-count and verdict regression gate](tests/test_sigma_integration.py) |
| LLM scenario | [Scenario regression suite](tests/test_llm_manipulation.py) and [Sigma rule](sigma/rules/llm/shenron_llm_manipulation.yml) |
| Golden demo | [Pinned artifact regression checks](tests/test_golden_demo.py) |
| pySigma bridge | [Bridge implementation](core/sigma/pysigma_bridge.py) and [integration tests](tests/test_sigma_integration.py) |
| MITRE ATT&CK drift | [Drift implementation](core/ci/drift_gate.py) and [regression tests](tests/test_mitre_drift.py) |
| Output adapters | [ECS/Splunk implementation](core/formats/adapter.py), [CEF implementation](core/formats/cef_adapter.py), and [platform-log tests](tests/test_llm_platform_logs.py) |
| Feedback adaptation | [Strategy-selection implementation](core/campaign/adaptation.py) and [Sigma-aware regression tests](tests/test_sigma_aware.py) |

---

## Repository structure

~~~text
core/campaign        -- CampaignBuilder, AdaptationEngine, DiffTool
core/brittleness     -- BrittlenessScorer, ArtifactBrittleness, weighted scoring
core/mutation        -- SigmaAwareMutator, combined evasion, deterministic seeding
core/sigma           -- pySigma default evaluator, bridge, generator, loader
core/layers          -- canonical simulation layers, including Windows and LLM
core/noise           -- BenignEventGenerator with 6 categories and 28 templates
core/assumptions     -- validator, fuzzer, and evidence-discipline layer
core/formats         -- ECS, Splunk HEC, CEF, and LLM platform adapters
core/ingest          -- journald normalizer
core/ci              -- GitHub Actions-compatible MITRE ATT&CK drift gate
core/engine          -- layer loader and payload registry
sigma/rules          -- Sigma rules across simulation and live telemetry
artifacts            -- committed demonstration and validation artifacts
docs                 -- field mappings and layer rename documentation
tests                -- regression, safety, integration, and evidence-contract checks
~~~

---

## Live telemetry integration

SHENRON can evaluate compatible JSONL telemetry produced outside the synthetic layer corpus. The public repository includes five live-only Sigma rules and the schema/assumption material used to keep that live path distinct from simulated-artifact expectations.

The current live-rule examples were developed against `bpf-watch` telemetry. That collector is not part of this public repository, so public users should treat the documented JSONL fields and committed live-rule tests as the available interface rather than expecting an external collector link to be reproducible from this checkout.

The [five live-only Sigma rules](sigma/rules/live) are explicitly separated from simulated-artifact trigger expectations in the [Sigma integration gate](tests/test_sigma_integration.py). This keeps live-telemetry claims distinct from results produced by SHENRON's committed synthetic artifacts.

---

## Launch articles

- [Observable Adversarial Behavior, Not Portable Adversarial Procedure](https://dev.to/gnomeman4201/observable-adversarial-behavior-not-portable-adversarial-procedure-4mo6)
- [SHENRON v0.3.3: From Telemetry Generator to Blue-Team Reasoning Instrument](https://dev.to/gnomeman4201/shenron-v033-from-telemetry-generator-to-blue-team-reasoning-instrument-2k91)

---

gnomeman4201 / badBANANA Research Collective

*Observable adversarial behavior, not portable adversarial procedure.*