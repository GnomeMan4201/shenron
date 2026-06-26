![SHENRON](assets/shenron_banner.png)

SHENRON is a safe synthetic telemetry and detection engineering research tool.

It does not prove that a detection stack is effective.

It helps answer a harder question:
> How durable are your detection rules under adversarial pressure?

Rule coverage is table stakes. Rule durability is the harder problem.

---

## Core principle

**Observable adversarial behavior, not portable adversarial procedure.**

SHENRON generates structured synthetic JSONL telemetry representing adversarial behavior across 66 simulation layers. It does not contain payloads, exploit code, real network calls, subprocess execution, or operational malware logic. Every artifact is synthetic. Every layer carries an explicit safety contract.

---

## Safety boundary

SHENRON does not contain:

- Executable payloads or shellcode
- Real network connections or socket bindings
- Subprocess spawning or shell command execution
- Real file writes outside its own log directory
- Exploit code of any kind

This is not a disclaimer. It is an architectural constraint. Every layer is statically checked by tests/test_all_layers_safety_static.py.

---

## Quickstart

Install: pip install pyyaml pytest pysigma --break-system-packages

Run a campaign: python3 shenron.py campaign --scenario apt29-style --stress-test

Compare scenarios: python3 shenron.py compare-scenarios

Evaluate Sigma rules (pySigma by default): python3 shenron.py sigma --validate-dir sigma/rules/ --events artifacts/demo/shenron_demo_run.jsonl

MITRE drift CI gate: python3 -m core.ci.drift_gate

---

## What it does

SHENRON scores detection brittleness across three dimensions:

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

The adaptation engine (core/campaign/adaptation.py) implements genuine feedback-driven strategy selection:

1. After each iteration, inspect which Sigma rules are still firing
2. Extract which SHENRON event fields those rules test via live rule YAML parsing
3. Score each mutation strategy by field coverage against still-firing rules
4. Apply a diversity penalty for over-used strategies
5. Select the highest-scoring strategy not yet exhausted

Example output:
  [ADAPT] Iter 01/8 -- strategy: sigma_aware_field_omit (feedback-selected)
  [ADAPT]   Top candidates: [(sigma_aware_field_omit, 2), (sigma_aware_value_swap, 2)]
  [ADAPT]   Firing: 1 | Evaded: 3 | Rate: 0.75

---

## LLM manipulation telemetry

The first structured multi-layer LLM attack scenario in the detection engineering space:

- 7 injection techniques: role override, indirect RAG pipeline, jailbreak encoding, output poisoning, prompt fuzzing, context window overflow, multimodal injection
- 5-phase kill chain: RECONNAISSANCE -> INJECT -> MANIPULATE -> OBFUSCATE -> EXFILTRATE
- 9 MITRE techniques: T1059.007, T1190, T1027, T1565.001, T1036, T1048, T1590, T1565, T1027.002
- 25 detection opportunities per scenario run
- Sigma rule: sigma/rules/llm/shenron_llm_manipulation.yml -- 5 detection blocks, all TRIGGERED

Platform log schema mappers (core/formats/llm_platform_logs.py):

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

---

## Verified state

| Check | Result |
|---|---|
| Test suite | 885 passed (Python 3.12) |
| Simulation layers | 66 |
| Sigma rules | 28 |
| Adversary scenarios | 6 |
| Artifact mutation strategies | 11 (6 standard + 5 sigma-aware) |
| Correlation mutation strategies | 4 |
| Safety failures | 0 |
| pySigma integration | default evaluator path |
| Windows EventID support | windows_event_log_sim + pySigma bridge |
| LLM platform log schemas | Azure OpenAI, AWS Bedrock, Anthropic |
| CEF output | ArcSight/QRadar compatible |
| Feedback-driven adaptation | field-coverage strategy scoring |
| MITRE drift CI gate | exit codes 0/1/2 |

---

## Repository structure

core/campaign        -- CampaignBuilder, AdaptationEngine feedback-driven, DiffTool
core/brittleness     -- BrittlenessScorer, ArtifactBrittleness, weighted scoring
core/mutation        -- SigmaAwareMutator, combined evasion, deterministic seeding
core/sigma           -- evaluator pySigma default, pysigma_bridge, generator, loader
core/layers          -- 66 canonical simulation layers incl Windows Event Log and LLM
core/noise           -- BenignEventGenerator 6 categories 28 templates
core/assumptions     -- validator, fuzzer, evidence discipline layer
core/formats         -- ECS, Splunk HEC, CEF adapters; LLM platform log schemas
core/ingest          -- journald normalizer
core/ci              -- MITRE drift CI gate GitHub Actions compatible
core/engine          -- layer loader and payload registry
sigma/rules          -- 28 Sigma rules c2, persistence, evasion, execution, llm, live
artifacts            -- demo, LLM, Windows, platform log artifacts
docs                 -- layer rename map, field mapping documentation
tests                -- 885 tests across 40+ test files

---

## Live telemetry integration

SHENRON accepts live telemetry from bpf-watch (https://github.com/GnomeMan4201/bpf-watch), an eBPF rootkit detection daemon that emits SHENRON-compatible JSONL.

5 live Sigma rules in sigma/rules/live/ fire against real kernel telemetry. The kprobe sentinel rule has been confirmed TRIGGERED against real kernel execve hooks on kernel 6.18.7.

---

## Launch articles

Observable Adversarial Behavior, Not Portable Adversarial Procedure
https://dev.to/gnomeman4201/observable-adversarial-behavior-not-portable-adversarial-procedure-4mo6

I Built a Tool That Scores How Fragile Your Detection Rules Are
https://dev.to/gnomeman4201

---

## Part of the BANANA_TREE Research Ecosystem

r4b1t         https://gnomeman4201.github.io/r4b1t -- 119k verified OSINT/security URLs
inv-hub       https://github.com/GnomeMan4201/inv-hub
PRAXIS        https://github.com/GnomeMan4201/PRAXIS
SHENRON       https://github.com/GnomeMan4201/shenron
bpf-watch     https://github.com/GnomeMan4201/bpf-watch

gnomeman4201 / badBANANA Research Collective
Observable adversarial behavior, not portable adversarial procedure.