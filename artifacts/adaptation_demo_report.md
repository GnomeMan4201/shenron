# SHENRON Adversary Adaptation Report

**Campaign:** unknown (`demo-b4dbefc84ae...`)  
**Generated:** 2026-06-25T22:58:03.432234+00:00  
**Rules Evaluated:** 68  
**Rules Firing on Original:** 41  
**Iterations Run:** 11  
**Full Evasion Achieved:** **YES** — achieved in 11 iteration(s)  

## Adaptation Path

label_ambiguity → field_drop → timing_jitter → technique_noise → signal_density_low → phase_imbalance → sigma_aware_case_flip → sigma_aware_unicode → sigma_aware_whitespace → sigma_aware_value_swap → sigma_aware_field_omit

## Per-Iteration Results

| Iteration | Mutation | Rules Fired | Evaded | Evasion Rate |
|-----------|----------|------------|--------|-------------|
| 1 | label_ambiguity | 41 | 0 | 0.00 |
| 2 | field_drop | 41 | 0 | 0.00 |
| 3 | timing_jitter | 41 | 0 | 0.00 |
| 4 | technique_noise | 41 | 0 | 0.00 |
| 5 | signal_density_low | 25 | 16 | 0.39 |
| 6 | phase_imbalance | 25 | 16 | 0.39 |
| 7 | sigma_aware_case_flip | 25 | 16 | 0.39 |
| 8 | sigma_aware_unicode | 25 | 16 | 0.39 |
| 9 | sigma_aware_whitespace | 25 | 16 | 0.39 |
| 10 | sigma_aware_value_swap | 25 | 16 | 0.39 |
| 11 | sigma_aware_field_omit | 0 | 41 | 1.00 |

## Evaded Rules

- SHENRON C2 Beacon Detection
- SHENRON Covert Channel / Protocol Tunneling
- Ephemeral Exfiltration Shell Behavioral Cluster
- SHENRON Generated — Analyst Workflow Shape
- SHENRON Generated — Anti Debug Signal
- SHENRON Generated — Auth Probe Logger
- SHENRON Generated — Autonomous Signal Cloner
- SHENRON Generated — Coverage Gap Scorer
- SHENRON Generated — Detection Rule Validator
- SHENRON Generated — Dll Load Shape
- SHENRON Generated — Dns Shape Observer
- SHENRON Generated — Entropy Profiler
- SHENRON Generated — Env Recon Simulator
- SHENRON Generated — Exfil Volume Sim
- SHENRON Generated — False Positive Shape Model
- SHENRON Generated — Gap Report Emitter
- SHENRON Generated — Identity Spoofing Sensor
- SHENRON Generated — Lateral Probe Emitter
- SHENRON Generated — Lateral Rdp Shape
- SHENRON Generated — Llm Prompt Injector
- SHENRON Generated — Mirror Loop Deflector
- SHENRON Generated — Mitre Coverage Aggregator
- SHENRON Generated — Mutation Trace Logger
- SHENRON Generated — Network Share Enum Shape
- SHENRON Generated — Payload Shape Model
- SHENRON Generated — Persistence Cron Shape
- SHENRON Generated — Powershell Shape
- SHENRON Generated — Privilege Context Sensor
- SHENRON Generated — Process Hollow Detector
- SHENRON Generated — Reg Run Key Shape
- SHENRON Generated — Run Comparison Engine
- SHENRON Generated — Sandbox Detect Shape
- SHENRON Generated — Scheduled Task Shape
- SHENRON Generated — Service Install Shape
- SHENRON Generated — Signal Drift Detector
- SHENRON Generated — Staged Loader Shape
- SHENRON Generated — Startup Folder Shape
- SHENRON Generated — Telemetry Schema Validator
- SHENRON Generated — Tls Fingerprint Recorder
- SHENRON Generated — Void Gateway Tunnel
- SHENRON Generated — Wmi Exec Shape

## Surviving Rules (Detection-Robust)

*(all rules evaded)*