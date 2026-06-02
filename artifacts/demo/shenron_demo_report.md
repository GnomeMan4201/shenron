# SHENRON Demo Run Report

**Run ID:** `demo-22dd79e7a7b5`  
**Generated:** 2026-06-02T18:55:48.288056+00:00  
**Generator:** shenron/demo_generator v0.1.0  

> **IMPORTANT:** This report was produced by the safe demo artifact generator.
> All records are synthetic. No real adversarial execution occurred.
> Every record carries `simulation_only: true`, `executable: false`,
> `payload_present: false`, `portable_adversarial_procedure: false`.

---

## Summary

| Metric | Value |
|--------|-------|
| Total events | 40 |
| Phases | 4 |
| Unique layers | 40 |
| MITRE techniques | 32 |
| Unique signals | 40 |
| Safety violations | 0 |
| Verdict | ✅ PASS |

---

## Phase Breakdown

### OBSERVE (10 events)

| Layer | Signal | MITRE |
|-------|--------|-------|
| `beacon_emitter_cloak` | `periodic_beacon` | T1071.001 |
| `autonomous_signal_cloner` | `signal_clone` | T1020 |
| `entropy_profiler` | `entropy_spike` | T1027 |
| `dns_shape_observer` | `dns_burst` | T1071.004 |
| `tls_fingerprint_recorder` | `tls_ja3_shape` | T1573.001 |
| `identity_spoofing_sensor` | `identity_mismatch` | T1036 |
| `privilege_context_sensor` | `privilege_delta` | T1068 |
| `process_hollow_detector` | `hollow_process_signal` | T1055.012 |
| `env_recon_simulator` | `env_enum_signal` | T1082 |
| `auth_probe_logger` | `auth_probe_burst` | T1110 |

### SIMULATE (10 events)

| Layer | Signal | MITRE |
|-------|--------|-------|
| `spectral_packet_weaver` | `covert_channel_shape` | T1048 |
| `void_gateway_tunnel` | `protocol_tunnel_shape` | T1095 |
| `llm_prompt_injector` | `llm_injection_signal` | T1059.007 |
| `mirror_loop_deflector` | `defensive_impair_signal` | T1070 |
| `lateral_probe_emitter` | `lateral_probe_shape` | T1021 |
| `payload_shape_model` | `obfuscation_pattern` | T1027 |
| `exfil_volume_sim` | `exfil_volume_shape` | T1041 |
| `staged_loader_shape` | `staged_loader_signal` | T1055 |
| `anti_debug_signal` | `anti_debug_signal` | T1622 |
| `sandbox_detect_shape` | `sandbox_detect_signal` | T1497 |

### EXECUTE (10 events)

| Layer | Signal | MITRE |
|-------|--------|-------|
| `persistence_cron_shape` | `cron_persist_signal` | T1053.003 |
| `service_install_shape` | `service_install_signal` | T1543.003 |
| `reg_run_key_shape` | `reg_run_key_signal` | T1547.001 |
| `startup_folder_shape` | `startup_persist_signal` | T1547.001 |
| `scheduled_task_shape` | `task_sched_signal` | T1053.005 |
| `lateral_rdp_shape` | `rdp_lateral_signal` | T1021.001 |
| `wmi_exec_shape` | `wmi_exec_signal` | T1047 |
| `powershell_shape` | `ps_invocation_signal` | T1059.001 |
| `dll_load_shape` | `dll_load_signal` | T1574.002 |
| `network_share_enum_shape` | `net_share_signal` | T1135 |

### ADAPT (10 events)

| Layer | Signal | MITRE |
|-------|--------|-------|
| `coverage_gap_scorer` | `coverage_gap_score` | T1589 |
| `signal_drift_detector` | `signal_drift_score` | T1205 |
| `mutation_trace_logger` | `mutation_trace` | T1027 |
| `detection_rule_validator` | `rule_validation_signal` | T1595 |
| `mitre_coverage_aggregator` | `mitre_coverage_score` | T1590 |
| `false_positive_shape_model` | `fp_shape_signal` | T1036 |
| `run_comparison_engine` | `run_delta_score` | T1589 |
| `telemetry_schema_validator` | `schema_valid_signal` | T1595 |
| `analyst_workflow_shape` | `analyst_workflow_signal` | T1590 |
| `gap_report_emitter` | `gap_report_signal` | T1589 |

---

## MITRE ATT&CK Coverage

Techniques present in this run:

- T1020
- T1021
- T1021.001
- T1027
- T1036
- T1041
- T1047
- T1048
- T1053.003
- T1053.005
- T1055
- T1055.012
- T1059.001
- T1059.007
- T1068
- T1070
- T1071.001
- T1071.004
- T1082
- T1095
- T1110
- T1135
- T1205
- T1497
- T1543.003
- T1547.001
- T1573.001
- T1574.002
- T1589
- T1590
- T1595
- T1622

---

## Safety Verification

All 40 records passed safety contract validation.

| Field | Value |
|-------|-------|
| `simulation_only` | `True` |
| `executable` | `False` |
| `payload_present` | `False` |
| `portable_adversarial_procedure` | `False` |
| `network_connection` | `False` |
| `subprocess_spawned` | `False` |
| `real_file_written` | `False` |
| `shell_invoked` | `False` |

---

## What this proves

- SHENRON can generate structured synthetic telemetry across all four bananaTREE phases.
- Each event carries an explicit safety contract readable by downstream tooling.
- Coverage spans 32 MITRE technique descriptors.
- The generator contains zero subprocess calls, zero socket calls, zero file execution.

## What this does NOT prove

- This is a demo generator run, not a full 50-layer scenario execution.
- No real SIEM has been tested against these events.
- No real detection rules have fired on this output.
- The telemetry shape is representative, not field-validated.

---

*SHENRON — Observable adversarial behavior, not portable adversarial procedure.*
