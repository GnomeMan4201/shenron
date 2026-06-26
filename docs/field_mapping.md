# SHENRON Field Mapping Reference

Maps SHENRON synthetic event fields to real log source field names.
Use this when writing Sigma rules against SHENRON artifacts or when
mapping SHENRON output to a real SIEM ingestion pipeline.

## Sigma field -> SHENRON field mapping

The pySigma bridge (core/sigma/pysigma_bridge.py) applies this mapping
when evaluating Sigma rules against SHENRON JSONL artifacts.

| Sigma field | SHENRON event field(s) | Real log source |
|---|---|---|
| CommandLine | behavior_class, command_sim, cmdline_sim | Sysmon EID 1, Security EID 4688 |
| Image | layer, behavior_class, exe_sim | Sysmon EID 1 |
| TargetFilename | target_path_sim, file_path_sim, synthetic_path | Sysmon EID 11 |
| DestinationIp | target_ip_sim, target_hostname | Sysmon EID 3 |
| DestinationPort | port_sim | Sysmon EID 3 |
| User | token_type_sim, user_sim | Security auth events |
| ParentImage | layer, parent_layer_sim | Sysmon EID 1 |
| EventID | event_id_sim, windows_event_id, EventID | Windows Security/System |
| Channel | channel_sim, windows_channel, log_source_sim | Windows Event Log |
| Provider_Name | provider_sim, windows_provider | Windows Event Log |
| Computer | host_sim, computer_sim | All Windows Event Log sources |
| SubjectUserName | user_sim, subject_user_sim | Security EID 4624/4625/4698 |
| SubjectDomainName | domain_sim | Security auth events |
| ObjectName | object_name_sim, target_path_sim | Security EID 4663 |
| ServiceName | service_name_sim, behavior_class | Security EID 4697, System EID 7045 |
| ServiceFileName | service_path_sim, target_path_sim | Security EID 4697 |
| TaskName | task_name_sim, behavior_class | Security EID 4698/4699/4702 |
| RegistryKey | registry_key_sim, target_path_sim | Sysmon EID 12/13 |

## SHENRON-native fields (direct mapping)

These fields map to themselves -- no translation needed.

| Sigma field | SHENRON field | Notes |
|---|---|---|
| layer | layer | SHENRON layer name |
| behavior_class | behavior_class | Primary behavior classification |
| mitre_technique | mitre_techniques | List field -- any match |
| phase | phase | Kill chain phase |
| signal | signal | Detection signal name |
| detection_opp | detection_opportunities | List field -- any match |
| category | category | Event category (benign layers) |
| simulation_only | simulation_only | Always true in SHENRON |

## LLM attack fields

| Sigma field | SHENRON field | Notes |
|---|---|---|
| injection_technique | injection_technique_sim | Prompt injection technique type |
| target_model | target_model_sim | Target LLM model identifier |
| prompt_shape | prompt_shape_sim | Prompt structure descriptor |

## Windows Event IDs emitted by windows_event_log_sim

| EventID | Event | MITRE | Key fields emitted |
|---|---|---|---|
| 4688 | Process Creation | T1059 | EventID, Channel, Image, CommandLine, ParentImage, SubjectUserName |
| 4698 | Scheduled Task Created | T1053.005 | EventID, Channel, TaskName, SubjectUserName |
| 4697 | Service Installed | T1543.003 | EventID, Channel, ServiceName, ServiceFileName |
| 4625 | Failed Logon | T1110 | EventID, Channel, SubjectUserName, SubjectDomainName |
| 1102 | Audit Log Cleared | T1070.001 | EventID, Channel, SubjectUserName |
| 7045 | New Service (System) | T1543.003 | EventID, Channel (System), ServiceName, ServiceFileName |

## LLM platform field mappings

See core/formats/llm_platform_logs.py for full implementation.

### Azure OpenAI (azureDiagnostics table)

| SHENRON field | Azure field |
|---|---|
| token_count_sim | properties_totalTokens_d |
| response_latency_sim | DurationMs |
| target_model_sim | properties_modelDeploymentName_s |
| injection_technique_sim (role_override) | ResultType: ContentFilter |
| phase | Category |

### AWS Bedrock (CloudTrail)

| SHENRON field | Bedrock CloudTrail field |
|---|---|
| target_model_sim | requestParameters.modelId |
| token_count_sim | responseElements.outputTokenCount |
| injection_technique_sim (context_window_overflow) | errorCode: ValidationException |
| phase | eventName |

### Anthropic API audit log

| SHENRON field | Anthropic field |
|---|---|
| target_model_sim | model |
| token_count_sim | usage.input_tokens + usage.output_tokens |
| response_latency_sim | request_latency_ms |
| injection_technique_sim (role_override) | stop_reason: stop_sequence |

## ECS output field mapping

When using core/formats/adapter.py to_ecs(), SHENRON fields map to:

| SHENRON field | ECS field |
|---|---|
| mitre_techniques | threat.technique.id |
| layer | labels.shenron_layer |
| phase | labels.shenron_phase |
| behavior_class | labels.shenron_behavior |
| session_id | labels.shenron_session |
| simulation_only | labels.simulation_only |
| timestamp | @timestamp |

## CEF output field mapping

When using core/formats/cef_adapter.py to_cef(), SHENRON fields map to:

| SHENRON field | CEF field |
|---|---|
| mitre_techniques[0] | SignatureID (header field 4) |
| behavior_class | Name (header field 5) |
| tactic | act, cat, deviceAction |
| timestamp | rt (epoch ms) |
| layer | cs1 / cs1Label=shenron_layer |
| phase | cs2 / cs2Label=shenron_phase |
| session_id | cs3 / cs3Label=shenron_session |
| mitre_techniques | cs5 / cs5Label=mitre_techniques |
| detection_opportunities | cs6 / cs6Label=detection_opps |
| EventID (Windows) | cs1 / cs1Label=EventID |
