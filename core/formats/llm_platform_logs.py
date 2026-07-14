"""
core/formats/llm_platform_logs.py

SHENRON LLM Platform Log Schema Mapper.

Maps SHENRON synthetic LLM attack telemetry to real log field schemas
from major LLM platform deployments:

  - Azure OpenAI Service diagnostic logs
    (Log Analytics / azureDiagnostics table)
  - AWS Bedrock CloudTrail events
    (eventSource: bedrock.amazonaws.com)
  - Anthropic API audit logs
    (structured JSON, api.anthropic.com)

PURPOSE: Close the gap identified in external assessment —
  "the module emits purely synthetic JSON with simulated fields like
   confidence_delta_sim that have no connection to real SIEM field schemas."

After conversion, SHENRON LLM attack telemetry can be:
  1. Directly compared to real platform logs in a SIEM
  2. Used to write Sigma rules that target actual log field names
  3. Fed into ECS via the existing adapter for Elastic ingestion

All output events carry simulation_only: true and the full safety contract.
No real API calls are made.

Reference field schemas:
  Azure: https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/monitoring
  Bedrock: https://docs.aws.amazon.com/bedrock/latest/userguide/logging.html
  Anthropic: https://docs.anthropic.com/en/api/getting-started
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional


# ── Azure OpenAI diagnostic log schema ────────────────────────────────────────
# Fields from azureDiagnostics table, Log Analytics workspace
# Source: Azure Monitor / OpenAI resource diagnostic settings

def to_azure_openai_log(event: dict) -> dict:
    """
    Map a SHENRON LLM event to Azure OpenAI diagnostic log format.

    Real field names from azureDiagnostics:
      TimeGenerated, OperationName, ResultType, ResultDescription,
      DurationMs, CallerIpAddress, Resource, ResourceGroup,
      SubscriptionId, TenantId, Category, Level,
      properties_modelVersion_s, properties_modelDeploymentName_s,
      properties_requestId_s, properties_promptTokens_d,
      properties_completionTokens_d, properties_totalTokens_d,
      properties_finishReason_s, properties_streamingEnabled_b
    """
    ts = event.get("timestamp", datetime.now(timezone.utc).isoformat())
    token_count = event.get("token_count_sim", 512)
    latency = event.get("response_latency_sim", 1.5)
    target_model = event.get("target_model_sim", "gpt-4-sim")
    injection_tech = event.get("injection_technique_sim", "")
    phase = event.get("phase", "UNKNOWN")
    behavior = event.get("behavior_class", "")

    # Prompt tokens heuristic: 60% of total for injection attacks
    prompt_tokens = int(token_count * 0.6)
    completion_tokens = token_count - prompt_tokens

    # Map injection phase to Azure operation
    operation_map = {
        "RECONNAISSANCE":   "ChatCompletions_Create",
        "INJECTION_ATTEMPT": "ChatCompletions_Create",
        "VALIDATION":       "ChatCompletions_Create",
        "EXFILTRATION_SIM": "ChatCompletions_Create",
        "echo_session_init": "ChatCompletions_Create",
        "hallucination_trace_sim": "ChatCompletions_Create",
        "obfuscation_layering": "Embeddings_Create",
        "OBFUSCATE":        "Embeddings_Create",
        "EXFILTRATE":       "ChatCompletions_Create",
    }
    operation = operation_map.get(phase, "ChatCompletions_Create")

    # Suspicious result: injection attempts may return policy violations
    result_type = "Success"
    result_desc = "Request completed successfully"
    if injection_tech in ("role_override_sim", "jailbreak_encoding_sim",
                           "context_window_overflow_sim"):
        result_type = "ContentFilter"
        result_desc = "Request blocked by content filtering policy"

    return {
        # Azure Monitor standard fields
        "TimeGenerated":        ts,
        "OperationName":        operation,
        "ResultType":           result_type,
        "ResultDescription":    result_desc,
        "DurationMs":           int(latency * 1000),
        "CallerIpAddress":      "10.0.sim.1",
        "Resource":             f"OPENAI-SIM-{target_model.upper().replace('-','')}",
        "ResourceGroup":        "rg-ai-sim",
        "SubscriptionId":       "00000000-sim-0000-0000-000000000000",
        "TenantId":             "ffffffff-sim-ffff-ffff-ffffffffffff",
        "Category":             "RequestResponse",
        "Level":                "Warning" if result_type != "Success" else "Information",

        # Azure OpenAI properties (flattened, _s suffix = string, _d = double, _b = bool)
        "properties_modelDeploymentName_s": target_model,
        "properties_modelVersion_s":        "2024-sim",
        "properties_requestId_s":           str(uuid.uuid4()),
        "properties_promptTokens_d":        float(prompt_tokens),
        "properties_completionTokens_d":    float(completion_tokens),
        "properties_totalTokens_d":         float(token_count),
        "properties_finishReason_s":        "stop" if result_type == "Success" else "content_filter",
        "properties_streamingEnabled_b":    False,

        # SHENRON provenance — preserved for correlation
        "shenron_layer":            event.get("layer", ""),
        "shenron_phase":            phase,
        "shenron_behavior":         behavior,
        "shenron_injection_tech":   injection_tech,
        "shenron_session_id":       event.get("session_id", ""),
        "shenron_mitre_techniques": event.get("mitre_techniques", []),
        "shenron_detection_opps":   event.get("detection_opportunities", []),

        # Safety contract
        "simulation_only":  True,
        "executable":       False,
        "payload_present":  False,

        # Schema identifier
        "_shenron_schema": "azure_openai_diagnostic_v1",
        "_schema_note":    (
            "SYNTHETIC — field names match Azure Monitor azureDiagnostics table. "
            "Values are simulated. No real Azure API was called."
        ),
    }


# ── AWS Bedrock CloudTrail schema ─────────────────────────────────────────────
# Fields from CloudTrail events with eventSource: bedrock.amazonaws.com
# Source: AWS Bedrock model invocation logging / CloudTrail

def to_bedrock_cloudtrail(event: dict) -> dict:
    """
    Map a SHENRON LLM event to AWS Bedrock CloudTrail event format.

    Real CloudTrail fields:
      eventVersion, userIdentity, eventTime, eventSource, eventName,
      awsRegion, sourceIPAddress, userAgent, requestParameters,
      responseElements, requestID, eventID, eventType, recipientAccountId
    """
    ts = event.get("timestamp", datetime.now(timezone.utc).isoformat())
    token_count = event.get("token_count_sim", 512)
    latency     = event.get("response_latency_sim", 1.5)
    target_model = event.get("target_model_sim", "claude-3-sim")
    injection_tech = event.get("injection_technique_sim", "")
    phase  = event.get("phase", "UNKNOWN")
    behavior = event.get("behavior_class", "")

    # Map SHENRON model names to Bedrock model IDs
    model_id_map = {
        "claude-3-sim":    "anthropic.claude-3-sonnet-20240229-v1:0",
        "llama-3-sim":     "meta.llama3-70b-instruct-v1:0",
        "mistral-sim":     "mistral.mistral-large-2402-v1:0",
        "local-ollama-sim": "amazon.titan-text-express-v1",
        "gpt-4-sim":       "amazon.titan-text-premier-v1:0",
        "gemini-pro-sim":  "amazon.titan-text-express-v1",
    }
    model_id = model_id_map.get(target_model, "anthropic.claude-3-sonnet-20240229-v1:0")

    event_name_map = {
        "RECONNAISSANCE":    "InvokeModel",
        "INJECTION_ATTEMPT": "InvokeModel",
        "VALIDATION":        "InvokeModel",
        "EXFILTRATION_SIM":  "InvokeModel",
        "EXFILTRATE":        "InvokeModel",
        "MANIPULATE":        "InvokeModel",
        "OBFUSCATE":         "InvokeModelWithResponseStream",
    }
    event_name = event_name_map.get(phase, "InvokeModel")

    error_code = None
    error_msg  = None
    if injection_tech in ("context_window_overflow_sim", "role_override_sim"):
        error_code = "ValidationException"
        error_msg  = "Input too long for requested model"

    return {
        # CloudTrail standard fields
        "eventVersion":      "1.08",
        "eventTime":         ts,
        "eventSource":       "bedrock.amazonaws.com",
        "eventName":         event_name,
        "awsRegion":         "us-east-1-sim",
        "sourceIPAddress":   "10.0.sim.2",
        "userAgent":         "python-requests/2.31.0-sim",
        "requestID":         str(uuid.uuid4()),
        "eventID":           str(uuid.uuid4()),
        "eventType":         "AwsApiCall",
        "recipientAccountId": "123456789012-SIM",
        "readOnly":          False,

        # User identity
        "userIdentity": {
            "type":           "AssumedRole",
            "principalId":    "AROASIM:session-sim",
            "arn":            "arn:aws:sts::123456789012-SIM:assumed-role/sim-role/session",
            "accountId":      "123456789012-SIM",
            "sessionContext": {
                "sessionIssuer": {
                    "type":      "Role",
                    "userName":  "sim-bedrock-role",
                    "arn":       "arn:aws:iam::123456789012-SIM:role/sim-bedrock-role",
                }
            }
        },

        # Request parameters
        "requestParameters": {
            "modelId":         model_id,
            "contentType":     "application/json",
            "accept":          "application/json",
        },

        # Response elements
        "responseElements": None if error_code else {
            "inputTokenCount":  int(token_count * 0.6),
            "outputTokenCount": int(token_count * 0.4),
            "stopReason":       "end_turn",
            "latencyMs":        int(latency * 1000),
        },

        # Error (if any)
        "errorCode":    error_code,
        "errorMessage": error_msg,

        # SHENRON provenance
        "shenron_layer":            event.get("layer", ""),
        "shenron_phase":            phase,
        "shenron_behavior":         behavior,
        "shenron_injection_tech":   injection_tech,
        "shenron_session_id":       event.get("session_id", ""),
        "shenron_mitre_techniques": event.get("mitre_techniques", []),
        "shenron_detection_opps":   event.get("detection_opportunities", []),

        # Safety
        "simulation_only": True,
        "executable":      False,
        "payload_present": False,

        "_shenron_schema": "aws_bedrock_cloudtrail_v1",
        "_schema_note":    (
            "SYNTHETIC — field names match AWS CloudTrail Bedrock events. "
            "Values are simulated. No real AWS API was called."
        ),
    }


# ── Anthropic API audit log schema ────────────────────────────────────────────
# Based on Anthropic API response structure and usage logging
# Source: Anthropic API docs + audit log format

def to_anthropic_audit_log(event: dict) -> dict:
    """
    Map a SHENRON LLM event to Anthropic API audit log format.

    Anthropic logs structured as JSON with these top-level fields:
      id, type, model, role, content, stop_reason, stop_sequence,
      usage.input_tokens, usage.output_tokens, usage.cache_creation_input_tokens
    Plus request metadata:
      request_id, organization_id, api_key_id, created_at
    """
    ts = event.get("timestamp", datetime.now(timezone.utc).isoformat())
    token_count  = event.get("token_count_sim", 512)
    latency      = event.get("response_latency_sim", 1.5)
    target_model = event.get("target_model_sim", "claude-3-sim")
    injection_tech = event.get("injection_technique_sim", "")
    phase   = event.get("phase", "UNKNOWN")
    behavior = event.get("behavior_class", "")

    model_map = {
        "claude-3-sim":    "claude-3-5-sonnet-20241022",
        "gpt-4-sim":       "claude-3-5-sonnet-20241022",
        "gemini-pro-sim":  "claude-3-opus-20240229",
        "llama-3-sim":     "claude-3-haiku-20240307",
        "mistral-sim":     "claude-3-haiku-20240307",
        "local-ollama-sim": "claude-3-haiku-20240307",
    }
    model = model_map.get(target_model, "claude-3-5-sonnet-20241022")

    stop_reason = "end_turn"
    if injection_tech == "context_window_overflow_sim":
        stop_reason = "max_tokens"
    elif injection_tech in ("role_override_sim", "jailbreak_encoding_sim"):
        stop_reason = "stop_sequence"

    input_tokens  = int(token_count * 0.65)
    output_tokens = token_count - input_tokens

    return {
        # Anthropic Messages API response structure
        "id":           f"msg_sim_{uuid.uuid4().hex[:24]}",
        "type":         "message",
        "model":        model,
        "role":         "assistant",
        "stop_reason":  stop_reason,
        "stop_sequence": None,

        # Usage
        "usage": {
            "input_tokens":                  input_tokens,
            "output_tokens":                 output_tokens,
            "cache_creation_input_tokens":   0,
            "cache_read_input_tokens":       0,
        },

        # Request metadata (audit log additions)
        "request_id":       str(uuid.uuid4()),
        "organization_id":  "org-sim-00000000",
        "api_key_id":       "key-sim-00000000",
        "created_at":       ts,
        "request_latency_ms": int(latency * 1000),

        # Request parameters (audit log captures these)
        "request": {
            "model":       model,
            "max_tokens":  4096,
            "stream":      False,
            "messages": [
                {
                    "role":    "user",
                    "content": f"[SHENRON SYNTHETIC] {injection_tech or behavior} shape",
                }
            ],
        },

        # Content block (synthetic, minimal)
        "content": [
            {
                "type": "text",
                "text": f"[SHENRON SYNTHETIC RESPONSE — {phase}]",
            }
        ],

        # SHENRON provenance
        "shenron_layer":            event.get("layer", ""),
        "shenron_phase":            phase,
        "shenron_behavior":         behavior,
        "shenron_injection_tech":   injection_tech,
        "shenron_session_id":       event.get("session_id", ""),
        "shenron_mitre_techniques": event.get("mitre_techniques", []),
        "shenron_detection_opps":   event.get("detection_opportunities", []),

        # Safety
        "simulation_only": True,
        "executable":      False,
        "payload_present": False,

        "_shenron_schema": "anthropic_audit_log_v1",
        "_schema_note":    (
            "SYNTHETIC — field names match Anthropic Messages API response + audit log. "
            "Values are simulated. No real Anthropic API was called."
        ),
    }


# ── Bulk converters ────────────────────────────────────────────────────────────

def convert_llm_artifact(
    artifact_path: str,
    platform: str = "azure",
) -> List[dict]:
    """
    Convert a SHENRON LLM JSONL artifact to platform log format.

    Args:
        artifact_path: Path to SHENRON JSONL artifact
        platform:      "azure" | "bedrock" | "anthropic"

    Returns:
        List of platform-formatted log events
    """
    converters = {
        "azure":     to_azure_openai_log,
        "bedrock":   to_bedrock_cloudtrail,
        "anthropic": to_anthropic_audit_log,
    }
    converter = converters.get(platform)
    if not converter:
        raise ValueError(f"Unknown platform: {platform}. Choose: azure, bedrock, anthropic")

    events = []
    with open(artifact_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                # Only convert LLM-related events
                if any(k in ev.get("layer", "") for k in ("llm", "prompt", "echo", "shroud")):
                    events.append(converter(ev))
                elif ev.get("injection_technique_sim") or ev.get("target_model_sim"):
                    events.append(converter(ev))
            except json.JSONDecodeError:
                continue
    return events


def write_platform_logs(
    artifact_path: str,
    output_dir: str,
    platforms: List[str] = None,
    verbose: bool = True,
) -> Dict[str, str]:
    """
    Convert a SHENRON LLM artifact to all platform log formats.

    Args:
        artifact_path: Path to SHENRON LLM JSONL artifact
        output_dir:    Directory for output files
        platforms:     List of platforms (default: all three)
        verbose:       Print summary

    Returns:
        Dict mapping platform -> output path
    """
    platforms = platforms or ["azure", "bedrock", "anthropic"]
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    output_paths = {}

    for platform in platforms:
        events = convert_llm_artifact(artifact_path, platform)
        out_path = out_dir / f"llm_{platform}_logs.jsonl"
        with open(out_path, "w", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")
        output_paths[platform] = str(out_path)

        if verbose:
            print(f"  [{platform.upper():<12}] {len(events)} events -> {out_path}")

    if verbose:
        print()
        print(f"  All events carry simulation_only: true")
        print(f"  Field names match real platform log schemas for SIEM rule development")
        print()

    return output_paths


def print_schema_comparison(event: dict, platform: str) -> None:
    """Print a side-by-side view of SHENRON vs platform fields."""
    converters = {
        "azure":     to_azure_openai_log,
        "bedrock":   to_bedrock_cloudtrail,
        "anthropic": to_anthropic_audit_log,
    }
    converted = converters[platform](event)
    print(f"\n  SHENRON -> {platform.upper()} field mapping sample:")
    mappings = {
        "azure": [
            ("token_count_sim",         "properties_totalTokens_d"),
            ("response_latency_sim",    "DurationMs"),
            ("target_model_sim",        "properties_modelDeploymentName_s"),
            ("injection_technique_sim", "shenron_injection_tech"),
            ("phase",                   "Category"),
        ],
        "bedrock": [
            ("token_count_sim",         "responseElements.outputTokenCount"),
            ("target_model_sim",        "requestParameters.modelId"),
            ("injection_technique_sim", "shenron_injection_tech"),
            ("phase",                   "eventName"),
        ],
        "anthropic": [
            ("token_count_sim",         "usage.input_tokens + usage.output_tokens"),
            ("target_model_sim",        "model"),
            ("response_latency_sim",    "request_latency_ms"),
            ("injection_technique_sim", "shenron_injection_tech"),
            ("phase",                   "shenron_phase"),
        ],
    }
    for src_field, dst_field in mappings.get(platform, []):
        src_val = event.get(src_field, "N/A")
        print(f"  {src_field:<30} -> {dst_field}")
        print(f"    SHENRON: {src_val}")
    print()
