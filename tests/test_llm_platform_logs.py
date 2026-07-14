"""
tests/test_llm_platform_logs.py

Tests for core/formats/llm_platform_logs.py — LLM platform log schema mapper.
"""
import json
import tempfile
from pathlib import Path
import pytest
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.formats.llm_platform_logs import (
    to_azure_openai_log,
    to_bedrock_cloudtrail,
    to_anthropic_audit_log,
    convert_llm_artifact,
    write_platform_logs,
)

LLM_ARTIFACT = Path(__file__).parent.parent / "artifacts" / "llm_manipulation" / "scenario_run.jsonl"

SAMPLE_LLM_EVENT = {
    "artifact_id": "test-llm-001",
    "session_id": "sess-llm-001",
    "layer": "llm_prompt_injector",
    "phase": "INJECTION_ATTEMPT",
    "behavior_class": "role_boundary_violation_sim",
    "signal": "role_boundary_violation_sim",
    "injection_technique_sim": "role_override_sim",
    "target_model_sim": "gpt-4-sim",
    "token_count_sim": 1024,
    "response_latency_sim": 2.5,
    "mitre_techniques": ["T1059.007", "T1190"],
    "detection_opportunities": ["prompt_role_boundary_violation"],
    "simulation_only": True,
    "executable": False,
    "payload_present": False,
    "timestamp": "2026-06-25T12:00:00+00:00",
}

SAMPLE_ECHO_EVENT = {
    "artifact_id": "test-echo-001",
    "session_id": "sess-echo-001",
    "layer": "llm_echo_chamber",
    "phase": "hallucination_trace_sim",
    "behavior_class": "llm_hallucination_trace_inject_sim",
    "token_count_sim": 512,
    "response_latency_sim": 1.2,
    "mitre_techniques": ["T1565", "T1036"],
    "detection_opportunities": ["llm_format_log_entries_from_non_llm_process"],
    "simulation_only": True,
    "executable": False,
    "payload_present": False,
    "timestamp": "2026-06-25T12:01:00+00:00",
}


# -- Azure OpenAI log ----------------------------------------------------------

def test_azure_has_time_generated():
    ev = to_azure_openai_log(SAMPLE_LLM_EVENT)
    assert "TimeGenerated" in ev

def test_azure_has_operation_name():
    ev = to_azure_openai_log(SAMPLE_LLM_EVENT)
    assert ev["OperationName"] == "ChatCompletions_Create"

def test_azure_has_result_type():
    ev = to_azure_openai_log(SAMPLE_LLM_EVENT)
    assert ev["ResultType"] in ("Success", "ContentFilter", "Error")

def test_azure_role_override_is_content_filter():
    ev = to_azure_openai_log(SAMPLE_LLM_EVENT)
    assert ev["ResultType"] == "ContentFilter"
    assert ev["properties_finishReason_s"] == "content_filter"

def test_azure_token_fields():
    ev = to_azure_openai_log(SAMPLE_LLM_EVENT)
    assert "properties_totalTokens_d" in ev
    assert "properties_promptTokens_d" in ev
    assert "properties_completionTokens_d" in ev
    total = ev["properties_promptTokens_d"] + ev["properties_completionTokens_d"]
    assert abs(total - ev["properties_totalTokens_d"]) < 2

def test_azure_model_deployment_name():
    ev = to_azure_openai_log(SAMPLE_LLM_EVENT)
    assert "properties_modelDeploymentName_s" in ev
    assert ev["properties_modelDeploymentName_s"] == "gpt-4-sim"

def test_azure_duration_ms():
    ev = to_azure_openai_log(SAMPLE_LLM_EVENT)
    assert ev["DurationMs"] == int(2.5 * 1000)

def test_azure_shenron_provenance():
    ev = to_azure_openai_log(SAMPLE_LLM_EVENT)
    assert ev["shenron_layer"] == "llm_prompt_injector"
    assert ev["shenron_injection_tech"] == "role_override_sim"
    assert "T1059.007" in ev["shenron_mitre_techniques"]

def test_azure_simulation_only():
    ev = to_azure_openai_log(SAMPLE_LLM_EVENT)
    assert ev["simulation_only"] is True
    assert ev["executable"] is False
    assert ev["payload_present"] is False

def test_azure_schema_identifier():
    ev = to_azure_openai_log(SAMPLE_LLM_EVENT)
    assert ev["_shenron_schema"] == "azure_openai_diagnostic_v1"

def test_azure_level_warning_for_content_filter():
    ev = to_azure_openai_log(SAMPLE_LLM_EVENT)
    assert ev["Level"] == "Warning"

def test_azure_level_info_for_success():
    benign_event = dict(SAMPLE_LLM_EVENT)
    benign_event["injection_technique_sim"] = "indirect_injection_sim"
    ev = to_azure_openai_log(benign_event)
    assert ev["Level"] == "Information"


# -- AWS Bedrock CloudTrail ----------------------------------------------------

def test_bedrock_event_source():
    ev = to_bedrock_cloudtrail(SAMPLE_LLM_EVENT)
    assert ev["eventSource"] == "bedrock.amazonaws.com"

def test_bedrock_event_name():
    ev = to_bedrock_cloudtrail(SAMPLE_LLM_EVENT)
    assert ev["eventName"] == "InvokeModel"

def test_bedrock_has_request_parameters():
    ev = to_bedrock_cloudtrail(SAMPLE_LLM_EVENT)
    assert "requestParameters" in ev
    assert "modelId" in ev["requestParameters"]

def test_bedrock_role_override_error():
    ev = to_bedrock_cloudtrail(SAMPLE_LLM_EVENT)
    assert ev["errorCode"] == "ValidationException"

def test_bedrock_user_identity():
    ev = to_bedrock_cloudtrail(SAMPLE_LLM_EVENT)
    assert "userIdentity" in ev
    assert ev["userIdentity"]["type"] == "AssumedRole"

def test_bedrock_event_time():
    ev = to_bedrock_cloudtrail(SAMPLE_LLM_EVENT)
    assert ev["eventTime"] == "2026-06-25T12:00:00+00:00"

def test_bedrock_shenron_provenance():
    ev = to_bedrock_cloudtrail(SAMPLE_LLM_EVENT)
    assert ev["shenron_layer"] == "llm_prompt_injector"
    assert ev["shenron_injection_tech"] == "role_override_sim"

def test_bedrock_simulation_only():
    ev = to_bedrock_cloudtrail(SAMPLE_LLM_EVENT)
    assert ev["simulation_only"] is True

def test_bedrock_schema_identifier():
    ev = to_bedrock_cloudtrail(SAMPLE_LLM_EVENT)
    assert ev["_shenron_schema"] == "aws_bedrock_cloudtrail_v1"

def test_bedrock_exfil_phase_invoke_model():
    exfil_event = dict(SAMPLE_LLM_EVENT)
    exfil_event["phase"] = "EXFILTRATE"
    exfil_event["injection_technique_sim"] = "llm_output_poisoning_sim"
    ev = to_bedrock_cloudtrail(exfil_event)
    assert ev["eventName"] == "InvokeModel"
    assert ev["errorCode"] is None


# -- Anthropic audit log -------------------------------------------------------

def test_anthropic_type():
    ev = to_anthropic_audit_log(SAMPLE_LLM_EVENT)
    assert ev["type"] == "message"

def test_anthropic_has_model():
    ev = to_anthropic_audit_log(SAMPLE_LLM_EVENT)
    assert "model" in ev
    assert "claude" in ev["model"]

def test_anthropic_usage_fields():
    ev = to_anthropic_audit_log(SAMPLE_LLM_EVENT)
    usage = ev["usage"]
    assert "input_tokens" in usage
    assert "output_tokens" in usage
    assert usage["input_tokens"] + usage["output_tokens"] == 1024

def test_anthropic_stop_reason_role_override():
    ev = to_anthropic_audit_log(SAMPLE_LLM_EVENT)
    assert ev["stop_reason"] == "stop_sequence"

def test_anthropic_stop_reason_normal():
    normal = dict(SAMPLE_LLM_EVENT)
    normal["injection_technique_sim"] = "indirect_injection_sim"
    ev = to_anthropic_audit_log(normal)
    assert ev["stop_reason"] == "end_turn"

def test_anthropic_has_request():
    ev = to_anthropic_audit_log(SAMPLE_LLM_EVENT)
    assert "request" in ev
    assert "messages" in ev["request"]

def test_anthropic_latency_ms():
    ev = to_anthropic_audit_log(SAMPLE_LLM_EVENT)
    assert ev["request_latency_ms"] == 2500

def test_anthropic_shenron_provenance():
    ev = to_anthropic_audit_log(SAMPLE_LLM_EVENT)
    assert ev["shenron_injection_tech"] == "role_override_sim"

def test_anthropic_simulation_only():
    ev = to_anthropic_audit_log(SAMPLE_LLM_EVENT)
    assert ev["simulation_only"] is True

def test_anthropic_schema_identifier():
    ev = to_anthropic_audit_log(SAMPLE_LLM_EVENT)
    assert ev["_shenron_schema"] == "anthropic_audit_log_v1"


# -- Artifact conversion -------------------------------------------------------

def test_convert_artifact_azure():
    if not LLM_ARTIFACT.exists():
        pytest.skip("LLM artifact not present")
    events = convert_llm_artifact(str(LLM_ARTIFACT), "azure")
    assert len(events) > 0
    for ev in events:
        assert ev["_shenron_schema"] == "azure_openai_diagnostic_v1"
        assert ev["simulation_only"] is True

def test_convert_artifact_bedrock():
    if not LLM_ARTIFACT.exists():
        pytest.skip("LLM artifact not present")
    events = convert_llm_artifact(str(LLM_ARTIFACT), "bedrock")
    assert len(events) > 0
    for ev in events:
        assert ev["eventSource"] == "bedrock.amazonaws.com"

def test_convert_artifact_anthropic():
    if not LLM_ARTIFACT.exists():
        pytest.skip("LLM artifact not present")
    events = convert_llm_artifact(str(LLM_ARTIFACT), "anthropic")
    assert len(events) > 0
    for ev in events:
        assert ev["type"] == "message"

def test_convert_artifact_invalid_platform():
    if not LLM_ARTIFACT.exists():
        pytest.skip("LLM artifact not present")
    with pytest.raises(ValueError):
        convert_llm_artifact(str(LLM_ARTIFACT), "gcp")

def test_convert_artifact_count():
    if not LLM_ARTIFACT.exists():
        pytest.skip("LLM artifact not present")
    azure = convert_llm_artifact(str(LLM_ARTIFACT), "azure")
    bedrock = convert_llm_artifact(str(LLM_ARTIFACT), "bedrock")
    anthropic = convert_llm_artifact(str(LLM_ARTIFACT), "anthropic")
    assert len(azure) == len(bedrock) == len(anthropic)


# -- Write platform logs -------------------------------------------------------

def test_write_platform_logs_creates_files():
    if not LLM_ARTIFACT.exists():
        pytest.skip("LLM artifact not present")
    with tempfile.TemporaryDirectory() as d:
        paths = write_platform_logs(str(LLM_ARTIFACT), d, verbose=False)
        for platform, path in paths.items():
            assert Path(path).exists(), f"Missing: {path}"

def test_write_platform_logs_valid_jsonl():
    if not LLM_ARTIFACT.exists():
        pytest.skip("LLM artifact not present")
    with tempfile.TemporaryDirectory() as d:
        paths = write_platform_logs(str(LLM_ARTIFACT), d, verbose=False)
        for platform, path in paths.items():
            with open(path) as f:
                lines = [json.loads(l) for l in f if l.strip()]
            assert len(lines) > 0

def test_write_platform_logs_returns_dict():
    if not LLM_ARTIFACT.exists():
        pytest.skip("LLM artifact not present")
    with tempfile.TemporaryDirectory() as d:
        paths = write_platform_logs(str(LLM_ARTIFACT), d, verbose=False)
        assert "azure" in paths
        assert "bedrock" in paths
        assert "anthropic" in paths

def test_write_platform_logs_single_platform():
    if not LLM_ARTIFACT.exists():
        pytest.skip("LLM artifact not present")
    with tempfile.TemporaryDirectory() as d:
        paths = write_platform_logs(
            str(LLM_ARTIFACT), d,
            platforms=["azure"],
            verbose=False
        )
        assert "azure" in paths
        assert "bedrock" not in paths
