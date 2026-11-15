#!/usr/bin/env python3
"""Matched negative controls for observable-only rules.

Each benign twin carries the same evidence fields as a rule's positive
events, with ordinary values. A behavior-specific rule must stay quiet.

Twins marked NOT_SPECIFIC currently fire: the selection they hit only checks
that fields exist (or matches values benign traffic also has). They are
strict xfails, so making a rule specific turns them into unexpected passes
and CI says so. Until then, these rules must not be described as
behavior-specific detection. See docs/OBSERVABLE_FIELDS.md.
"""
import json
import tempfile
from pathlib import Path

import pytest

from core.sigma.evaluator import evaluate_sigma_rule

RULES = Path(__file__).resolve().parent.parent / "sigma" / "rules"
NOT_SPECIFIC = pytest.mark.xfail(strict=True, reason="selection is presence-only or matches common benign values")

TWINS = [
    pytest.param('shenron_beacon.yml', {'beacon_interval_sim': 3600.0, 'beacon_data': {'method': 'http_get', 'synthetic_url': 'https://updates.vendor.example/v2/check', 'user_agent': 'VendorUpdater/2.1', 'params': {'version': '2.1.0'}, 'synthetic_response_code': 200}}, id='beacon: hourly software update check (HTTPS GET)', marks=NOT_SPECIFIC),
    pytest.param('shenron_beacon.yml', {'beacon_interval_sim': 300.0, 'beacon_data': {'method': 'dns_a', 'synthetic_query': 'www.example.com', 'query_type': 'A', 'synthetic_response': '93.184.216.34', 'ttl_sim': 300}}, id='beacon: resolver refreshing a cached A record', marks=NOT_SPECIFIC),
    pytest.param('shenron_covert_channel.yml', {'channel_type_sim': 'icmp_echo', 'encoding_sim': 'none'}, id='covert_channel: ordinary ping (ICMP echo, no encoding)', marks=NOT_SPECIFIC),
    pytest.param('shenron_covert_channel.yml', {'carrier_protocol_sim': 'https', 'inner_protocol_sim': 'http', 'port_sim': 443}, id='covert_channel: normal HTTPS carrying HTTP', marks=NOT_SPECIFIC),
    pytest.param('shenron_covert_channel.yml', {'listen_port_sim': 443, 'forward_dest_sim': '10.0.0.5', 'forward_port_sim': 8080}, id='covert_channel: reverse proxy forwarding to an internal app', marks=NOT_SPECIFIC),
    pytest.param('shenron_transient_exfil_shell.yml', {'lifecycle_sim': 'persistent', 'listen_backlog_sim': 128, 'bind_addr_sim': '0.0.0.0', 'port_sim': 8080, 'protocol_sim': 'TCP', 'direction_sim': 'inbound'}, id='transient_exfil_shell: long-lived service listener'),
    pytest.param('shenron_transient_exfil_shell.yml', {'remote_addr_sim': '203.0.113.10', 'remote_port_sim': 443, 'data_shape_sim': 'multipart_form_sim', 'data_size_bytes_sim': 2048, 'transfer_duration_sim': 0.4, 'outcome_sim': 'http_200_sim', 'socket_closed_after_sim': True}, id='transient_exfil_shell: routine HTTPS upload that closes its socket', marks=NOT_SPECIFIC),
    pytest.param('shenron_transient_exfil_shell.yml', {'port_released_sim': 8080, 'cleanup_delay_sim': 0.05, 'log_entry_written_sim': True}, id='transient_exfil_shell: service releasing a port on shutdown', marks=NOT_SPECIFIC),
    pytest.param('shenron_llm_manipulation.yml', {'target_model_sim': 'local-ollama-sim', 'token_count_sim': 512, 'response_latency_sim': 0.8}, id='llm_manipulation: ordinary chat completion request', marks=NOT_SPECIFIC),
    pytest.param('shenron_llm_manipulation.yml', {'prompt_shape_sim': 'Summarise this meeting transcript in five bullet points.', 'target_model_sim': 'local-ollama-sim'}, id='llm_manipulation: ordinary prompt with no injection'),
    pytest.param('shenron_llm_manipulation.yml', {'target_log_sim': '/var/log/app/inference.log', 'planned_traces_sim': 100, 'write_interval_sim': 60.0}, id='llm_manipulation: app logger initialising its log file', marks=NOT_SPECIFIC),
    pytest.param('shenron_llm_manipulation.yml', {'label': 'backup_bundle', 'depth': 2, 'overall_entropy_sim': 0.92}, id='llm_manipulation: nested compressed archive', marks=NOT_SPECIFIC),
]


@pytest.mark.parametrize("rule_name, event", TWINS)
def test_benign_twin_does_not_fire(rule_name, event):
    rule = next(RULES.rglob(rule_name))
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        f.write(json.dumps(dict(event, simulation_only=True, executable=False)) + "\n")
        path = f.name
    try:
        assert evaluate_sigma_rule(str(rule), path, match_mode="strict").triggered_count == 0
    finally:
        Path(path).unlink()
