#!/usr/bin/env python3
"""
core/layers/timestamp_spoof_sim.py

Professional alias for quantum_trace_rewinder.py

This module re-exports everything from the original layer under a
professional name. The original file is preserved for backward
compatibility with existing tests, scenario configs, and the
payload registry.

Layer behavior: see quantum_trace_rewinder.py
"""
# Re-export all public symbols from the original
from core.layers.quantum_trace_rewinder import *  # noqa: F401, F403
from core.layers.quantum_trace_rewinder import main as main  # noqa: F401

# Register under professional name
from core.engine.payload_registry import register_payload
from core.layers.quantum_trace_rewinder import main as _quantum_trace_rewinder_main

@register_payload(name="timestamp_spoof_sim")
def _alias_main():
    return _quantum_trace_rewinder_main()
