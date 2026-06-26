#!/usr/bin/env python3
"""
core/layers/process_masquerade_sim.py

Professional alias for shenron_holo_emitter.py

This module re-exports everything from the original layer under a
professional name. The original file is preserved for backward
compatibility with existing tests, scenario configs, and the
payload registry.

Layer behavior: see shenron_holo_emitter.py
"""
# Re-export all public symbols from the original
from core.layers.shenron_holo_emitter import *  # noqa: F401, F403
from core.layers.shenron_holo_emitter import main as main  # noqa: F401

# Register under professional name
from core.engine.payload_registry import register_payload
from core.layers.shenron_holo_emitter import main as _shenron_holo_emitter_main

@register_payload(name="process_masquerade_sim")
def _alias_main():
    return _shenron_holo_emitter_main()
