#!/usr/bin/env python3
"""
core/layers/payload_hash_shuffler.py

Professional alias for quantum_state_shuffler.py

This module re-exports everything from the original layer under a
professional name. The original file is preserved for backward
compatibility with existing tests, scenario configs, and the
payload registry.

Layer behavior: see quantum_state_shuffler.py
"""
# Re-export all public symbols from the original
from core.layers.quantum_state_shuffler import *  # noqa: F401, F403
from core.layers.quantum_state_shuffler import main as main  # noqa: F401

# Register under professional name
from core.engine.payload_registry import register_payload
from core.layers.quantum_state_shuffler import main as _quantum_state_shuffler_main

@register_payload(name="payload_hash_shuffler")
def _alias_main():
    return _quantum_state_shuffler_main()
