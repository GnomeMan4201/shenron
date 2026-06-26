#!/usr/bin/env python3
"""
core/layers/covert_socket_relay.py

Professional alias for quantum_entanglement_relay.py

This module re-exports everything from the original layer under a
professional name. The original file is preserved for backward
compatibility with existing tests, scenario configs, and the
payload registry.

Layer behavior: see quantum_entanglement_relay.py
"""
# Re-export all public symbols from the original
from core.layers.quantum_entanglement_relay import *  # noqa: F401, F403
from core.layers.quantum_entanglement_relay import main as main  # noqa: F401

# Register under professional name
from core.engine.payload_registry import register_payload
from core.layers.quantum_entanglement_relay import main as _quantum_entanglement_relay_main

@register_payload(name="covert_socket_relay")
def _alias_main():
    return _quantum_entanglement_relay_main()
