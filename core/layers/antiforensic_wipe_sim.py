#!/usr/bin/env python3
"""
core/layers/antiforensic_wipe_sim.py

Professional alias for dragons_breath_destructor.py

This module re-exports everything from the original layer under a
professional name. The original file is preserved for backward
compatibility with existing tests, scenario configs, and the
payload registry.

Layer behavior: see dragons_breath_destructor.py
"""
# Re-export all public symbols from the original
from core.layers.dragons_breath_destructor import *  # noqa: F401, F403
from core.layers.dragons_breath_destructor import main as main  # noqa: F401

# Register under professional name
from core.engine.payload_registry import register_payload
from core.layers.dragons_breath_destructor import main as _dragons_breath_destructor_main

@register_payload(name="antiforensic_wipe_sim")
def _alias_main():
    return _dragons_breath_destructor_main()
