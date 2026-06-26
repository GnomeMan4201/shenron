#!/usr/bin/env python3
"""
core/layers/device_fingerprint_spoof.py

Professional alias for shenron_bio_replication.py

This module re-exports everything from the original layer under a
professional name. The original file is preserved for backward
compatibility with existing tests, scenario configs, and the
payload registry.

Layer behavior: see shenron_bio_replication.py
"""
# Re-export all public symbols from the original
from core.layers.shenron_bio_replication import *  # noqa: F401, F403
from core.layers.shenron_bio_replication import main as main  # noqa: F401

# Register under professional name
from core.engine.payload_registry import register_payload
from core.layers.shenron_bio_replication import main as _shenron_bio_replication_main

@register_payload(name="device_fingerprint_spoof")
def _alias_main():
    return _shenron_bio_replication_main()
