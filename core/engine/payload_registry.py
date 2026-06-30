#!/usr/bin/env python3
from typing import Callable, Dict, Optional
_REGISTRY: Dict[str, Callable] = {}

def register_payload(name: str, **kwargs):
    def decorator(fn: Callable) -> Callable:
        _REGISTRY[name] = fn
        return fn
    return decorator

def get(name): return _REGISTRY.get(name)
def list_registered(): return sorted(_REGISTRY.keys())
def get_layer_names() -> list: return sorted(_REGISTRY.keys())
def get_registered_layers() -> dict: return dict(_REGISTRY)
def _log_execution(name, status, notes=""):
    try:
        import importlib.util, os
        spec = importlib.util.spec_from_file_location(
            "mutation_history",
            os.path.join(os.path.dirname(__file__), "../layers/mutation_history.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if status == "executed":
            try:
                from core.validation.stealth_scorer import score_layer_from_log
                computed = score_layer_from_log(name)
                score = str(computed) if computed >= 0 else "0"
            except Exception:
                score = "0"
        else:
            score = "0"
        mod.log_mutation(name, status, score, notes)
    except Exception:
        pass

def run(name, **kwargs):
    fn = get(name)
    if fn is None: return None
    try:
        fn(**kwargs)
        _log_execution(name, "executed")
        return True
    except Exception as e:
        _log_execution(name, "exec_failed", str(e))
        print(f"[!] {name}: {e}")
        return False
def clear(): _REGISTRY.clear()
