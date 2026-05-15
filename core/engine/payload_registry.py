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
def _log_execution(name, status, notes=""):
    try:
        import importlib.util, os
        spec = importlib.util.spec_from_file_location(
            "mutation_history",
            os.path.join(os.path.dirname(__file__), "../layers/mutation_history.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        score = "100" if status == "executed" else "0"
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
