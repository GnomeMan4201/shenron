#!/usr/bin/env python3
from typing import Callable, Dict, Optional
_REGISTRY: Dict[str, Callable] = {}

def register_payload(name: str):
    def decorator(fn: Callable) -> Callable:
        _REGISTRY[name] = fn
        return fn
    return decorator

def get(name): return _REGISTRY.get(name)
def list_registered(): return sorted(_REGISTRY.keys())
def run(name, **kwargs):
    fn = get(name)
    if fn is None: return None
    try:
        fn(**kwargs)
        return True
    except Exception as e:
        print(f"[!] {name}: {e}")
        return False
def clear(): _REGISTRY.clear()
