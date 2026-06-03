"""
core/taxonomy.py

SHENRON MITRE ATT&CK taxonomy loader.

Single source of truth for layer → technique mappings.
Reads from taxonomy/mitre_mappings.json.

Usage in layer files:
    from core.taxonomy import get_techniques
    techniques = get_techniques("dormant_sleeper_seed")
    # returns ["T1053", "T1547"]

Usage in manifest/validation:
    from core.taxonomy import load_taxonomy, get_all_mappings
    taxonomy = load_taxonomy()

Custom taxonomy (for specialized environments):
    SHENRON_TAXONOMY_PATH=/path/to/custom_mappings.json python3 shenron.py ...
"""

import json
import os
from pathlib import Path
from typing import Optional

# Default taxonomy path — relative to repo root
_DEFAULT_TAXONOMY_PATH = Path(__file__).parent.parent / "taxonomy" / "mitre_mappings.json"

# Cache — loaded once per process
_cache: Optional[dict] = None


def _taxonomy_path() -> Path:
    """Return taxonomy file path, respecting SHENRON_TAXONOMY_PATH env var."""
    env = os.environ.get("SHENRON_TAXONOMY_PATH")
    if env:
        return Path(env)
    return _DEFAULT_TAXONOMY_PATH


def load_taxonomy(force_reload: bool = False) -> dict:
    """
    Load and return the full taxonomy dict.
    Cached after first load. Set force_reload=True to re-read from disk.

    Returns:
        {
            "_meta": { ... },
            "layers": {
                "layer_name": {
                    "techniques": ["T1053", "T1547"],
                    "tactic": "persistence"
                },
                ...
            }
        }
    """
    global _cache
    if _cache is not None and not force_reload:
        return _cache

    path = _taxonomy_path()
    if not path.exists():
        raise FileNotFoundError(
            f"Taxonomy file not found: {path}\n"
            f"Run: python3 shenron.py taxonomy init  (or check SHENRON_TAXONOMY_PATH)"
        )

    _cache = json.loads(path.read_text(encoding="utf-8"))
    return _cache


def get_techniques(layer_name: str, default: Optional[list] = None) -> list:
    """
    Return technique list for a layer.

    Args:
        layer_name: canonical layer name (e.g. "dormant_sleeper_seed")
        default: returned if layer not in taxonomy (default: [])

    Returns:
        list of technique ID strings e.g. ["T1053", "T1547"]
    """
    if default is None:
        default = []
    try:
        taxonomy = load_taxonomy()
        entry = taxonomy.get("layers", {}).get(layer_name, {})
        return entry.get("techniques", default)
    except FileNotFoundError:
        return default


def get_tactic(layer_name: str, default: str = "") -> str:
    """Return tactic string for a layer."""
    try:
        taxonomy = load_taxonomy()
        entry = taxonomy.get("layers", {}).get(layer_name, {})
        return entry.get("tactic", default)
    except FileNotFoundError:
        return default


def get_all_mappings() -> dict:
    """Return the full layer → {techniques, tactic} mapping dict."""
    try:
        return load_taxonomy().get("layers", {})
    except FileNotFoundError:
        return {}


def get_all_techniques() -> set:
    """Return the set of all unique technique IDs across all layers."""
    mappings = get_all_mappings()
    return {t for entry in mappings.values() for t in entry.get("techniques", [])}


def layer_count() -> int:
    """Return number of layers with technique mappings."""
    return len(get_all_mappings())


def technique_count() -> int:
    """Return total number of technique mappings (not unique)."""
    mappings = get_all_mappings()
    return sum(len(v.get("techniques", [])) for v in mappings.values())


def validate_taxonomy() -> list[str]:
    """
    Validate taxonomy file structure.
    Returns list of error strings (empty = valid).
    """
    errors = []
    try:
        taxonomy = load_taxonomy()
    except FileNotFoundError as e:
        return [str(e)]
    except json.JSONDecodeError as e:
        return [f"Taxonomy file is malformed JSON: {e}"]

    layers = taxonomy.get("layers", {})
    if not layers:
        errors.append("No layers found in taxonomy file")
        return errors

    for name, entry in layers.items():
        if not isinstance(entry, dict):
            errors.append(f"{name}: entry must be a dict")
            continue
        techs = entry.get("techniques", [])
        if not isinstance(techs, list):
            errors.append(f"{name}: techniques must be a list")
        for t in techs:
            if not isinstance(t, str) or not t.startswith("T"):
                errors.append(f"{name}: invalid technique ID '{t}'")

    return errors
