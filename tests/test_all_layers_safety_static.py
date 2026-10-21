# tests/test_all_layers_safety_static.py
# Static safety audit across all canonical layers.
#
# AST-based: parses each layer and inspects real imports and calls, so forbidden
# tokens inside strings, comments, or field names never produce false positives,
# and the check cannot be evaded by a token the old substring scan missed. This
# gate is a lint for *accidental* unsafe patterns in first-party layer source. It
# is NOT a sandbox and does not contain adversarial/malicious code — a layer that
# deliberately builds a forbidden name dynamically (getattr/__getattribute__ on a
# runtime string) is out of scope and would need runtime isolation to stop.

import ast
from pathlib import Path

from core.engine.layer_loader import discover_canonical

# Importing any of these modules is forbidden in a canonical layer.
FORBIDDEN_IMPORT_ROOTS = {
    "subprocess", "socket", "shutil", "ctypes", "importlib", "marshal", "pty",
}
# from os import <name> — these names are process/shell escapes.
FORBIDDEN_OS_NAMES = {"system", "popen", "fork", "forkpty"}
# Bare builtin calls that execute or import dynamically.
FORBIDDEN_CALL_NAMES = {"eval", "exec", "compile", "__import__"}
# <root>.<attr>(...) calls that are process / network / fs escapes.
FORBIDDEN_ATTR_CALLS = {
    ("os", "system"), ("os", "popen"), ("os", "fork"), ("os", "forkpty"),
    ("subprocess", "run"), ("subprocess", "Popen"), ("subprocess", "call"),
    ("subprocess", "check_output"), ("subprocess", "check_call"), ("subprocess", "getoutput"),
    ("socket", "socket"), ("socket", "create_connection"),
    ("shutil", "copy"), ("shutil", "copy2"), ("shutil", "copyfile"), ("shutil", "move"),
}


def _root_name(node):
    """Dotted root of an attribute chain: os.path.join -> 'os'. None if not a plain name."""
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def scan_source(source: str, label: str):
    """Return a list of human-readable safety violations for one layer source."""
    violations = []
    try:
        tree = ast.parse(source, filename=label)
    except SyntaxError as e:
        return [f"{label}: unparseable ({e})"]

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in FORBIDDEN_IMPORT_ROOTS:
                    violations.append(f"{label}:{node.lineno}: forbidden import '{alias.name}'")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in FORBIDDEN_IMPORT_ROOTS:
                violations.append(f"{label}:{node.lineno}: forbidden import from '{node.module}'")
            if root == "os":
                for alias in node.names:
                    if alias.name in FORBIDDEN_OS_NAMES or alias.name.startswith(("exec", "spawn")):
                        violations.append(f"{label}:{node.lineno}: forbidden 'from os import {alias.name}'")
        elif isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in FORBIDDEN_CALL_NAMES:
                violations.append(f"{label}:{node.lineno}: forbidden call '{fn.id}(...)'")
            elif isinstance(fn, ast.Attribute):
                root = _root_name(fn)
                attr = fn.attr
                if root == "os" and attr.startswith(("exec", "spawn")):
                    violations.append(f"{label}:{node.lineno}: forbidden call 'os.{attr}(...)'")
                elif (root, attr) in FORBIDDEN_ATTR_CALLS:
                    violations.append(f"{label}:{node.lineno}: forbidden call '{root}.{attr}(...)'")
    return violations


def test_all_canonical_layers_pass_static_safety():
    canonical = discover_canonical()
    assert len(canonical) > 0, "No canonical layers found"

    violations = []
    for layer_type, path in canonical.items():
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            violations.append(f"{layer_type}: could not read file: {e}")
            continue
        violations.extend(scan_source(source, f"{layer_type} ({path.name})"))

    if violations:
        print(f"\n  STATIC SAFETY VIOLATIONS ({len(violations)}):")
        for v in violations:
            print(f"    {v}")

    assert not violations, (
        f"{len(violations)} static safety violation(s) found in canonical layers. "
        "See output above."
    )


def test_canonical_layer_count():
    canonical = discover_canonical()
    assert len(canonical) >= 51, f"Expected >= 51 canonical layers, got {len(canonical)}"


def test_all_canonical_layers_readable():
    canonical = discover_canonical()
    for layer_type, path in canonical.items():
        assert path.exists(), f"Layer file not found: {path}"
        source = path.read_text(encoding="utf-8", errors="replace")
        assert len(source) > 0, f"Layer file empty: {path}"
