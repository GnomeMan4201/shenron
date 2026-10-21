# tests/test_all_layers_safety_static.py
# Static safety audit across all canonical layers.
#
# AST-based: parses each layer and inspects real imports and calls, so forbidden
# tokens inside strings, comments, or field names never produce false positives,
# and the check cannot be evaded by import aliasing (`import os as x; x.system()`).
# This gate is a lint for *accidental* unsafe patterns in first-party layer
# source. It is NOT a sandbox: a layer that builds a forbidden name from a runtime
# string (`getattr(os, "sys"+"tem")`) is out of scope and needs runtime isolation.

import ast

import pytest

from core.engine.layer_loader import discover_canonical

# Importing any of these modules is forbidden in a canonical layer.
FORBIDDEN_IMPORT_ROOTS = {
    "subprocess", "socket", "shutil", "ctypes", "importlib", "marshal", "pty",
}
# from os import <name> — these names are process/shell escapes.
FORBIDDEN_OS_NAMES = {"system", "popen", "fork", "forkpty"}
# Bare builtin calls that execute or import dynamically.
FORBIDDEN_CALL_NAMES = {"eval", "exec", "compile", "__import__"}
# <module>.<attr>(...) calls that are process / network / fs escapes. The module
# is the RESOLVED import name, so aliases are checked against these too.
FORBIDDEN_ATTR_CALLS = {
    ("os", "system"), ("os", "popen"), ("os", "fork"), ("os", "forkpty"),
    ("subprocess", "run"), ("subprocess", "Popen"), ("subprocess", "call"),
    ("subprocess", "check_output"), ("subprocess", "check_call"), ("subprocess", "getoutput"),
    ("socket", "socket"), ("socket", "create_connection"),
    ("shutil", "copy"), ("shutil", "copy2"), ("shutil", "copyfile"), ("shutil", "move"),
}


def _base_name(node):
    """Base name of an attribute chain: os.path.join -> 'os'. None if not a plain name."""
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

    # Pass 1: imports + an alias map {local_name -> real module root}.
    alias_map = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                real_root = alias.name.split(".")[0]
                local = alias.asname or real_root
                alias_map[local] = real_root
                if real_root in FORBIDDEN_IMPORT_ROOTS:
                    violations.append(f"{label}:{node.lineno}: forbidden import '{alias.name}'")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in FORBIDDEN_IMPORT_ROOTS:
                violations.append(f"{label}:{node.lineno}: forbidden import from '{node.module}'")
            if root == "os":
                for alias in node.names:
                    if alias.name in FORBIDDEN_OS_NAMES or alias.name.startswith(("exec", "spawn")):
                        violations.append(f"{label}:{node.lineno}: forbidden 'from os import {alias.name}'")

    # Pass 2: calls, resolving the base name through the alias map.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id in FORBIDDEN_CALL_NAMES:
            violations.append(f"{label}:{node.lineno}: forbidden call '{fn.id}(...)'")
        elif isinstance(fn, ast.Attribute):
            base = _base_name(fn)
            real = alias_map.get(base, base)
            attr = fn.attr
            if real == "os" and attr.startswith(("exec", "spawn")):
                violations.append(f"{label}:{node.lineno}: forbidden call 'os.{attr}(...)'")
            elif (real, attr) in FORBIDDEN_ATTR_CALLS:
                violations.append(f"{label}:{node.lineno}: forbidden call '{real}.{attr}(...)'")
    return violations


# ── Scanner regression cases: lock in what the gate must catch / must ignore ──
_DETECT_CASES = [
    ("import subprocess", True),
    ("import subprocess as sp\nsp.run(['x'])", True),
    ("import os as operating_system\noperating_system.system('x')", True),   # alias bypass
    ("import os\nos.system('x')", True),
    ("import os\nos.execv('/bin/sh', [])", True),
    ("from os import system\nsystem('x')", True),
    ("from os import system as s\ns('x')", True),
    ("m = __import__('subprocess')", True),
    ("import ctypes", True),
    ("import importlib", True),
    ("import marshal", True),
    ("eval('1')", True),
    ("exec('x')", True),
    ("import socket as net\nnet.socket()", True),
    ("import os\nq = os.path.join('a', 'b')", False),                        # allowed os use
    ("note = {'k': 'no subprocess or os.system here'}", False),             # word in a string
    ("import json\njson.dumps({})", False),
]


@pytest.mark.parametrize("src,should_flag", _DETECT_CASES)
def test_scanner_detection(src, should_flag):
    flagged = bool(scan_source(src, "case"))
    assert flagged == should_flag, f"{src!r} -> {scan_source(src, 'case')}"


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
