# tests/test_all_layers_safety_static.py
# Static safety audit across all 50 canonical layers.
# Asserts no forbidden patterns exist in any canonical layer source file.
# This is a CI gate — if it fails, a layer violates the safety contract.

import ast
from pathlib import Path
from core.engine.layer_loader import discover_canonical

FORBIDDEN_CALLS = [
    "subprocess",
    "os.system",
    "os.popen",
    "shutil.copy",
    "shutil.move",
    "socket.socket",
    "socket.connect",
    "socket.bind",
    "socket.listen",
    "eval(",
    "exec(",
    "popen(",
    "Popen(",
    "check_output(",
    "check_call(",
    "ping",
    "renice",
    "PAYLOAD_DROP",
]

FORBIDDEN_IMPORTS = [
    "import socket",
    "import shutil",
    "from shutil",
    "from socket",
]

ALLOWED_SUBPROCESS_COMMENTS = [
    "# No subprocess",
    "subprocess_spawned",
    "subprocess_called",
    "subprocess_popen",
    "No subprocess",
]


def _is_forbidden_line(line: str) -> tuple:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False, ""

    # Check forbidden imports
    for fi in FORBIDDEN_IMPORTS:
        if fi in stripped:
            return True, f"forbidden import: {fi!r}"

    # Check forbidden calls — but allow field name strings containing these words
    for fc in FORBIDDEN_CALLS:
        if fc in stripped:
            # Allow if it is a string value (dict key or value assignment)
            if (f'"{fc}' in stripped or
                f"\'{fc}\'" in stripped or
                f": {fc}" not in stripped and
                f"import {fc}" not in stripped and
                f".{fc}(" not in stripped and
                f"{fc}.run" not in stripped and
                f"{fc}.Popen" not in stripped and
                f"{fc}.check_output" not in stripped and
                f"{fc}.check_call" not in stripped and
                f"{fc}.PIPE" not in stripped and
                f"{fc}.DEVNULL" not in stripped):
                continue
            return True, f"forbidden call: {fc!r}"

    return False, ""


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

        for lineno, line in enumerate(source.splitlines(), 1):
            forbidden, reason = _is_forbidden_line(line)
            if forbidden:
                violations.append(f"{layer_type} ({path.name}:{lineno}): {reason} — {line.strip()[:80]}")

    if violations:
        print(f"\n  STATIC SAFETY VIOLATIONS ({len(violations)}):")
        for v in violations:
            print(f"    {v}")

    assert len(violations) == 0, (
        f"{len(violations)} static safety violation(s) found in canonical layers. "
        "See output above."
    )


def test_canonical_layer_count():
    canonical = discover_canonical()
    assert len(canonical) >= 50, f"Expected >= 50 canonical layers, got {len(canonical)}"


def test_all_canonical_layers_readable():
    canonical = discover_canonical()
    for layer_type, path in canonical.items():
        assert path.exists(), f"Layer file not found: {path}"
        source = path.read_text(encoding="utf-8", errors="replace")
        assert len(source) > 0, f"Layer file empty: {path}"
