# core/schema/validator.py
# Stdlib-only JSON schema validator — no external deps.
from __future__ import annotations
import json
from pathlib import Path
from typing import Any

SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "schemas"


def _load_schema(name: str) -> dict:
    path = SCHEMAS_DIR / name
    return json.loads(path.read_text())


def _check(schema: dict, data: Any, path: str = "") -> list[str]:
    errors = []
    if "type" in schema:
        expected = schema["type"]
        type_map = {
            "object":  dict,
            "array":   list,
            "string":  str,
            "boolean": bool,
            "integer": int,
            "number":  (int, float),
            "null":    type(None),
        }
        checker = type_map.get(expected)
        if checker and not isinstance(data, checker):
            errors.append(f"{path}: expected {expected}, got {type(data).__name__}")
            return errors
    if "const" in schema and data != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}, got {data!r}")
    if "enum" in schema and data not in schema["enum"]:
        errors.append(f"{path}: {data!r} not in enum {schema['enum']}")
    if isinstance(data, dict):
        for key in schema.get("required", []):
            if key not in data:
                errors.append(f"{path}: missing required field '{key}'")
        for key, subschema in schema.get("properties", {}).items():
            if key in data:
                errors.extend(_check(subschema, data[key], f"{path}.{key}"))
    if isinstance(data, list):
        min_items = schema.get("minItems")
        if min_items is not None and len(data) < min_items:
            errors.append(f"{path}: array too short (min {min_items}, got {len(data)})")
        items_schema = schema.get("items")
        if items_schema:
            for i, item in enumerate(data):
                errors.extend(_check(items_schema, item, f"{path}[{i}]"))
    return errors


def validate_event(event: dict) -> list[str]:
    schema = _load_schema("shenron_event.schema.json")
    return _check(schema, event, "event")


def validate_safety_contract(event: dict) -> list[str]:
    schema = _load_schema("safety_contract.schema.json")
    return _check(schema, event, "event")


def validate_events_file(events_path: str) -> dict:
    path = Path(events_path)
    if not path.exists():
        return {"ok": False, "error": f"File not found: {events_path}", "events": 0, "failures": []}
    events = []
    parse_errors = []
    for i, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            events.append((i, json.loads(line)))
        except json.JSONDecodeError as e:
            parse_errors.append(f"line {i}: JSON parse error: {e}")
    failures = list(parse_errors)
    for lineno, event in events:
        for e in validate_event(event):
            failures.append(f"line {lineno}: {e}")
    return {"ok": len(failures) == 0, "events": len(events), "failures": failures}
