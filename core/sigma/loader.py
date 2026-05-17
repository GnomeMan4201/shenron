import json, re
from pathlib import Path
from typing import Dict, Any, List


def _load_yaml_simple(path: Path) -> dict:
    """Minimal YAML loader for Sigma rules — no external deps."""
    text = path.read_text()
    result = {}
    current_key = None
    current_list = None
    detection_block = False
    detection_data = {}
    condition_str = None

    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        indent = len(line) - len(line.lstrip())

        if indent == 0 and ":" in stripped:
            k, _, v = stripped.partition(":")
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k == "detection":
                detection_block = True
                current_key = "detection"
                i += 1
                continue
            elif detection_block and k not in ("title","id","status","description",
                                                "author","tags","logsource",
                                                "falsepositives","level","fields"):
                pass
            else:
                detection_block = False
            if v:
                result[k] = v
            current_key = k
            current_list = None

        elif detection_block:
            # Parse detection sub-block
            if indent == 4 and ":" in stripped:
                k, _, v = stripped.partition(":")
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k == "condition":
                    condition_str = v
                elif v:
                    detection_data[k] = v
                else:
                    detection_data[k] = {}
                current_key = k
            elif indent == 8 and current_key in detection_data:
                if ":" in stripped:
                    k2, _, v2 = stripped.partition(":")
                    k2 = k2.strip()
                    v2 = v2.strip().strip('"').strip("'")
                    if isinstance(detection_data[current_key], dict):
                        detection_data[current_key][k2] = v2
                elif stripped.startswith("- "):
                    val = stripped[2:].strip().strip('"').strip("'")
                    if not isinstance(detection_data[current_key], list):
                        detection_data[current_key] = []
                    detection_data[current_key].append(val)
            elif indent == 4 and stripped.startswith("- "):
                val = stripped[2:].strip().strip('"').strip("'")
                if isinstance(detection_data.get(current_key), list):
                    detection_data[current_key].append(val)

        elif indent == 4 and current_key:
            if stripped.startswith("- "):
                val = stripped[2:].strip().strip('"').strip("'")
                if current_key not in result or not isinstance(result[current_key], list):
                    result[current_key] = []
                result[current_key].append(val)
            elif ":" in stripped:
                k, _, v = stripped.partition(":")
                if not isinstance(result.get(current_key), dict):
                    result[current_key] = {}
                result[current_key][k.strip()] = v.strip().strip('"').strip("'")

        i += 1

    result["detection"] = detection_data
    if condition_str:
        result["condition"] = condition_str
    return result


def load_sigma_rule(path) -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Sigma rule not found: {path}")
    data = _load_yaml_simple(p)
    data["_path"] = str(p)
    return data


def load_artifacts(path) -> list:
    p = Path(path)
    if not p.exists():
        return []
    records = []
    with open(p) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records
