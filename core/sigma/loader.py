import json
from pathlib import Path


def load_sigma_rule(path) -> dict:
    """
    Load a Sigma rule YAML file.
    Uses PyYAML for correct nested detection block parsing.
    The hand-rolled parser could not handle multi-level selection blocks
    and was silently flattening nested selection blocks to top-level keys.
    """
    try:
        import yaml
    except ImportError:
        raise ImportError(
            "PyYAML is required for Sigma rule loading. "
            "Run: pip install pyyaml --break-system-packages"
        )

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Sigma rule not found: {path}")

    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Sigma rule must be a YAML mapping: {path}")

    # Sigma standard: condition lives inside the detection block.
    # Also hoist it to top-level so callers that check data["condition"] still work.
    detection = data.get("detection", {})
    if isinstance(detection, dict) and "condition" in detection:
        if "condition" not in data:
            data["condition"] = detection["condition"]

    data["_path"] = str(p)
    return data


def load_artifacts(path) -> list:
    p = Path(path)
    if not p.exists():
        return []
    records = []
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records
