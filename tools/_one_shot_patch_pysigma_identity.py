from pathlib import Path

path = Path("core/sigma/pysigma_bridge.py")
text = path.read_text(encoding="utf-8")


def replace_once(old: str, new: str, label: str) -> None:
    global text
    matches = text.count(old)
    if matches != 1:
        raise SystemExit(f"unexpected source shape for {label}: {matches} matches")
    text = text.replace(old, new, 1)


replace_once(
    '''import uuid as _uuid_mod

def _ensure_uuid_id(rule_yaml: str) -> str:
    """Ensure rule has a valid UUID id field for pySigma."""
    lines = rule_yaml.splitlines()
    new_lines = []
    found_id = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("id:"):
            val = stripped[3:].strip()
            try:
                _uuid_mod.UUID(val)
                new_lines.append(line)
            except (ValueError, AttributeError):
                new_lines.append(f"id: {_uuid_mod.uuid4()}")
            found_id = True
        else:
            new_lines.append(line)
    if not found_id:
        new_lines.insert(1, f"id: {_uuid_mod.uuid4()}")
    return "\\n".join(new_lines)
''',
    '''import uuid as _uuid_mod

def _parser_uuid(seed: str) -> _uuid_mod.UUID:
    """Return a deterministic parser-only UUID for pySigma compatibility."""
    return _uuid_mod.uuid5(_uuid_mod.NAMESPACE_URL, seed)


def _ensure_uuid_id(rule_yaml: str) -> str:
    """Give pySigma a UUID without changing the rule's public source identity."""
    lines = rule_yaml.splitlines()
    new_lines = []
    found_id = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("id:"):
            val = stripped[3:].strip()
            try:
                _uuid_mod.UUID(val)
                new_lines.append(line)
            except (ValueError, AttributeError):
                source_id = val.strip("'\\\"")
                new_lines.append(
                    f"id: {_parser_uuid(f'shenron:sigma-id:{source_id}')}"
                )
            found_id = True
        else:
            new_lines.append(line)
    if not found_id:
        new_lines.insert(
            1,
            f"id: {_parser_uuid(f'shenron:sigma-yaml:{rule_yaml}')}",
        )
    return "\\n".join(new_lines)
''',
    "UUID fixer",
)

replace_once(
    '''    # Load and parse rule
    try:
        rule_text = rule_path_p.read_text(encoding="utf-8")
        rule_text = _ensure_uuid_id(rule_text)
        collection = SigmaCollection.from_yaml(rule_text)
        rules = list(collection)
        if not rules:
            return BridgeResult(
                rule_id=rule_id, rule_title=rule_title,
                rule_file=rule_path, artifact_file=artifact_path,
                verdict=BridgeVerdict.ERROR,
                errors=["No rules in collection"],
            )
        rule = rules[0]
        rule_id    = str(rule.id) if rule.id else rule_id
        rule_title = str(rule.title) if rule.title else rule_title
''',
    '''    # Preserve committed source identity while parsing a UUID-compatible copy.
    try:
        from core.sigma.loader import load_sigma_rule

        source_rule = load_sigma_rule(str(rule_path_p)) or {}
        rule_id = str(source_rule.get("id") or rule_id)
        rule_title = str(source_rule.get("title") or rule_title)

        rule_text = rule_path_p.read_text(encoding="utf-8")
        parser_rule_text = _ensure_uuid_id(rule_text)
        collection = SigmaCollection.from_yaml(parser_rule_text)
        rules = list(collection)
        if not rules:
            return BridgeResult(
                rule_id=rule_id, rule_title=rule_title,
                rule_file=rule_path, artifact_file=artifact_path,
                verdict=BridgeVerdict.ERROR,
                errors=["No rules in collection"],
            )
        rule = rules[0]
        rule_title = str(rule.title) if rule.title else rule_title
''',
    "bridge source identity",
)

path.write_text(text, encoding="utf-8")
