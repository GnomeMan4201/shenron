#!/usr/bin/env python3
# SHENRON: Shared safety contract — single source of truth
# Every generator, validator, report, and compare mode imports from here.
# Do not duplicate these fields elsewhere.

from typing import Any

# ── Contract definition ───────────────────────────────────────────────────────

SAFETY_CONTRACT: dict[str, Any] = {
    "simulation_only":                True,
    "executable":                     False,
    "payload_present":                False,
    "portable_adversarial_procedure": False,
    "network_connection":             False,
    "subprocess_spawned":             False,
    "real_file_written":              False,
    "shell_invoked":                  False,
}

# Fields that must be True in a compliant record
REQUIRED_TRUE  = {"simulation_only"}

# Fields that must be False in a compliant record
REQUIRED_FALSE = {
    "executable",
    "payload_present",
    "portable_adversarial_procedure",
    "network_connection",
    "subprocess_spawned",
    "real_file_written",
    "shell_invoked",
}

ALL_FIELDS = REQUIRED_TRUE | REQUIRED_FALSE


# ── Compliance check ─────────────────────────────────────────────────────────

def check_record(record: dict) -> dict[str, str]:
    """
    Check a single record's safety block against the contract.
    Returns {field: "PASS"|"FAIL"|"MISSING"} for every field.
    """
    safety = record.get("safety", {})
    results = {}
    for field in sorted(ALL_FIELDS):
        if field not in safety:
            results[field] = "MISSING"
        elif field in REQUIRED_TRUE:
            results[field] = "PASS" if safety[field] is True else "FAIL"
        else:
            results[field] = "PASS" if safety[field] is False else "FAIL"
    return results


def verify_records(records: list[dict]) -> dict:
    """
    Verify a list of records against the safety contract.
    Returns a summary dict suitable for reporting.
    """
    total    = len(records)
    passed   = 0
    failed   = 0
    missing  = 0
    per_field: dict[str, dict] = {f: {"pass": 0, "fail": 0, "missing": 0}
                                   for f in sorted(ALL_FIELDS)}
    violations = []

    for i, record in enumerate(records):
        field_results = check_record(record)
        record_ok = all(v == "PASS" for v in field_results.values())
        if record_ok:
            passed += 1
        else:
            failed += 1
            violations.append({
                "index":  i,
                "layer":  record.get("layer", "unknown"),
                "fields": {k: v for k, v in field_results.items() if v != "PASS"},
            })
        for field, status in field_results.items():
            per_field[field][status.lower()] += 1
        if any(v == "MISSING" for v in field_results.values()):
            missing += 1

    verdict = "PASS" if failed == 0 and total > 0 else ("FAIL" if total > 0 else "NO_RECORDS")

    return {
        "total":      total,
        "passed":     passed,
        "failed":     failed,
        "missing":    missing,
        "verdict":    verdict,
        "per_field":  per_field,
        "violations": violations,
    }


def make_safe_record_fields() -> dict:
    """Return a fresh copy of the safety contract for embedding in a record."""
    return SAFETY_CONTRACT.copy()


# ── Report formatting ─────────────────────────────────────────────────────────

def print_verification(result: dict, source: str = ""):
    print()
    if source:
        print(f"  [SOURCE]      {source}")
    print(f"  [RECORDS]     {result['total']}")
    print()
    for field in sorted(ALL_FIELDS):
        pf = result["per_field"][field]
        status = "PASS" if pf["fail"] == 0 and pf["missing"] == 0 else "FAIL"
        print(f"  {field:<36} {status}")
    print()
    print(f"  [VERDICT]     {result['verdict']}")
    if result["violations"]:
        print(f"  [VIOLATIONS]  {len(result['violations'])}")
        for v in result["violations"][:5]:
            print(f"    record {v['index']} ({v['layer']}): {v['fields']}")
        if len(result["violations"]) > 5:
            print(f"    ... and {len(result['violations']) - 5} more")
    print()


def verification_to_markdown(result: dict, source: str = "") -> str:
    lines = [
        "# SHENRON Safety Contract Verification",
        "",
        f"**Source:** `{source}`  " if source else "",
        f"**Records checked:** {result['total']}  ",
        f"**Verdict:** {result['verdict']}  ",
        "",
        "---",
        "",
        "## Field Results",
        "",
        "| Field | Result |",
        "|-------|--------|",
    ]
    for field in sorted(ALL_FIELDS):
        pf = result["per_field"][field]
        status = "✅ PASS" if pf["fail"] == 0 and pf["missing"] == 0 else "❌ FAIL"
        lines.append(f"| `{field}` | {status} |")

    lines += [
        "",
        "---",
        "",
        "## Safety Contract",
        "",
        "| Field | Required Value |",
        "|-------|---------------|",
    ]
    for field, value in sorted(SAFETY_CONTRACT.items()):
        lines.append(f"| `{field}` | `{value}` |")

    if result["violations"]:
        lines += ["", "---", "", "## Violations", ""]
        for v in result["violations"]:
            lines.append(f"- Record {v['index']} (`{v['layer']}`): {v['fields']}")
    else:
        lines += ["", "---", "", "## Violations", "", "None. All records passed."]

    lines += [
        "",
        "---",
        "",
        "*SHENRON — Observable adversarial behavior, not portable adversarial procedure.*",
    ]
    return "\n".join(l for l in lines if l is not None)
