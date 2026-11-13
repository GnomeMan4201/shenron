#!/usr/bin/env python3
"""Read-only diagnostics for scoped Shenron assumption evidence.

Usage:
    python scripts/diagnose_assumption_signals.py CATEGORY EVENTS.jsonl
No category execution, artifact mutation, or fuzzy matching is performed.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.assumptions.loader import load_assumption, load_artifacts
from core.assumptions.validator import (
    _artifact_signals, _artifact_techniques, _check_claim, _normalize,
)
from core.cli.commands.validate_all import CATEGORY_ASSUMPTIONS


def diagnose(category, events_path):
    assumption_path = Path(CATEGORY_ASSUMPTIONS[category])
    assumption_id, _, claims = load_assumption(assumption_path)
    artifacts = load_artifacts(events_path)
    observed_signals = sorted(set().union(*(_artifact_signals(a) for a in artifacts)))
    observed_techniques = sorted(set().union(*(_artifact_techniques(a) for a in artifacts)))
    records = []
    for claim in claims:
        result = _check_claim(claim, artifacts)
        records.append({
            "claim_id": claim.id,
            "claim_type": claim.type.value,
            "evidence_scope": claim.evidence_scope,
            "status": result.status.value,
            "required_signals": [
                {"signal": s, "normalized": _normalize(s),
                 "exact_match": s in result.supported}
                for s in claim.requires_signals
            ],
            "required_techniques": [
                {"technique": t, "exact_match": t in result.supported}
                for t in claim.requires_techniques
            ],
            "supported": result.supported,
            "unsupported": result.unsupported,
        })
    return {
        "category": category,
        "assumption_id": assumption_id,
        "artifact_count": len(artifacts),
        "observed_signals": observed_signals,
        "observed_techniques": observed_techniques,
        "claims": records,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("category", choices=sorted(CATEGORY_ASSUMPTIONS))
    parser.add_argument("events", type=Path, help="Existing scoped JSONL artifact")
    args = parser.parse_args()
    if not args.events.is_file():
        parser.error("scoped artifact does not exist; no simulation will be run")
    print(json.dumps(diagnose(args.category, args.events), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
