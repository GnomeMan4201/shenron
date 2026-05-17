#!/usr/bin/env python3
# SHENRON: Mutation engine
# Produces safe variants of synthetic telemetry records.
# Tests whether analysis pipelines are brittle to incomplete, noisy,
# or mislabeled telemetry.
# No subprocess, no network, no execution, no payloads.

import copy
import hashlib
import json
import random
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


# ── Mutation type registry ────────────────────────────────────────────────────

MUTATION_TYPES = {
    "field_drop": {
        "description": "Remove a non-critical field from each record",
        "purpose":     "Tests whether downstream analysis depends on optional fields",
        "safe":        True,
    },
    "timing_jitter": {
        "description": "Add random offset to timestamps",
        "purpose":     "Tests whether correlation rules tolerate timing variance",
        "safe":        True,
    },
    "label_ambiguity": {
        "description": "Replace specific signal names with generic variants",
        "purpose":     "Tests whether detection works on less-specific signal labels",
        "safe":        True,
    },
    "signal_density_high": {
        "description": "Duplicate records to increase event volume",
        "purpose":     "Tests whether analysis handles high-volume bursts",
        "safe":        True,
    },
    "signal_density_low": {
        "description": "Drop a percentage of records (sparse telemetry)",
        "purpose":     "Tests whether detection works on incomplete telemetry",
        "safe":        True,
    },
    "phase_imbalance": {
        "description": "Concentrate all records into a single phase",
        "purpose":     "Tests whether phase-aware analysis handles imbalanced runs",
        "safe":        True,
    },
    "technique_noise": {
        "description": "Add unrelated technique IDs to some records",
        "purpose":     "Tests whether MITRE-based correlation handles noisy technique labels",
        "safe":        True,
    },
    "missing_safety_fields": {
        "description": "Remove safety contract fields from some records",
        "purpose":     "Tests whether safety verification catches incomplete contracts",
        "safe":        True,
        "note":        "Intentional safety contract violation — for testing verify-safety only",
    },
}

DROPPABLE_FIELDS = [
    "description", "entropy", "artifact_hash", "generator", "note",
]

NOISE_TECHNIQUES = [
    "T1000", "T1001", "T1002", "T1003", "T1004",
]

GENERIC_SIGNAL_MAP = {
    "periodic_outbound_connection": "outbound_connection",
    "dns_subdomain_query":          "dns_query",
    "subnet_sweep":                 "network_probe",
    "smb_port_probe":               "port_probe",
    "log_file_cleared":             "file_modified",
    "scheduled_task_creation":      "system_modification",
    "process_injection_attempt":    "process_event",
    "signal_handler_modification":  "system_event",
    "hidden_temp_directory":        "directory_event",
    "periodic_beacon":              "network_event",
    "entropy_spike":                "file_event",
    "lateral_probe_shape":          "network_probe",
}


# ── Mutation result ───────────────────────────────────────────────────────────

@dataclass
class MutationResult:
    mutation_type:   str
    description:     str
    purpose:         str
    records_in:      int
    records_out:     int
    changes_made:    int
    run_id:          str
    safe:            bool   = True
    note:            str    = ""
    records:         List[dict] = field(default_factory=list)


# ── Mutators ──────────────────────────────────────────────────────────────────

def _stamp(record: dict, mutation_type: str, mutation_run_id: str) -> dict:
    """Add mutation metadata to a record."""
    r = copy.deepcopy(record)
    r["mutation"] = {
        "type":    mutation_type,
        "run_id":  mutation_run_id,
        "applied": True,
    }
    # Preserve safety contract
    if "safety" not in r:
        r["safety"] = {
            "simulation_only":                True,
            "executable":                     False,
            "payload_present":                False,
            "portable_adversarial_procedure": False,
            "network_connection":             False,
            "subprocess_spawned":             False,
            "real_file_written":              False,
            "shell_invoked":                  False,
        }
    return r


def mutate_field_drop(
    records: List[dict],
    run_id: str,
    fields: Optional[List[str]] = None,
    seed: int = 42,
) -> MutationResult:
    """Remove a non-critical field from each record."""
    rng = random.Random(seed)
    target_fields = fields or DROPPABLE_FIELDS
    out = []
    changes = 0
    for rec in records:
        r = _stamp(rec, "field_drop", run_id)
        for field_name in target_fields:
            if field_name in r:
                del r[field_name]
                changes += 1
                break
        out.append(r)
    meta = MUTATION_TYPES["field_drop"]
    return MutationResult(
        mutation_type="field_drop", description=meta["description"],
        purpose=meta["purpose"], records_in=len(records), records_out=len(out),
        changes_made=changes, run_id=run_id, records=out,
    )


def mutate_timing_jitter(
    records: List[dict],
    run_id: str,
    jitter_seconds: int = 300,
    seed: int = 42,
) -> MutationResult:
    """Add random timing offset to timestamps."""
    from datetime import timedelta
    rng = random.Random(seed)
    out = []
    changes = 0
    for rec in records:
        r = _stamp(rec, "timing_jitter", run_id)
        ts_raw = r.get("timestamp", "")
        if ts_raw:
            try:
                dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                offset = rng.randint(-jitter_seconds, jitter_seconds)
                dt2 = dt + timedelta(seconds=offset)
                r["timestamp"] = dt2.isoformat()
                r["mutation"]["jitter_seconds"] = offset
                changes += 1
            except Exception:
                pass
        out.append(r)
    meta = MUTATION_TYPES["timing_jitter"]
    return MutationResult(
        mutation_type="timing_jitter", description=meta["description"],
        purpose=meta["purpose"], records_in=len(records), records_out=len(out),
        changes_made=changes, run_id=run_id, records=out,
    )


def mutate_label_ambiguity(
    records: List[dict],
    run_id: str,
    signal_map: Optional[dict] = None,
    seed: int = 42,
) -> MutationResult:
    """Replace specific signal names with more generic variants."""
    mapping = signal_map or GENERIC_SIGNAL_MAP
    out = []
    changes = 0
    for rec in records:
        r = _stamp(rec, "label_ambiguity", run_id)
        sig = r.get("signal", "")
        if sig in mapping:
            r["signal_original"] = sig
            r["signal"] = mapping[sig]
            r["mutation"]["original_signal"] = sig
            changes += 1
        out.append(r)
    meta = MUTATION_TYPES["label_ambiguity"]
    return MutationResult(
        mutation_type="label_ambiguity", description=meta["description"],
        purpose=meta["purpose"], records_in=len(records), records_out=len(out),
        changes_made=changes, run_id=run_id, records=out,
    )


def mutate_signal_density_high(
    records: List[dict],
    run_id: str,
    multiplier: int = 3,
    seed: int = 42,
) -> MutationResult:
    """Duplicate records to simulate high-volume burst."""
    rng = random.Random(seed)
    out = []
    for rec in records:
        r = _stamp(rec, "signal_density_high", run_id)
        r["mutation"]["multiplier"] = multiplier
        out.append(r)
        for _ in range(multiplier - 1):
            dup = copy.deepcopy(r)
            dup["sequence"] = rng.randint(10000, 99999)
            out.append(dup)
    meta = MUTATION_TYPES["signal_density_high"]
    return MutationResult(
        mutation_type="signal_density_high", description=meta["description"],
        purpose=meta["purpose"], records_in=len(records), records_out=len(out),
        changes_made=len(out) - len(records), run_id=run_id, records=out,
    )


def mutate_signal_density_low(
    records: List[dict],
    run_id: str,
    keep_fraction: float = 0.5,
    seed: int = 42,
) -> MutationResult:
    """Drop a fraction of records to simulate sparse telemetry."""
    rng = random.Random(seed)
    out = []
    dropped = 0
    for rec in records:
        if rng.random() < keep_fraction:
            r = _stamp(rec, "signal_density_low", run_id)
            r["mutation"]["keep_fraction"] = keep_fraction
            out.append(r)
        else:
            dropped += 1
    meta = MUTATION_TYPES["signal_density_low"]
    return MutationResult(
        mutation_type="signal_density_low", description=meta["description"],
        purpose=meta["purpose"], records_in=len(records), records_out=len(out),
        changes_made=dropped, run_id=run_id, records=out,
    )


def mutate_phase_imbalance(
    records: List[dict],
    run_id: str,
    target_phase: str = "EXECUTE",
    seed: int = 42,
) -> MutationResult:
    """Relabel all records to a single phase."""
    out = []
    changes = 0
    for rec in records:
        r = _stamp(rec, "phase_imbalance", run_id)
        if r.get("phase") != target_phase:
            r["phase_original"] = r.get("phase", "")
            r["phase"] = target_phase
            r["mutation"]["target_phase"] = target_phase
            changes += 1
        out.append(r)
    meta = MUTATION_TYPES["phase_imbalance"]
    return MutationResult(
        mutation_type="phase_imbalance", description=meta["description"],
        purpose=meta["purpose"], records_in=len(records), records_out=len(out),
        changes_made=changes, run_id=run_id, records=out,
    )


def mutate_technique_noise(
    records: List[dict],
    run_id: str,
    noise_rate: float = 0.3,
    noise_techniques: Optional[List[str]] = None,
    seed: int = 42,
) -> MutationResult:
    """Add unrelated technique IDs to a fraction of records."""
    rng   = random.Random(seed)
    noise = noise_techniques or NOISE_TECHNIQUES
    out   = []
    changes = 0
    for rec in records:
        r = _stamp(rec, "technique_noise", run_id)
        if rng.random() < noise_rate:
            original = r.get("mitre_technique", "")
            noisy    = rng.choice(noise)
            r["mitre_technique_original"] = original
            r["mitre_technique"] = noisy
            r["mutation"]["noise_technique"] = noisy
            changes += 1
        out.append(r)
    meta = MUTATION_TYPES["technique_noise"]
    return MutationResult(
        mutation_type="technique_noise", description=meta["description"],
        purpose=meta["purpose"], records_in=len(records), records_out=len(out),
        changes_made=changes, run_id=run_id, records=out,
    )


def mutate_missing_safety_fields(
    records: List[dict],
    run_id: str,
    drop_rate: float = 0.2,
    seed: int = 42,
) -> MutationResult:
    """
    Remove safety contract fields from some records.
    INTENTIONAL safety contract violation — for testing --verify-safety only.
    """
    rng = random.Random(seed)
    out = []
    changes = 0
    for rec in records:
        r = _stamp(rec, "missing_safety_fields", run_id)
        if rng.random() < drop_rate:
            if "safety" in r:
                del r["safety"]
                changes += 1
                r["mutation"]["safety_dropped"] = True
        out.append(r)
    meta = MUTATION_TYPES["missing_safety_fields"]
    return MutationResult(
        mutation_type="missing_safety_fields",
        description=meta["description"],
        purpose=meta["purpose"],
        records_in=len(records), records_out=len(out),
        changes_made=changes, run_id=run_id,
        safe=False,
        note=meta.get("note", ""),
        records=out,
    )


# ── Bulk runner ───────────────────────────────────────────────────────────────

MUTATOR_MAP = {
    "field_drop":            mutate_field_drop,
    "timing_jitter":         mutate_timing_jitter,
    "label_ambiguity":       mutate_label_ambiguity,
    "signal_density_high":   mutate_signal_density_high,
    "signal_density_low":    mutate_signal_density_low,
    "phase_imbalance":       mutate_phase_imbalance,
    "technique_noise":       mutate_technique_noise,
    "missing_safety_fields": mutate_missing_safety_fields,
}


def run_mutations(
    records: List[dict],
    mutation_types: Optional[List[str]] = None,
    out_dir: str = "artifacts/mutations",
    seed: int = 42,
    verbose: bool = True,
) -> List[MutationResult]:
    """
    Run one or more mutations against a set of records.
    Writes each mutation variant to out_dir as a JSONL file.
    """
    import os
    os.makedirs(out_dir, exist_ok=True)

    types_to_run = mutation_types or [
        t for t in MUTATION_TYPES
        if t != "missing_safety_fields"  # opt-in only
    ]

    results = []
    now = datetime.now(timezone.utc).isoformat()

    for mut_type in types_to_run:
        if mut_type not in MUTATOR_MAP:
            if verbose:
                print(f"  [!] Unknown mutation type: {mut_type}")
            continue

        mutator = MUTATOR_MAP[mut_type]
        run_id  = f"mut-{mut_type[:8]}-{abs(hash(now + mut_type)) % 10000:04d}"

        try:
            result = mutator(records, run_id=run_id, seed=seed)
        except Exception as e:
            if verbose:
                print(f"  [!] Mutation {mut_type} failed: {e}")
            continue

        # Write JSONL
        out_path = os.path.join(out_dir, f"mutation_{mut_type}.jsonl")
        with open(out_path, "w", encoding="utf-8") as f:
            for r in result.records:
                f.write(json.dumps(r) + "\n")

        # Write mutation manifest
        manifest = {
            "mutation_type":  result.mutation_type,
            "description":    result.description,
            "purpose":        result.purpose,
            "records_in":     result.records_in,
            "records_out":    result.records_out,
            "changes_made":   result.changes_made,
            "run_id":         result.run_id,
            "safe":           result.safe,
            "note":           result.note,
            "generated_at":   now,
            "simulation_only": True,
            "output_file":    out_path,
        }
        manifest_path = os.path.join(out_dir, f"mutation_{mut_type}_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        results.append(result)

        if verbose:
            safety_flag = "" if result.safe else "  ⚠ intentional safety violation"
            print(
                f"  [{mut_type:<25}] "
                f"{result.records_in:>4} → {result.records_out:>4} records  "
                f"{result.changes_made:>4} changes{safety_flag}"
            )

    return results


def print_mutation_summary(results: List[MutationResult]):
    print()
    print(f"  [MUTATIONS]   {len(results)} variants generated")
    print()
    for r in results:
        safety_flag = "" if r.safe else "  ⚠ intentional safety violation"
        print(f"  {r.mutation_type:<28} {r.records_out:>4} records  {r.changes_made:>4} changes{safety_flag}")
    print()
