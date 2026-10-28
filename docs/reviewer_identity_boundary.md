# Reviewer readiness addendum — identity claim boundary

Status: **OPEN / NOT REVIEWER-QUALIFIED**. Draft PR #47, pending hosted CI.

## Evidence observed

In CI run 208, scoped identity artifacts contained `bios_log_forge_sim`, `bios_tamper_log_write_sim`, `trusted_name_rename_sim`, and device-identity anomaly signals. They did **not** contain the required `synthetic_device_fingerprint_emit_sim`.

The generator `core/layers/device_fingerprint_spoof.py` emits `multi_identity_emit_sim`, `uuid_anomaly_sim`, and more specific device-identity detection opportunities. Its documented technique set is T1036/T1027/T1078. The identity assumption's `token_impersonation_evidence` claim requires T1542 and `bios_log_forge_sim`, which come from a different firmware-related evidence path. A union of signals across a scoped category is not proof that these distinct behaviors occurred together or share a causal mechanism.

## Review question

The current claim name, `token_impersonation_evidence`, overstates the direct meaning of the required firmware and device-fingerprint observations. Do **not** resolve the missing signal by inventing a new event or silently aliasing a UUID anomaly to token impersonation.

Recommended next design decision: split firmware-integrity and device-identity claims, each with explicit provenance and technique mappings; evaluate token impersonation separately against telemetry that actually supports it. This requires a specification and validator review because the current validator aggregates required signals across all artifacts in a category.

## External review disclosure

- Exact matching is enforced; it does not establish semantic correctness of claims.
- Synthetic evidence is not proof of real-world detection coverage.
- Category-level signal aggregation does not prove co-occurrence within one event/session.
- Identity coverage remains unresolved; no reviewer package should describe it as fully supported.
- Hosted CI status must be recorded for the exact reviewed commit.
