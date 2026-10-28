# Exact-signal coverage review — PR #47

Evidence source: hosted CI run 208, assumption-evidence artifact 12849400374.
These observations apply to the scoped synthetic category runs in that CI job.
They are not claims about real-world detection coverage.

| Category | Claim | Required signal absent from scoped artifacts | Status |
| --- | --- | --- | --- |
| payload | scripting_evidence | `interpreter_spawn_sim` | PARTIALLY_SUPPORTED |
| identity | token_impersonation_evidence | `synthetic_device_fingerprint_emit_sim` | PARTIALLY_SUPPORTED |

## Source boundaries

- `interpreter_spawn_sim` is classified by `core/ingest/journald_normalizer.py` from external journald process metadata. This is not evidence that the scoped synthetic payload run emits that signal.
- `core/layers/device_fingerprint_spoof.py` declares `synthetic_device_uuid_rapid_generation_sim`, which is not the same exact signal as `synthetic_device_fingerprint_emit_sim`. Do not treat the former as proof of the latter.
- Other required signals and techniques for the two claims were present in run 208; the other positive-evidence claims and the out-of-scope checks passed.
- A positive claim with an absent required signal remains partially supported. No automatic alias or fuzzy substitution is authorized.

## Open decision

Review whether each assumption is intended to validate *synthetic category output* or *external normalized telemetry*. If the scope is synthetic-only, revise the claim specification only after a human review of its intended semantics; do not rename evidence or fabricate an event to satisfy CI. Keep the coverage failure visible until the source contract is resolved.
