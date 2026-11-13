# Shenron reviewer findings — integration candidate (not merged)

This branch combines the source changes from the frozen review and tested draft
fixes, **not** human reviewer endorsement or a production release. Its base is
PR #54 head `982ad96ee9e211f3ce1bbdaae69e96f1bc47ca56`. The historical
human-review source `fb4eedc15d022ec6856f5978d14a07904fdb9220` remains
untouched. GitHub Issue #57 tracks acceptance.

## Explicit merge resolutions

- PR #54: Retain strict assumption YAML structure and required-claim validation,
  aggregate fail-closed handling, and narrowly pinned, explicitly reported
  built-in legacy exclusions in Audit and Quickstart.
- PRs #49/#52: Add strict Sigma JSONL ingestion, nested eight-field safety
  verification, generated canonical demo CI evidence, CLI error propagation,
  adversarial tests, README and documented limitations. The assumption loader
  now shares the physical-line-aware JSONL parser but retains #54's evidence
  field type checks and exact line-numbered errors.
- Current main `803bb41a133a82d974fa339b879a0ed945ce7420`: Preserve
  per-record Sigma condition matching, duplicate-record counting and parse
  error treatment. Add #52's preflight ingestion and pySigma-specific failure
  propagation **without** overwriting the event coherence fix.
- PR #55: Preserve punctuation during normalization so `!signal` and
  `~signal` cannot silently become positive `signal`; retain exact
  normalized matching and its controls.
- PR #56: Remove unsupported T1078 association from synthetic device
  fingerprint emission and its assumption; preserve the explicit change in
  matching strength (semantic claim narrows, signal-only requirement relaxes).
  Retain diagnostic tests and current-code positive/negative seed gate.

## Two distinct identity experiments

The unseeded seven-category **survey** is allowed to observe either supported
or partially supported identity evidence, but must fail if it cannot account
for the generated claim status. All non-identity categories must be supported.

A separate **qualified fixture gate** generates a known positive seed and a
known negative seed twice each, asserts record/signal counts, semantic digest
agreement, expected per-claim status and signal removal. Only the known
positive fixture is used for the seeded all-seven verdict. This does *not*
establish real-world detection or an unseeded success rate.

The original census #50 (72 fully supported, 28 partially supported among
100 seeds) and source-pinned fixture experiment #51 are preserved on their
original unmerged branches. The old `research/identity_fixed_evidence_gate.py`
from #52's ancestry is not copied into this candidate: its frozen T1078 event
digest is intentionally incompatible with the corrected generator.
Instead, current-code CI invokes `research/identity_ci_gate.py`.

## Required acceptance

On this exact combined head, verify all CI jobs: Python 3.10/3.11/3.12,
minimum dependencies, nested safety and fixed legacy exclusions, Sigma
coherence and malformed input, C1/C2 unresolved claim tests, punctuation
negation and positive controls, T1078 semantic boundary, nondeterministic
identity characterization, and fixed positive/negative/near-miss controls.

Any malformed input producing unqualified SUPPORTED, missing signal falsely
accepted, loss of record-level Sigma coherence, stale diagnostic expectation,
or incomplete exact-head CI is a **kill criterion** for the proposed release.
No live third-party traffic, merge, tag, publication or reviewer outreach.
