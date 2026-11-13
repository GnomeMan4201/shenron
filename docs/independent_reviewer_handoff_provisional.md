# Shenron independent reviewer handoff — provisional

**Status:** HOSTED CI VERIFIED AT PINNED HEAD; INDEPENDENT METHODOLOGICAL REVIEW PENDING. This document indexes evidence, not certification.

## Frozen reviewer target

- Review change: draft PR #47, `fix/exact-signal-evidence-negation`.
- **Pinned source commit:** `fb4eedc15d022ec6856f5978d14a07904fdb9220`.
- Source: https://github.com/GnomeMan4201/shenron/tree/fb4eedc15d022ec6856f5978d14a07904fdb9220
- PR diff: https://github.com/GnomeMan4201/shenron/pull/47
- Hosted CI: https://github.com/GnomeMan4201/shenron/actions/runs/40779695961 — eight jobs concluded success at this exact head (Python 3.10–3.12, minimum dependencies, package, ATT&CK drift, scoped assumptions, schema/safety/audit bundle).
- CI scoped evidence artifact: `assumption-evidence`, artifact ID `12856303527`, SHA-256 of ZIP `6ff7d2752fed1c8d2802611d8cebaaf1b229715f4547a09c1baca784454020c3`.
- The original October 28 email handoff ZIP contains instructions and supporting materials. The repository link provides the complete source revision.

## Precisely scoped questions

1. Does exact normalized signal membership eliminate the false-positive substring and negation cases?
2. Are the positive and out-of-scope statuses justified by the **scoped synthetic artifacts**?
3. Does optional `evidence_scope: same_artifact` prevent cross-artifact union for opted-in claims? Category-wide union remains the default for legacy claims.
4. Are the revised synthetic payload and identity claim definitions semantically supported, rather than merely test-satisfying?

## Explicit limitations and unresolved areas

- Hosted CI validates implementation behavior at the pinned revision, not independent methodological correctness or real-world detection coverage.
- A broad demo-artifact audit at that revision reports **9 out-of-scope violations and 0/19 assumptions supported**, while the separately scoped assumption CI job reports **7/7 categories supported**. These are different evaluations; successful audit-bundle generation is **not** a claim that the broad demo supports every assumption.
- Category-level union remains possible for non-opted-in claims; same-artifact is not same-session, same-host, authenticity, or causal proof.
- Historical claim names implying token impersonation and process injection were removed from the new identity assumption. Those capabilities remain unassessed.
- At the pinned commit, the audit safety check examines only selected top-level fields, malformed assumption JSONL can be dropped, and brittleness scoring can suppress evaluation errors. A **separate draft hardening branch** addresses those weaknesses without changing the pinned reviewer snapshot.
- Static forbidden-pattern tests do not establish complete absence of runtime side effects. CLI helper subprocesses and the MITRE drift check lie outside synthetic-layer guarantees.
- A reviewer may report a counterexample, negative result, or inconclusive findings. No sign-off is claimed.

## Hardening investigation (separate from pinned review)

- Red-first negative controls at https://github.com/GnomeMan4201/shenron/actions/runs/42130004663 demonstrated four source-level defects before remediation: malformed JSONL omission, incomplete nested safety fields accepted by the audit bundle, brittleness exceptions interpreted as zero, and a mixed rule-evaluation error exiting zero.
- Strict safety verification uncovered **10 of 50 committed demo records** without the eight-field nested contract. The original file is retained as negative-control evidence; it must not be represented as a uniformly compliant artifact.
- The canonical 40-event demo generator emits the nested contract and is used as a distinct positive audit fixture. Generating this fixture does **not** repair or qualify the mixed historical 50-event file.
- On hardening run https://github.com/GnomeMan4201/shenron/actions/runs/42131036555 the independently scoped identity check reported 3/4 claims supported: `trusted_name_rename_sim` was absent. The producing layer `stealth_mimic` randomly chooses among multiple behavior classes. Do not call the 7/7 result from the pinned run deterministically reproducible; this fluctuation remains an open research finding.
- CI green/red status represents the individual checked workflow and input, not global assurance. The hardening branch is draft-only, has no merge approval, and is **not** the reviewed revision sent to Brian.

## Reproduction boundary

Use the exact source commit and CI run above, not later `main` or unrelated branches. Any subsequent hardening branch must receive its own exact-head test record and independent assessment.

**Kill criterion:** If malformed or incomplete evidence can produce an unqualified supported or robust verdict, the affected evaluator is not reviewer-qualified until a regression test and fix block the counterexample.
