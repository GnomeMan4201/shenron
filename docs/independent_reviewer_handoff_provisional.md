# Shenron independent reviewer handoff — provisional

**Status:** NOT READY FOR FINAL SIGN-OFF. This document is a handoff index, not a certification or claim of independent validation.

**Change under review:** draft PR #47, `fix/exact-signal-evidence-negation`.
**Current candidate head:** `a710096413fc6ef231916c8f03043044c626b120`.
**CI:** run 220 (`40763739535`), queued at last observation. The results below must be refreshed against the *exact* final head after any further commit.

## Evidence to provide

1. The precise Git commit and PR diff, plus SHA-256 hashes for any exported reviewer files.
2. Hosted CI workflow run URL, job conclusions, Python 3.10/3.11/3.12 and minimum-dependency results, safety audit, package build, MITRE drift check.
3. The scoped assumption-evidence artifact from the same CI run, including JSONL, diagnostics, and artifact checksum.
4. A reproduction command and expected exit status for each verification step.
5. The regression tests for exact-signal matching, provenance scopes, and out-of-scope checks.

## Claims that can be evaluated, not presumed

- Exact normalized signal matching replaces substring and token-overlap acceptance.
- Positive claims may opt into `evidence_scope: same_artifact`. Legacy category-wide union remains default; this is not a universal same-artifact guarantee.
- Out-of-scope technique checks inspect all artifacts in the category.
- The synthetic payload assumption now requires the observed `interpreter_inline_exec_sim`; the external journald assumption still independently requires `interpreter_spawn_sim`.

## Open findings / exclusions

- **Identity assumption:** `token_impersonation_evidence` includes firmware and device-fingerprint requirements with a missing `synthetic_device_fingerprint_emit_sim` signal. The label and provenance semantics require specification review; do not silently alias related signals.
- **Category union:** legacy claims can aggregate requirements across unrelated artifacts. Opt-in same-artifact checks reduce this risk but do not prove same-session or causal relationships.
- **Synthetic vs external:** passing synthetic assumptions cannot establish external detector performance or real-world attribution.
- **Verification:** CI run 220 has no reported result at preparation time. Do not present this head as qualified.

## Final-release gate

Do not send as a *verified* package until (a) the exact-head test matrix and artifact hashes are recorded, (b) failing jobs are investigated and disclosed, (c) identity scope is resolved or explicitly accepted as an open finding, and (d) reviewer-facing claims match the code and measured artifacts. Independent methodological review remains separate from hosted reproducibility.
