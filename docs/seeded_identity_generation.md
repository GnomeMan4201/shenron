# Seeded identity generation and the assumption CI gate

## Prior findings reused

[Draft PR #50](https://github.com/GnomeMan4201/shenron/pull/50) measured
72/100 supported identity generations and 28/100 missing the exact
`trusted_name_rename_sim` signal, with zero semantic repeat mismatches.
[Draft PR #51](https://github.com/GnomeMan4201/shenron/pull/51) qualified
`2026110500` as a positive seed and `2026110506` as a negative seed.
This change reuses those seed selections and the current-code
`research/identity_ci_gate.py` normalization/negative controls. It does not
repeat or replace their 100-seed studies or change those draft PRs.

## Cause and change

`trusted_name_masquerade_evidence` requires `trusted_name_rename_sim`.
In `core/layers/stealth_mimic.py`, `simulate_stealth_mimic()` samples 2–4
payloads, then calls `random.choice(MIMIC_BEHAVIOR_CLASSES)` for each payload.
The target signal is one of three choices. Every draw can choose another
behavior, leaving the required signal absent. The validator correctly reports
the claim as `UNSUPPORTED` and the identity category as `PARTIALLY_SUPPORTED`.

The CLI now accepts `--seed` for `--run`, `run`, and
`--validate-all-assumptions`. Validate-all passes the seed to each independent
category subprocess; seeding only its parent would not seed those children.
The assumption CI job now generates fresh evidence with positive seed
`2026110500` and requires the command to exit zero. The existing fixed-identity
job still checks the known-negative seed and exact-signal-removal near miss.
Neither the generator's behavior selection nor the validator nor the identity
assumption YAML changes.

## Bounded measurements

Measured with Python 3.12.14 and `constraints/ci.txt`, from base `79a4f67`.
Each trial used a fresh scope directory and separate `SHENRON_HOME` and report
directory. Each invocation generated and validated all seven categories.
After measurements used the implementation in the second commit; only the
first, test-only commit existed when those working-tree measurements ran.

| Identity claim | Before, unseeded (50) | After, seed 2026110500 (50) | After, unseeded (50) |
| --- | ---: | ---: | ---: |
| firmware_log_forgery_evidence failures | 0 | 0 | 0 |
| firmware_tamper_evidence failures | 0 | 0 | 0 |
| device_identity_pollution_evidence failures | 0 | 0 | 0 |
| trusted_name_masquerade_evidence failures | 12 | 0 | 15 |
| no_exfil_overclaim failures | 0 | 0 | 0 |
| Identity category failures | 12 | 0 | 15 |
| Failures in each of the other six categories | 0 | 0 | 0 |
| Distinct selected identity semantic hashes | 50 | 1 | 50 |

The before failures were trials 0, 3, 5, 16, 20, 22, 25, 31, 33, 35, 38, 49
(zero based). Every failure lacked the target signal. The after seeded runs
each emitted 17 identity records with one exact target-signal record.
[Per-trial results](evidence/identity-generation-50.csv) retain CLI exits,
identity verdicts, record/signal counts, and semantic SHA-256 hashes for all
150 invocations. Semantic normalization is the existing
`research.identity_ci_gate.digest_semantics` function.

To reproduce the CI check, use a fresh directory each time:

```sh
scope=$(mktemp -d)
python3 shenron.py --validate-all-assumptions --seed 2026110500 --scope-dir "$scope"
python3 scripts/diagnose_assumption_signals.py identity "$scope/shenron_identity.jsonl"
```

Repeat 50 times for the seeded measurement; omit `--seed 2026110500` for the
unseeded measurements. Keep the generated JSONL for each invocation and run
`core.assumptions.validator.validate_assumption` against each category file to
count failures per claim. Use `2026110506` to reproduce the negative identity
case (validate-all exit 1). With `--no-rerun`, an existing negative artifact
stays negative even when supplied a positive seed.

## Claims and limits

The demonstrated result is repeatability of selected synthetic identity
evidence and verdicts under the chosen seeds on this source/dependency context,
and a strict seeded CI positive check. Unseeded generation remains stochastic;
the original command without a seed can still legitimately report partial
support. The 12/50 versus 15/50 unseeded counts are independent samples, not a
claimed change in failure probability. Arbitrary seeds need not support every
claim. UUIDs, timestamps and hashes from OS entropy are not byte deterministic.
Other categories' complete event semantics were not qualified for repeatability.
This does not establish real-world detection effectiveness, token impersonation,
process injection, independent security validation, or coverage across all seeds.

## Red-first regression

Commit `b8d8da8` adds tests only. All four cases fail on the base because the
CLI rejects `--seed` (exit 2). With the implementation, they pass and cover
repeated positive/negative identity output through both run grammars, forwarding
the seed to fresh validate-all subprocesses, and preserving negative evidence
under `--no-rerun`. The existing near-miss gate remains unchanged.
