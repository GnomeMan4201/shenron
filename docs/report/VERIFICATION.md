# Report verification

`docs/report/index.html` is a static snapshot of SHENRON at commit `6810866`. It was checked on 2026-11-14 by rerunning the tool at that commit and with PR #71 applied (`61064a6`), then reading the code paths behind each claim.

## How the numbers were regenerated

- Rule verdicts, hit counts and per-rule mutation counts: `POST /api/validate` (Flask test client) on `artifacts/demo/shenron_demo_run.jsonl`.
- Mutation rounds: `POST /api/adaptation` with `max_iterations=8` (`run_adaptation`).
- Scenarios: `python3 shenron.py compare-scenarios --out <dir>`.

Runs used `PYTHONHASHSEED` 1 and 2 for the snapshot and 11, 22 and 33 for the scenarios, at both commits.

## Claims and verdicts

| Claim on the page | Verdict | Evidence |
|---|---|---|
| 4 of 28 rules fire on the 50 demo events (beacon 3, covert channel 7, exfil shell 3, LLM 4) | Holds | Identical in both snapshot runs and at `61064a6`; also confirmed by two independent reviews |
| Per-rule mutation counts: beacon and exfil shell stopped by 2 of 7 mutations, the others by 0 | Holds | `_score_brittleness` in `core/cli/commands/validate.py` raises if any strategy fails, so the denominator is always 7; the values are unchanged at `61064a6` |
| 8 rounds, 2 of 4 rules stopped from round 1 on; survivors are covert channel and LLM | Holds | Identical across runs and at `61064a6` |
| Round 1 deleted `layer` from all 50 events | Holds | Instrumented `mutate_targeted`: `field_omit` targeted `layer` 50 times |
| Rounds 2–4 changed `run_id`, `host_id` or `timestamp`, which no rule reads | Holds | Same instrumentation. **Corrected:** the page previously said every round targeted `layer` |
| Rounds 5–6 changed nothing | Holds at `6810866` | `sigma_aware_unicode` and `sigma_aware_whitespace` become `unicode` and `whitespace`, which the mutator doesn't recognise; PR #71 adds aliases |
| Survivors keep firing because they also match `mitre_technique` | Holds | Both rules use `1 of selection_*` with a `mitre_technique` selection; no strategy targets that field |
| Campaign scorer compared a stage's full event set before mutation with the single mutated event after | Holds | Every stage has 3–13 events. Patching only this comparison at `6810866` (mutated event substituted into the full set) gives 0.00 for all six scenarios |
| Campaign scorer defects: undetected stages counted as evasion, only `layer` mutated, per-process seeds | Holds | `score_campaign` scores every artifact regardless of baseline detection; the mutator loads only root-level rules (targets `layer`, `behavior_class`); seed is `hash(event_id)` |
| With PR #71 all six scenarios score 0.00 | Holds | Three runs at `61064a6` |
| Originally reported scenario values (apt29-style 0.71 … ransomware-precursor 0.40) | Holds as a record of a first run | Later runs at `6810866` give apt29-style 0.67; all other values match |
| The reported "most effective strategy" rate equals the mean scenario brittleness, with tied strategies | Holds | `strategy_effectiveness` averages `overall_brittleness`; per-scenario counts show a four-way tie (`value_swap`, `field_omit`, `unicode_substitute`, `whitespace_inject`) |
| ATT&CK overlap 20 / 10 / 20 | Holds | Recomputed at parent-technique level from the embedded rules and events |
| 40 events carry a full safety object; 10 use fewer safety fields | Holds | 7 records have `safe` + `simulation_only`, 3 have only `simulation_only` |
| Mutation-round numbers come from the brittleness scorer and are withdrawn | **Corrected** | They come from `run_adaptation`, reproduce unchanged with PR #71, and are kept with a narrower interpretation |
| "Safety contract" label on events | **Corrected** | Renamed to "Safety flags"; these flags are written by the generator and are not an audit of runtime behaviour. Records without a safety object now show their `simulation_only`/`safe` fields |

## Not established by this page

- Real-world detector effectiveness: everything here is SHENRON's own synthetic telemetry.
- Rule durability: the mutation rounds only ever changed one detection field (`layer`).
- That the safety flags reflect what the tool did at runtime.
