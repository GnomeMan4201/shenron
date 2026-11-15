# Report verification

`docs/report/index.html` is a **historical** static snapshot of SHENRON at commit `6810866`, before the rule conversions in PR #72. Its "4 of 28 rules fired" is the result at that commit. With the rules on `main` after #72, 3 of 28 fire on the same demo events (C2 beacon 3, covert channel 4, exfil shell 3), and the LLM rule's 4 demo hits disappear because those events carry only labels. It was checked on 2026-11-14 by rerunning the tool at that commit and with PR #71 applied (`61064a6`), then reading the code paths behind each claim.

## How the numbers were regenerated

- Rule verdicts, hit counts and per-rule mutation counts: `POST /api/validate` (Flask test client) on `artifacts/demo/shenron_demo_run.jsonl`.
- Mutation rounds: `POST /api/adaptation` with `max_iterations=8` (`run_adaptation`).
- Scenarios: `python3 shenron.py compare-scenarios --out <dir>`.

Runs used `PYTHONHASHSEED` 1 and 2 for the snapshot and 11, 22 and 33 for the scenarios, at both commits. `reproduce.py` below covers all three in one command.

## Reproduce it

| Version | Commit |
|---|---|
| Snapshot in the report | `6810866025c0b3d44349c96654351ee60097e2ca` (main) |
| With the measurement fixes | `61064a6bf69a309d568e6e4877d056e119739fd3` (head of PR #71) |

From a checkout at either commit, with `docs/report/reproduce.py` copied in from `main`:

```bash
git checkout <commit>
pip install -r requirements.txt
PYTHONHASHSEED=1 python3 reproduce.py
PYTHONHASHSEED=2 python3 reproduce.py   # same output expected
```

Expected output at `6810866` (identical for seeds 1 and 2):

```
4 of 28 rules fired
  sigma/rules/c2/shenron_beacon.yml  hits=3  mutation_score=0.286
  sigma/rules/c2/shenron_covert_channel.yml  hits=7  mutation_score=0.0
  sigma/rules/exfiltration/shenron_transient_exfil_shell.yml  hits=3  mutation_score=0.286
  sigma/rules/llm/shenron_llm_manipulation.yml  hits=4  mutation_score=0.0
  round 1: sigma_aware_field_omit  firing=2  evasion_rate=0.5
  round 2: sigma_aware_value_swap  firing=2  evasion_rate=0.5
  round 3: sigma_aware_case_flip  firing=2  evasion_rate=0.5
  round 4: sigma_aware_field_omit  firing=2  evasion_rate=0.5
  round 5: sigma_aware_unicode  firing=2  evasion_rate=0.5
  round 6: sigma_aware_whitespace  firing=2  evasion_rate=0.5
  round 7: field_drop  firing=2  evasion_rate=0.5
  round 8: label_ambiguity  firing=2  evasion_rate=0.5
  still firing: ['SHENRON Covert Channel / Protocol Tunneling', 'SHENRON LLM Manipulation Attack Chain']
  evaded: ['Ephemeral Exfiltration Shell Behavioral Cluster', 'SHENRON C2 Beacon Detection']
  apt29-style: 0.67
  fin7-style: 0.56
  insider-threat: 0.67
  living-off-the-land: 0.67
  ransomware-precursor: 0.40
  supply-chain: 0.50
```

Expected at `61064a6`: identical rules and rounds, and every scenario `0.00`.

The report's originally published apt29-style value, 0.71, came from the first run in a fresh environment, as observed by one of the AI reviews; later runs give 0.67. That first-run value was not reproduced for this document.

**Isolating the comparison defect.** At `6810866`, in `core/brittleness/scorer.py` `score_campaign`, replace the two checks against `[variant]` with checks against `[variant if x is event.artifact else x for x in all_arts]`. Changing nothing else, all six scenarios score `0.00` (run with `PYTHONHASHSEED=7`).

**Seeing what each round changed.** Wrap `SigmaAwareMutator.mutate_targeted` to count `_mutation_meta["field_targeted"]` per strategy. At `6810866`, `field_omit` hits `layer` 50 times in round 1 and `run_id`/`host_id`/`timestamp` 50 times in round 4; `value_swap` and `case_flip` hit only `run_id`/`host_id`/`timestamp`; `unicode` and `whitespace` change nothing.

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
