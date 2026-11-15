# Observable fields vs. label fields

SHENRON measures how well a detection rule survives an adversary changing
their behavior. That only means something if the rule detects what the
adversary actually produces.

## The problem this fixes

Most rules matched on fields the simulator assigns to its own output:
`layer`, `mitre_technique(s)`, `behavior_class`, `detection_opportunities`.
A real adversary never emits those. Two independent reviews found that
brittleness scores therefore measured whether removing a label hides the
label. After the measurement fixes in PR #71, every scenario scored 0.00.
That wasn't durability either: the rules kept firing on protected labels
the mutator is not allowed to change.

## The policy

| Kind | Examples | Rules may match? | Mutator attacks? |
|---|---|---|---|
| Label | `layer`, `phase`, `signal`, `behavior_class`, `detection_opportunities`, `mitre_technique(s)`, `description` | No | Not needed |
| Observable | `*_sim` fields (`channel_type_sim`, `beacon_interval_sim`, `port_sim`), nested data (`beacon_data.method`) | Yes | Yes |

- The list lives in `core/sigma/fields.py` (`LABEL_FIELDS`).
- ATT&CK `tags` on a rule are metadata and are fine. Only `detection:` blocks are restricted.
- The adversary controls all of its own activity, so the brittleness scorer
  applies each strategy to every artifact a stage emits, not just one.
- Rules can address nested fields with dotted paths (`beacon_data.method`).
  The pySigma bridge and the mutator both resolve them.

## Rollout

The policy is enforced per folder through `OBSERVABLE_ONLY_RULE_DIRS` and
`tests/test_observable_field_policy.py`. Convert a folder, add it to the
list, and the test keeps it from regressing.

| Folder | Status |
|---|---|
| `c2` | Converted (pilot) |
| `exfiltration` | Converted |
| `llm` | Converted |
| everything else | Label-based, still to convert. None of these rules fire on the demo events. |

## Pilot results

Each of the 6 sigma-aware strategies is applied to every event, and the rule
is re-evaluated. Brittleness is the share of strategies that stopped the rule
firing. Results were measured on the demo artifact (50 events) and on a
`shenron.py run all` corpus (227 events).

| Rule | Detects on (before, labels) | Detects on (after, observables) | Before (demo) | After (demo) | After (corpus) |
|---|---|---|---|---|---|
| C2 beacon | `layer` + `mitre_technique` | `beacon_interval_sim` exists + `beacon_data.method` | 0.83 | 0.83 | 0.83 |
| Covert channel | `layer` or `mitre_technique` | header-carrier, encapsulation or relay observables | 0.00 | 0.67 | 0.17 |

- The old covert-channel rule scored 0.00 because it matched `mitre_techniques`, which the mutator may not touch. It looked unbreakable, but the mutator simply couldn't reach it.
- The rewritten rule fires on 4 demo events instead of 7. The three it dropped matched only on a technique tag; one was exfiltration telemetry.
- On the full corpus it matches the relay and encapsulation records of `covert_socket_relay`.

`covert_socket_relay` emitted only label fields before this change, so no behavior-based rule could detect it. It now emits synthetic observables: listener address and port, forward destination and port, and carrier and inner protocol. These are plain values in documentation address ranges, with no sockets involved.

Per strategy, after conversion:

| Strategy | Beacon | Covert (demo) | Covert (corpus) |
|---|---|---|---|
| value_swap | evaded | detected | detected |
| field_omit | evaded | evaded | evaded |
| case_flip | detected | detected | detected |
| unicode_substitute | evaded | evaded | detected |
| whitespace_inject | evaded | evaded | detected |
| combined_evasion | evaded | evaded | detected |

The corpus result reflects the relay selection's `exists` checks. Existence tests ignore value tricks, so only removing the field gets past them. That makes the rule only as strong as the telemetry source's guarantee that those fields are present.

## Findings worth acting on

- **Homoglyphs evade every rule matched by the pySigma bridge.** The
  bridge defines `_normalize()` but never calls it while matching. Whether
  matching should normalize homoglyphs and zero-width characters is a
  detection-design choice, not a bug fix, so it is left unchanged here.
  Controlled test at this commit: changing only `_get_event_values` to pass
  event strings through `_normalize()` turns `unicode_substitute` from
  evaded to detected for both C2 rules on the demo events (beacon 0.83 →
  0.50, covert 0.67 → 0.50). `combined_evasion` still evades both, because
  `_normalize()` does not remove zero-width characters. Measured on these two
  rules and SHENRON's synthetic events only.
- `contains` matching survives suffix-style value swaps that exact matching
  does not.
- `exists` checks resist every value mutation and fail only when the field
  is missing, so their strength depends on the telemetry source.
- Brittleness here is measured on synthetic fields, so it shows how a rule
  is *written*, not how it performs on real telemetry.

## Label-stripping control

Hold the events constant, remove every `LABEL_FIELDS` key, and evaluate the rules. Demo: 50 events, 410 label values removed. Corpus: a `shenron.py run all` run (227 events).

| Rule | `main`, demo, with / without labels | This PR, demo, with / without | This PR, corpus, with / without |
|---|---|---|---|
| C2 beacon | 3 / 0 | 3 / 3 | 3 / 3 |
| Covert channel | 7 / 0 | 4 / 4 | 2 / 2 |
| Exfil shell | 3 / 0 | 3 / 3 | 3 / 3 |
| LLM manipulation | 4 / 0 | 0 / 0 | 11 / 11 |

On `main`, every detection disappears once the simulator's labels are removed. Every converted rule fires on the same events with or without labels.

`tests/test_observable_field_policy.py` enforces, for every rule in a converted folder:

- **Positive control:** the same hit count with labels stripped, on the demo and on a freshly generated corpus, and at least one hit overall.
- **Negative control:** no hits on `artifacts/benign_demo.jsonl`.
- **Negative control:** no hits on corpus events from any generator other than the one the rule targets. The test uses `layer` as ground truth; the rules never read it.

With `main`'s exfil and LLM rules swapped back in, the label-stripping control and the static label check both fail. `main`'s LLM rule also fails the generator check, because it accepted technique labels such as T1027 that other generators share.

## Exfil and LLM conversion findings

- **Exfil shell** detects a one-shot listener (`lifecycle_sim`, `listen_backlog_sim`, `bind_addr_sim`), an outbound transfer that closes its socket, and a prompt port release. It fires on the same 3 events as before.
- **LLM manipulation** detects injection prompts, model probes, hallucination-tagged log traces and their log setup, and layered encoding. It fires on 11 of 12 events in `artifacts/llm_manipulation/scenario_run.jsonl`. The one it skips is the scenario summary, which only lists technique labels (`techniques_used_sim`).
- **The 4 LLM events in the demo artifact carry no evidence at all**, only labels and bookkeeping fields, so the converted rule correctly fires 0 times there. Its 4 demo detections on `main` were pure label matches.
- **The canonical demo generator emits labels only.** `scripts/generate_demo_artifacts.py` writes the same label template for all 40 layers, with no simulated observables, so no observable-only rule can fire on its output. `test_audit_bundle.py` previously asserted a TRIGGERED verdict on that output, which only held through a label match. It now asserts what the bundle guarantees: every rule is evaluated and none errors. Giving that generator real observables is a separate change.

### Brittleness of the converted rules

| Rule | Demo | Corpus | Only strategy that evades |
|---|---|---|---|
| Exfil shell | 0.17 | 0.17 | `field_omit` |
| LLM manipulation | n/a (no baseline detection) | 0.17 | `field_omit` |

Both rules mostly test for the presence of evidence fields, so changing values (swaps, case, homoglyphs, whitespace) leaves them firing and deleting fields stops them. That is a property of how these rules are written, not evidence that they are durable. It also means most value mutations here change data the rules never compare, so a low score measures little. Rules that compare values would be needed before brittleness says anything about evasion.

## Specificity: matched benign controls

Label independence is necessary, not sufficient. `tests/test_observable_specificity.py` gives each converted rule benign twins: events with the same evidence fields as its positives, but ordinary values. **10 of 12 twins fire:**

| Rule | Benign twins that fire |
|---|---|
| C2 beacon | 2 of 2: hourly software update check, resolver refreshing a cached record |
| Covert channel | 3 of 3: ordinary ping, normal HTTPS, reverse proxy |
| Exfil shell | 2 of 3: routine HTTPS upload, service releasing a port. Quiet: long-lived listener |
| LLM manipulation | 3 of 4: ordinary chat request, app logger setup, compressed archive. Quiet: ordinary prompt |

**These rules are label-independent but not behavior-specific, and must not be described as behavior-specific detection.** Most selections only check that fields exist, or match values benign traffic also has (`http_get`, `dns_a`, `https`). The two quiet twins hit selections that compare values (`lifecycle_sim: one_shot` with `listen_backlog_sim: 1`) or require a field whose name asserts the behavior (`injection_technique_sim`, effectively a label under another name).

The firing twins are strict xfails: when a rule is made specific, its twin passes unexpectedly and CI flags it so the mark can be removed.

Making them specific needs evidence the generators don't emit yet. Single events can't separate a beacon from an update check without process lineage, destination context or periodicity across events, and an upload from exfiltration without knowing what was read and by whom. Next steps, in order: tighten the selections the current fields can support (for example DNS carrying TCP), add discriminating context to the generators, and keep these twins as the acceptance test.

### Denominators used in this document

- **Demo:** `artifacts/demo/shenron_demo_run.jsonl`, 50 events, committed. The published report uses this file.
- **Corpus:** a fresh `shenron.py run all`, 227 events in the run measured here. Generated, so counts can vary between runs.
- **LLM scenario run:** `artifacts/llm_manipulation/scenario_run.jsonl`, 12 events, committed.
- **Benign twins:** 12 hand-written events in `tests/test_observable_specificity.py`.
