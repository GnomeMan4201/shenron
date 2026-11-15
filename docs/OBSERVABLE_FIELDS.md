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
| everything else | Label-based, still to convert |

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
