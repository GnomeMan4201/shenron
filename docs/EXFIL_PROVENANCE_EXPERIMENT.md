# Exfiltration with process lineage and data provenance

**Result: rejected.** Lineage and provenance separate exfiltration from an easy routine twin (a backup agent). They fail once routine activity keeps the suspicious relationship: **3 of 4** relationship-preserving cases fire the combined predicate. An attacker evades it in **3 of 3** variations. The remaining difference between the attacker and the admin is whether the action was **authorized**, and that isn't in process, file or network telemetry.

This is the third experiment on one question, after [EXFIL_CONTEXT_EXPERIMENT.md](EXFIL_CONTEXT_EXPERIMENT.md) (single event) and [EXFIL_SEQUENCE_EXPERIMENT.md](EXFIL_SEQUENCE_EXPERIMENT.md) (port and timing).

- **Code:** `research/exfil_provenance.py`.
- **Pinned by:** `tests/test_exfil_provenance_experiment.py`. It also checks that every case has the identical network transfer.

## Setup

Every case ends with the **same network transfer**: same address, port, size and socket behavior. Only two kinds of label-free evidence differ:

- **Lineage:** the process tree that started the sender, as image paths (`/usr/sbin/nginx`, `/bin/sh`).
- **Provenance:** which files the sender read before sending, as file paths.

Values are what real telemetry shows, not SHENRON-specific names, so no predicate can key on a generator convention.

| Predicate | Fires when |
|---|---|
| Lineage | The sender is a shell or interpreter descended from a network-facing service (nginx, apache2, php-fpm, sshd, node). |
| Provenance | The sender read a credential-class file first (`/etc/shadow`, SSH keys, cloud credentials, TLS private keys, `wp-config.php`, `.env`). |
| Combined | Both. |

## Round 1: exfiltration vs its routine twin

- **Exfiltration:** nginx starts a shell, which starts python3. It reads AWS credentials and `/etc/shadow`, then sends.
- **Twin:** systemd starts restic, which reads a database dump, then sends.

All three predicates separate them.

## Round 2: routine activity that keeps the suspicious relationship

| Case | Lineage | Provenance | Combined |
|---|---|---|---|
| Admin over SSH copies a server key to a new host | fires | fires | **fires** |
| WordPress backup plugin uploads its site config | fires | fires | **fires** |
| Node app shells out to upload its `.env` to a secrets manager | fires | fires | **fires** |
| Full-system backup that includes `/etc/shadow` | quiet | fires | quiet |

Each is the same shape as the attack. A network-facing service leads to a shell, which reads a secret and sends it. These are routine admin and application jobs.

## Round 3: attacker variations

The combined predicate misses all three:

- **Persist via cron:** no network-facing ancestor, so lineage misses.
- **Stage the data:** one process reads the secrets and a different one sends them, so provenance misses because it only checks the sender. Following data across processes would need taint tracking.
- **Rename the interpreter** to a service-like name, so lineage misses.

## Information limit: same events, different authorization

This rules out "a better predicate would fix it". Take one event history: an SSH session starts bash, which starts python3, reads a server's TLS private key and sends it to a new host. It has two authorization outcomes. One is an on-call admin migrating the service, which should not alert. The other is an attacker with a stolen SSH key, which should alert.

The two inputs are identical, so any deterministic detector that sees only these events gives both the same output. **When a binary malicious/benign verdict is required, it cannot classify both correctly.** `test_information_limit_identical_histories` checks this for the three predicates here, and for arbitrary functions of the input (always alert, never alert, a hash of the events).

This doesn't apply to a detector that abstains, or that reports suspicious activity without asserting malicious intent. Such a detector can be appropriately calibrated for both cases, for example "sensitive key sent to a new host; authorization unknown". That is the kind of output an event-only detector can honestly give here.

This is an information limit, not a failed heuristic. For this pair, no amount of extra behavioral evidence helps unless it differs between the two cases. Authorization context, such as which credential was used and whether the change was expected, does differ.

## What this establishes

- **Kill criterion met for this evidence model.** With network, lineage and provenance all matched, the attack and the admin task are the same events, and the information-limit test shows no event-only detector can classify both correctly when a binary malicious/benign verdict is required. This does not show that lineage and provenance are useless for detection: they remove easy false positives. Nor does it show that no behavioral detector can ever separate attacks from authorized work. It shows that these cases can't be separated from these events. Telling them apart takes **authorization context**:
  - who acted, and with which credential and authentication method;
  - whether this host or application normally does this;
  - whether a change or job was expected.
- **A ceiling on what SHENRON can show.** SHENRON simulates behavior, so it can test whether a rule *sees* a behavior. It can't establish that a rule separates malicious from authorized activity unless its generators also model authorization context, for both the attack and its routine twin.
- **What lineage and provenance are good for:** removing easy false positives, like the backup agent in round 1. They are worth emitting as evidence, but not as an exfiltration detector.
- **What's not worth building:** don't integrate this evidence model, or correlation support, into SHENRON as an exfiltration detector. The next experiment, if any, is whether minimal authorization context (actor identity and whether the action matches a baseline) separates round 2 without being trivially forged in round 3.

## Limits

All cases are hand-written, with one exfiltration sequence. The predicates are deliberately simple. Smarter ones (taint tracking, rarity baselines) could change round 3, but not round 2: those cases are legitimate even with complete tracking.
