# Exfiltration upload vs routine upload

**Result: rejected.** No context field on the upload event separates SHENRON's simulated exfiltration from routine uploads. Two fields together separate a hand-picked set, but every such pair is broken by one more plausible routine upload. The missing signal is not on the upload event at all. Telling the two apart needs evidence from *other* events: the process tree, what was read before sending, or the listener that preceded the transfer.

Code: `research/exfil_context.py` (run it directly). The outcome is pinned by `tests/test_exfil_context_experiment.py`.

## Setup

- **Positives:** 8 data-transfer events from SHENRON's own exfil generator (`core/layers/transient_exfil_sim.py`), with every label field stripped.
- **Negatives:** 6 routine uploads with the same existing fields: backup agent, browser form, cron `curl`, Python backup to MinIO, developer `scp`, CI artifact upload. They were chosen to be hard: short-lived tools, new destinations, non-standard ports.
- **Base rule:** the converted exfil rule's transfer selection, which only checks that `remote_addr_sim`, `data_size_bytes_sim` and `socket_closed_after_sim` exist.
- **Candidates:** taken from the generator's own header, which describes the behavior as an outbound connection to a non-standard port, from a non-network process, closed right after the transfer. Each candidate is one field, compared by value, added to every event with the value that activity would show:
  - `remote_port_sim` (already exists): not a standard service port.
  - `process_image_sim` (new): a shell or interpreter.
  - `process_uptime_sec_sim` (new): under 10 seconds.
  - `dest_first_seen_sim` (new): the destination hasn't been seen before.
- **Kill criterion:** a candidate that can't separate the two without simulator attack labels is rejected. No candidate uses labels.

## Round 1: each field alone, then in pairs

All candidates detect 8 of 8 generator transfers. False positives are out of the 6 routine uploads:

| Candidate | False positives |
|---|---|
| Existing transfer selection only | 6 of 6 |
| `remote_port_sim` (existing field) | 1: Python backup to MinIO (port 9000) |
| `process_image_sim` | 1: Python backup to MinIO |
| `process_uptime_sec_sim` < 10 | 3: backup agent, cron `curl`, `scp` |
| `dest_first_seen_sim` | 2: browser upload to a new site, `scp` to a new host |
| port + uptime | **0** |
| port + first seen | **0** |
| image + uptime | **0** |
| image + first seen | **0** |
| port + image | 1: Python backup to MinIO |
| uptime + first seen | 1: `scp` to a new host |

No single field separates them. The existing port field comes closest, which means the generator already carries the most useful single signal.

## Round 2: one more routine upload against each surviving pair

I wrote both the positives' context and the negatives, so a pair passing six hand-picked negatives proves little. Each survivor got one more plausible routine upload aimed at it:

| Pair | Broken by |
|---|---|
| port + uptime | a short Python job pushing to MinIO |
| port + first seen | a first sync to a new MinIO host |
| image + uptime | a short Python job pushing to MinIO |
| image + first seen | a Python script posting to a new SaaS API |

Every pair breaks.

## What this establishes

- **A requirement for the generator, not a reason to keep tuning Sigma predicates.** On a single upload event, exfiltration and a routine upload can show identical evidence.
- **The distinguishing behavior is across events.** The generator's own sequence is: a one-shot listener binds a high port, data goes out on that same port, and the port is released seconds later. The existing fields already link these (`port_sim`, `remote_port_sim` and `port_released_sim` share one value), but a single-event Sigma rule can't use a relationship between events.
- **Next steps:**
  1. Correlate the listener, transfer and release events. This needs a correlation (multi-event) rule, which SHENRON's evaluator doesn't support yet.
  2. Have the generator emit process lineage (which process spawned the sender) and data provenance (what was read before sending) for both the malicious and the routine sides, so the twins stay matched.

## Limits

- Every value here is synthetic, and the routine uploads are hand-written.
- Separating these fixtures would not have shown real-world detection. Failing to separate them does show that this context is insufficient.
- Found along the way: `|re` matching was broken and failed open. It's fixed in PR #75, which this experiment depends on for the uptime candidate.
