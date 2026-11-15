# Exfiltration as a sequence: listener, transfer, release

**Result: the cross-event pattern carries real signal, and it gives the first brittleness measurement in SHENRON that tests attacker behavior.** It separates SHENRON's exfiltration from every routine sequence in round 1, unlike any single-event context ([EXFIL_CONTEXT_EXPERIMENT.md](EXFIL_CONTEXT_EXPERIMENT.md)). One plausible routine activity still breaks it. Simple attacker variations evade it completely.

Code: `research/exfil_sequence.py`. The outcome is pinned by `tests/test_exfil_sequence_experiment.py`. The correlation is plain Python, because SHENRON's Sigma evaluator can't correlate events yet. This experiment tests whether that support is worth building first.

## The pattern

The exfil generator emits three events that share one port, X:

1. A one-shot listener binds X (backlog 1).
2. Data goes out to remote port X, not on loopback.
3. X is released.

Events are grouped by `session_id`, which stands in for "same process on the same host". Real telemetry would group by host and process ID. Everything must happen within 60 seconds. No simulator labels are used.

## Round 1: 8 generator sequences vs 6 routine sequences

| Pattern | Detects | False positives |
|---|---|---|
| Full pattern | 8 of 8 | **0 of 6** |
| Without the one-shot check | 8 of 8 | 0 |
| Without the same-port link | 8 of 8 | 2: FTP active-mode data channel, CLI login with a one-shot OAuth callback |
| Without the loopback exclusion | 8 of 8 | 1: CI test server on loopback |
| Without the port release | 8 of 8 | 0 |

The other routine sequences were Syncthing (a persistent listener, with peers on the same port), a coincidental port match between two processes, and a plain HTTPS upload. The **same-port link and the loopback exclusion carry the signal**. The one-shot and release checks only matter together, for Syncthing.

## Round 2

One more routine activity aimed at the full pattern: **a UDP hole punch** (a short-lived socket that contacts a peer on the same port) **matches it.** Peer-to-peer apps do this, so the pattern isn't specific to exfiltration.

## Attacker variation

Each change below is something an attacker controls. Unlike the earlier mutations, these change the behavior itself, not data no rule reads. Counts are the number of the 8 sequences each pattern **misses**:

| Variation | Full pattern | Minimal (same port + non-loopback) |
|---|---|---|
| Send to 443 instead of the listener port | 8 | 8 |
| Keep the port open (no release) | 8 | 0 |
| Listener backlog 5 instead of 1 | 8 | 0 |
| Wait 90s before sending | 8 | 8 |

The minimal pattern catches two more variations but picks up Syncthing as a false positive. That's a real detection trade-off. Neither pattern survives a different port or a delay longer than the window.

## What this establishes

- **Correlation is worth building.** It is the first approach that separates these fixtures without labels, and it gives brittleness numbers that measure attacker variation, not changes to irrelevant fields.
- **The pattern is easy to evade.** It depends on choices the attacker makes: the same port, a quick release, a short delay. Report its brittleness alongside detection, never detection alone.
- **Before trusting it:**
  - add real host and process grouping instead of `session_id`;
  - add more routine sequences, especially peer-to-peer and test tooling;
  - make the window a measured parameter.

## Limits

All events are synthetic, and the routine sequences are hand-written. Separating them doesn't show real-world detection. The UDP hole-punch collision and the evasion results are findings, not fixes.
