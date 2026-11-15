# Exfiltration as a sequence: listener, transfer, release

**Result: invalidated.** The cross-event pattern separated a hand-picked set of routine sequences (round 1). It fails the cheapest test that could break it: routine protocols that send from port X to port X by design, with the same timing (round 3). **It fires on 10 of 10.** Restricting it to ephemeral ports still fires on 3 of 10, and an attacker defeats that restriction by choosing a low port. Port-plus-timing is not an exfiltration signal. Rounds 1 and 2 below are kept as the record of how that looked before round 3.

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

## Round 3: routine same-port protocols, same timing

Ten routine protocols that use the same port on both ends, each as a short-lived sequence: bind, send within a second, release within two. They are NTP (123), mDNS (5353), SSDP (1900), NetBIOS (137), IKE (500), BitTorrent DHT (6881), WireGuard (51820), a WebRTC ICE check, a Tailscale probe and a game client's NAT punch.

| Pattern | Fires on |
|---|---|
| Full pattern | **10 of 10** |
| Full pattern, ephemeral ports only (49152+) | 3 of 10: WireGuard, WebRTC, game NAT punch |

The ephemeral-port restriction is also evaded by an attacker who uses port 123: 8 of 8 sequences missed.

## What this establishes

- **Port relationship and timing do not identify exfiltration.** Round 1 looked clean only because of which routine sequences were chosen. Round 3 shows the same shape is everyday network behavior.
- **The attacker-variation results still stand as method.** They change what the rule actually reads, so they are the right kind of brittleness test. The thing they were testing just turned out not to be a signal.
- **The requirement from the single-event experiment stands.** What separates exfiltration from routine transfers isn't in network events alone. It is in process lineage (what spawned the sender) and data provenance (what was read before sending). The generator emits neither, for either side.
- **Correlation support in the evaluator is not justified by this pattern.** Build it only for a pattern that first survives a round-3-style test in plain Python. That needs the evidence above, emitted by the generator for both exfiltration and its routine twins.

## Limits

All events are synthetic, and the routine sequences are hand-written. Separating them doesn't show real-world detection. The UDP hole-punch collision and the evasion results are findings, not fixes.
