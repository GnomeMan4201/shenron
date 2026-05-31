---
title: "Running a Full Multi-Stage Intrusion Simulation. Every Detection Fired."
published: false
tags: security, blueteam, python, opensource
cover_image:
---

I've been building SHENRON for a while — a polymorphic adversarial simulation framework that generates inert adversarial-shaped telemetry for detector and governance testing.

Last week I wired up real stealth scoring. Today I ran the `apt_kill_chain` scenario end to end and validated it against the full detection expectation suite. Here's what happened.

---

## What SHENRON Is

SHENRON doesn't execute attacks. It simulates the *shape* of attacks — the behavioral signatures, telemetry patterns, and detection opportunities that real adversarial techniques produce, without the capability.

A **layer** is a self-contained behavioral simulation module with its own telemetry schema, ATT&CK mappings, and detection validation expectations. Each layer emits synthetic JSONL artifacts representing what a technique looks like to a detection system — nothing executable, nothing functional.

The safety contract enforced per-artifact:

```yaml
simulation_only: true
executable: false
no_payload_present: true
network_calls_made: false
processes_spawned: false
```

The goal: give detection engineers and SOC teams a way to test whether their systems would *see* an attack — without running one.

---

## The Scenario

Nine stages. Full ATT&CK coverage. Realistic inter-stage timing offsets.

```
[STAGE 1/9] initial_c2             — beacon_emitter_cloak      +0s
[STAGE 2/9] recon                  — lateral_webcrawler         +120s
[STAGE 3/9] persistence_plant      — dormant_sleeper_seed       +300s
[STAGE 4/9] memory_hijack          — memory_hijack_inheritor    +360s
[STAGE 5/9] cover_tracks           — anti_forensics_molt        +420s
[STAGE 6/9] masquerade             — mirror_loop_deflector      +450s
[STAGE 7/9] persistence_reinforce  — shadow_system_rebuilder    +480s
[STAGE 8/9] file_plant             — poltergeist_file_infector  +510s
[STAGE 9/9] exfil_c2               — beacon_emitter_cloak       +600s
```

ATT&CK coverage by stage:

| Stage | Techniques | Observable Class |
|-------|-----------|-----------------|
| initial_c2 | T1071, T1132 | C2 beacon, encoded comms |
| recon | T1021, T1046, T1135 | Host sweep, port scan, share enum |
| persistence_plant | T1053, T1547 | Scheduled task, boot persistence |
| memory_hijack | T1055, T1134 | Process injection, token impersonation |
| cover_tracks | T1070, T1107 | Log wipe, anti-forensics |
| masquerade | T1036, T1036.005 | Process name spoof, fake cmdline |
| persistence_reinforce | T1547, T1543 | Shadow restore, service install |
| file_plant | T1027, T1564.001 | Script modification, hidden artifact |
| exfil_c2 | T1071, T1132 | Beacon pattern replication only — no data movement |

---

## Stage by Stage

### Stage 1 — C2 Beacon Establishment

Three synthetic beacon events with realistic jitter:

```
method        : https_encoded        interval: 54.7s
dns_query_sim : mjcjbowe.metrics.example.io
method        : http_get             interval: 71.4s
user_agent    : curl/7.88.1
```

**Stealth: 80.** C2 over HTTPS with jittered intervals blends well. DNS subdomain entropy is the tell.

**Detection signals:** periodic outbound connection · DNS subdomain query · encoded URI parameter

---

### Stage 2 — Lateral Reconnaissance

8 hosts discovered, 2 targeted for deeper enumeration:

```
172.16.1.112  BACKUPHOST   → port 8080 Tomcat → /login/ /. git/ /backup/
172.16.1.113  PRINTSERVER  → port 80 Apache  → /wp-admin/ /phpmyadmin/
```

**Stealth: 78.** Sequential host sweeps are noisy. The `.git/` and `/backup/` probes are high-signal for anomaly-based detection.

**Detection signals:** subnet sweep · SMB port probe · share enumeration · sequential host requests

---

### Stage 3 — Persistence Plant

Trigger-armed persistence that waits for a condition before activating:

```
mechanism     : systemd_unit
path          : /etc/systemd/system/update-check.service
trigger_type  : port_open (localhost:4444)
check_interval: 45s
→ TRIGGER EVAL #4: condition met — activation simulated
```

**Stealth: 65.** Systemd unit creation is well-logged. Persistence layers consistently score lowest — they're hard to hide from any reasonably instrumented environment.

**Detection signals:** scheduled task creation · registry run key write · cron modification

---

### Stage 4 — Process Injection Simulation

```
/proc/6109/mem probed → stack region 0x7fff0000
injection_attempt: shellcode_stub_sim → success
token_manipulation: NetworkService impersonation
MONITOR CYCLE #3: runtime variance detected → anomaly: True
```

**Stealth: 68.** `/proc/mem` access from a non-parent process is a hard detection signal. The anomaly in cycle 3 is exactly what EDR behavioral engines catch.

**Detection signals:** proc mem access · token impersonation · RWX region write

---

### Stage 5 — Anti-Forensics

```
~/.bash_history              → truncate_to_zero
~/.local/share/recently-used.xbel → overwrite_with_decoys
  decoys: ['cat /etc/hostname', 'cd /tmp', 'echo hello world']
mtime_rollback_24h on 3 targets
```

**Stealth: 77.** Log truncation is detectable via inotify or auditd. The decoy injection looks benign on cursory inspection — but timing correlation breaks it.

**Detection signals:** log file cleared · history truncated · timestamp rollback

---

### Stage 6 — Process Masquerade

```
target_sim    : systemd-resolve (pid 5496)
cmdline_sim   : /usr/bin/systemd-resolve --daemon
DEFLECTION LOOP #3: anomaly logged
```

**Stealth: 84 — highest in the chain.** Name spoofing is hard to detect at the log level. The anomaly in loop 3 is what a behavioral engine catches: the process walks like `systemd-resolve` but doesn't talk like it.

**Detection signals:** process name spoof · fake cmdline · PID masquerade

---

### Stage 7 — Persistence Reinforcement

Self-healing persistence detects tampered files and restores from shadow copies:

```
/etc/rc.local                          hash mismatch → restored
/etc/profile.d/env.sh                  hash mismatch → restored
/etc/systemd/system/update.service     absent        → shadow copy deployed
ts_adjusted: True  (on all restores)
```

**Stealth: 65.** File integrity monitoring catches the restore. Timestamp adjustment is a second detectable signal in the same window.

**Detection signals:** file hash mismatch · unauthorized file copy · timestamp modification

---

### Stage 8 — Script Modification

Recursive home traversal, candidate selection, EOF append:

```
scan: *.py *.sh across ~/
→ ~/research_hub/utils/scan.py selected
marker appended: # SYS_UPDATE_HOOK_SIM
hash_delta: 305ff87c... → a5fe9306...
```

**Stealth: 68.** Hash change on a user script is detectable by any FIM tool. The traversal is the noisy precursor.

**Detection signals:** recursive home traversal · script file append · hash change on script

### Stage 9 — Beacon Pattern Replication

Second `beacon_emitter_cloak` pass replicating exfiltration beacon shape. DNS subdomain encoding, jittered HTTP callbacks. No data movement — beacon pattern only.

---

## Validation

```
[VALIDATION]  apt_kill_chain
[RUN_ID]      155aa94b-7cf5-4ffd-a7e4-eddea1b3f8db
[EXPECTED]    25
[OBSERVED]    25
[PARTIAL]     0
[MISSING]     0
[COVERAGE]    100.0%
[SAFETY FAIL] 0
[VERDICT]     PASS
```

25 detection expectations. 25 matched. 0 missing. 0 safety violations. 339 synthetic telemetry events.

Full detection signal map:

| Stage | Layer | Signal | MITRE |
|-------|-------|--------|-------|
| initial_c2 | beacon_emitter_cloak | periodic outbound connection | T1071 |
| initial_c2 | beacon_emitter_cloak | DNS subdomain query | T1132 |
| initial_c2 | beacon_emitter_cloak | encoded URI parameter | T1071 |
| recon | lateral_webcrawler | subnet sweep | T1046 |
| recon | lateral_webcrawler | SMB port probe | T1021 |
| recon | lateral_webcrawler | share enumeration | T1135 |
| recon | lateral_webcrawler | sequential host requests | T1046 |
| persistence_plant | dormant_sleeper_seed | scheduled task creation | T1053 |
| persistence_plant | dormant_sleeper_seed | registry run key write | T1547 |
| persistence_plant | dormant_sleeper_seed | cron modification | T1053 |
| memory_hijack | memory_hijack_inheritor | proc mem access | T1055 |
| memory_hijack | memory_hijack_inheritor | token impersonation | T1134 |
| memory_hijack | memory_hijack_inheritor | RWX region write | T1055 |
| cover_tracks | anti_forensics_molt | log file cleared | T1070 |
| cover_tracks | anti_forensics_molt | history truncated | T1107 |
| cover_tracks | anti_forensics_molt | timestamp rollback | T1070 |
| masquerade | mirror_loop_deflector | process name spoof | T1036.005 |
| masquerade | mirror_loop_deflector | fake cmdline | T1036.005 |
| masquerade | mirror_loop_deflector | PID masquerade | T1036 |
| persistence_reinforce | shadow_system_rebuilder | file hash mismatch | T1547 |
| persistence_reinforce | shadow_system_rebuilder | unauthorized file copy | T1543 |
| persistence_reinforce | shadow_system_rebuilder | timestamp modification | T1547 |
| file_plant | poltergeist_file_infector | recursive home traversal | T1564.001 |
| file_plant | poltergeist_file_infector | script file append | T1027 |
| file_plant | poltergeist_file_infector | hash change on script | T1027 |

---

## Stealth Scoring

### Model

Each layer receives a score (0–100) based on detection surface. Lower score = more detectable.

```
base_score = 100

penalties:
  3.0 per unique detection_opportunity signal (artifact-level)
  4.0 per alert_signature (manifest)
  2.0 per expected_event (manifest)
  2.5 per log source exposed

  20.0 if executable = True
  10.0 if files_created = True

bonus:
  +5.0 (one-time) if all artifacts are simulation_only + non-executable

deduplication: signals appearing in both artifact telemetry and manifest
are counted once — rewarding layers whose manifest accurately predicts
runtime behavior.
```

### Example: mirror_loop_deflector (score: 84)

```
base_score          = 100
detection_ops (3)   → -9.0
alert_sigs (3)      → -12.0
expected_events (3) → -6.0
log_sources (3)     → -7.5
dedup credit        → +13.5  (overlap between manifest and runtime signals)
simulation bonus    → +5.0
                      ──────
                        84
```

### Results

```
mirror_loop_deflector     ████████████████░░░░  84
beacon_emitter_cloak      ████████████████░░░░  80
lateral_webcrawler        ███████████████░░░░░  78
anti_forensics_molt       ███████████████░░░░░  77
memory_hijack_inheritor   █████████████░░░░░░░  68
poltergeist_file_infector █████████████░░░░░░░  68
dormant_sleeper_seed      █████████████░░░░░░░  65
shadow_system_rebuilder   █████████████░░░░░░░  65
```

C2 and evasion layers score highest — designed to blend. Persistence layers score lowest — systemd unit creation and file integrity violations are hard to hide. Memory injection sits in the middle: detectable, but requires deeper visibility than log analysis alone.

---

## What to Do With the Output

339 synthetic telemetry events, JSONL format:

```json
{
  "artifact_id": "c76c6616-764b-4e...",
  "layer": "memory_hijack_inheritor",
  "phase": "memory_probe",
  "behavior_class": "proc_mem_access",
  "mitre_techniques": ["T1055", "T1134"],
  "detection_opportunities": ["proc_mem_access", "rwx_region_write"],
  "simulation_only": true,
  "executable": false
}
```

- **SIEM rule validation** — feed the JSONL in and check which rules fire at which stage
- **Sigma rule testing** — detection signals map directly to Sigma condition fields
- **Detection model training** — synthetic labeled data for behavioral classifiers
- **SOC tabletop exercises** — replay the timeline and test analyst response
- **Coverage gap analysis** — compare `[MISSING]` expectations against your current rule set

---

## The Repo

[github.com/GnomeMan4201/shenron](https://github.com/GnomeMan4201/shenron)

```bash
git clone https://github.com/GnomeMan4201/shenron
cd shenron
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 shenron.py --scenario apt_kill_chain
python3 shenron.py --validate latest
```

Five built-in scenarios. Fifty behavioral simulation layers. All inert. Detection coverage scoring included.

---

*Observable adversarial behavior, not portable adversarial procedure.*
