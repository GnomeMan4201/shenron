# SHENRON Limitations

## What SHENRON is

A blue-team evidence discipline tool. It answers a specific question:

> Does this artifact support the validation claim being made about it?

## What SHENRON is not

**Not a red team tool.**
SHENRON does not perform real attacks, generate real payloads, or simulate live
adversary activity. It generates synthetic telemetry representing the observable
shape of adversarial behavior.

**Not a substitute for real artifacts.**
A TRIGGERED Sigma verdict means your rule matches the shape of the simulated
behavior in SHENRON's synthetic telemetry. It does not mean your detection stack
would catch a real attacker who might vary field values, timing, encoding, or platform.

**Not a coverage proof.**
SHENRON tells you whether your detection rules and assumption claims are consistent
with your artifacts. It does not prove your detection stack is effective against
real adversaries.

**Not a breach and attack simulation (BAS) tool.**
BAS tools execute real payloads in isolated environments. SHENRON does not execute
payloads at all. The tradeoff is safety and portability at the cost of runtime fidelity.

**Not a kernel-level or hardware-level simulator.**
SHENRON cannot test bypass techniques that rely on specific kernel-level memory
manipulations, hardware-specific quirks, or timing-dependent behavior.

## Synthetic telemetry limits

SHENRON's 50 simulation layers cover 23+ MITRE techniques across the demo artifact.
Coverage is breadth-oriented, not depth-oriented. A single technique may have one
simulation signal where a real adversary would have dozens of variants.

## The honest use case

SHENRON is most valuable for:
- Validating detection rule logic against realistic telemetry shape
- Enforcing evidence discipline — preventing overclaiming from thin artifacts
- Blue team reasoning exercises where the question is "what does this artifact support?"
- Testing SIEM ingestion and field mapping without risk

SHENRON is not a replacement for:
- Live red team exercises
- Production EDR/SIEM telemetry validation
- Adversary emulation platforms (Atomic Red Team, Caldera, etc.)

## Relationship to other tools

| Tool type | SHENRON | BAS tools | Adversary emulation |
|---|---|---|---|
| Real execution | No | Yes | Yes |
| Safe in production | Yes | No | No |
| Tests detection logic | Yes | Yes | Yes |
| Tests runtime bypass | No | Partial | Yes |
| Evidence discipline | Yes | No | No |
| Assumption validation | Yes | No | No |
