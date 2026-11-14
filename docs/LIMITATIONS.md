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
| Safe in production | Not established (synthetic only) | No | No |
| Tests detection logic | Yes | Yes | Yes |
| Tests runtime bypass | No | Partial | Yes |
| Evidence discipline | Yes | No | No |
| Assumption validation | Yes | No | No |


## Single-assumption CLI qualification (Issue #59)

`python3 shenron.py assumption validate ASSUMPTION.yaml --events EVIDENCE.jsonl`
has a deliberately strict input/version contract:

- **Exit 0:** the aggregate assumption verdict is `SUPPORTED`, using a
  `schema_version: "1.0"` YAML and a readable evidence file.
- **Exit 1:** the YAML and evidence are interpretable but the aggregate
  verdict is `UNSUPPORTED`, `PARTIALLY_SUPPORTED`, or
  `OUT_OF_SCOPE_VIOLATION`. The verdict is printed and still recorded in
  the validation history/index as useful negative evidence. `--scope-report`
  still reports its bounded conclusion when requested.
- **Exit 3:** YAML/evidence is absent, malformed, inaccessible, or
  `schema_version` is missing or not exactly compatible with `1.0`.
  This case does not write a new validation history/index entry.

The **strict schema requirement applies only to the individual
`assumption validate` command**. Other legacy validation routes and direct
library calls retain compatibility warnings for missing/mismatched versions;
do not interpret those warnings as version qualification. This change does
not establish the meaning or integrity of external evidence or real-world
detection effectiveness.


## Canonical assumption document and evidence qualification (Issue #63)

Assumptions using the canonical YAML schema accept only four top-level keys:
`id`, `schema_version`, `description` and `claims`. Unknown keys are
rejected on every assumption load route, including library callers, because a
typo such as `claim` or `schema_versoin` would otherwise remove requirements.
This does **not** change the existing warning-only treatment of a genuinely
missing schema version for legacy library callers; strict single-assumption
CLI qualification still requires version `1.0`.

The two exact-hash-pinned historical noncanonical examples are still explicitly
**excluded**, not validated, in Audit and Quickstart. They are not a generic
exception in the canonical loader. Other paths that attempt to validate one of
these files directly must handle the resulting input error.

`validate_assumption()` requires a real regular evidence file (JSONL or graph
JSON) and raises `FileNotFoundError` for a missing or directory path. Existing
readable files containing an empty or nonmatching evidence set still produce
ordinary negative outcomes such as `UNSUPPORTED`. General-purpose
`load_artifacts()` remains optional and may return `[]` when its path
does not exist for reporting/diagnostic uses. **Do not interpret that optional
loader result as qualified evidence.**

These changes establish input *qualification*, not the provenance, truth,
or production detection validity of the supplied evidence.


## Evidence field and technique-ID qualification

An out-of-scope claim reports a technique as *absent* only after the evidence
has been read under these rules. Input that cannot be interpreted is rejected
as an input error rather than counted as absence.

- **Fields inspected.** Techniques are read only from the top-level fields
  `mitre_techniques`, `mitre_technique`, `technique` and `techniques` of each
  JSONL record. **Nested objects are not searched**: a technique placed inside
  a nested object is not inspected and is not evidence of absence or presence.
- **Field spelling.** A top-level key that differs from a recognized evidence
  field only by letter case or by `-`/space separators (for example
  `MITRE_techniques`, `Mitre-Techniques` or `Phase`) is rejected. Other unknown
  keys are allowed and ignored; generated records carry many descriptive fields.
- **Duplicate keys.** A repeated key in any JSON object, including nested
  objects, is rejected with the file and line, for every consumer of the shared
  JSONL loader (assumptions and Sigma ingestion).
- **Technique IDs.** Values in technique fields must match `T####` or
  `T####.###` after trimming whitespace and uppercasing. Anything else is
  rejected. This checks the *form* only: it does not establish that an ID
  exists in ATT&CK or that it is an appropriate mapping for the behaviour.
- **Sub-techniques.** For out-of-scope (absence) claims, a prohibited parent
  such as `T1048` is also violated by any of its sub-techniques, such as
  `T1048.003`. Positive requirements remain exact: `T1542.001` does not
  satisfy a requirement for `T1542`, and a prohibited sub-technique is not
  violated by evidence naming only its parent.
