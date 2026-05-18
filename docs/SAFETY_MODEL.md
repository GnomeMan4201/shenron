# SHENRON Safety Model

## What the safety boundary means

SHENRON generates synthetic telemetry that represents the *observable shape* of
adversarial behavior — the logs and events a defender would see — without containing
the procedure that would make that behavior executable or portable.

## Safety contract fields

Every SHENRON event carries these fields:

| Field | Required value | Meaning |
|---|---|---|
| `simulation_only` | `true` | This event is synthetic. It does not represent real activity. |
| `executable` | `false` | No executable code is present or was run to produce this event. |
| `no_payload_present` | `true` | No payload, shellcode, or exploit is embedded in this artifact. |
| `subprocess_spawned` | `false` | No real subprocess was spawned to produce this event. |
| `subprocess_called` | `false` | No subprocess module call was made to produce this event. |

## What SHENRON does not contain

- Executable payloads or shellcode
- Real network connections or socket bindings
- Subprocess spawning or shell command execution
- Real file writes outside its own log directory
- Exploit code of any kind
- Portable adversarial procedures

## This is an architectural constraint, not a disclaimer

The layer loader (`discover_canonical()`) only loads canonical layers. All 50 canonical
layers were audited in v0.4.0 to verify compliance with the safety contract.
`obfuscated_skinwalker_dropper` was rewritten in v0.4.0 after audit found real
filesystem writes in the pre-v0.4.0 implementation.

## Verifying the safety contract

```bash
# Validate safety contract on any artifact
python3 shenron.py schema validate --events artifacts/demo/shenron_demo_run.jsonl

# Run dry-run across all 50 layers
python3 shenron.py run all --dry-run
```

## CLI utility subprocess use

`shenron.py` contains one `subprocess` call at line ~656, used to invoke
`scripts/generate_demo_artifacts.py` via `sys.executable`. This is a CLI utility
call to a local SHENRON helper script. It is not adversarial simulation.
