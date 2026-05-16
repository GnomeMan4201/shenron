# SHENRON v0.2.0: Reproducible Adversarial-Shaped Telemetry Without Adversarial Execution

A tool becomes easier to trust when its claims can be reproduced.

SHENRON v0.2.0 now has a one-command release demo:

```bash
git clone https://github.com/GnomeMan4201/shenron
cd shenron
python3 shenron.py --release-demo
```

That command produces a complete artifact bundle: JSONL telemetry, a markdown
report, safety contract verification, an ATT&CK Navigator layer, comparison
output placeholder, five charts, and a MANIFEST.

The point is not to simulate compromise.

The point is to make defensive assumptions inspectable without creating
portable adversarial procedure.

---

## Outline

1. The problem: detection assumptions are hard to inspect without generating risk
2. The boundary: what synthetic telemetry is and is not
3. The command: `python3 shenron.py --release-demo`
4. The artifact bundle: what each file proves
5. The safety contract: why the output is non-portable
6. The compare/Navigator workflow: where this becomes useful for blue teams
7. What v0.2.0 does not prove

---

## Key output to include

- `--release-demo` terminal output (bundle complete block)
- One JSONL record showing the full safety contract
- `--verify-safety` output (8 fields, PASS)
- `--compare apt_kill_chain persistence_runbook` showing 13 signals lost, 9 MITRE lost
- Navigator import screenshot or description

---

## Framing notes

- Lead with the gap: most detection rules have never been tested against
  realistic adversarial event sequences
- The compare output is the strongest evidence: different campaign profiles
  produce fundamentally different signal vocabularies
- Close with the Navigator angle: import the gap layer, see what your
  persistence-focused validation misses about C2 and lateral movement

---

## Do not

- Claim real ATT&CK validation
- Claim detection rules fired
- Claim this substitutes for adversarial emulation
- Use "MITRE coverage" without the synthetic qualifier

