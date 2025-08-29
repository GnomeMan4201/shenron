# SHENRON (Research Edition)

**Status:** pre-release | **Author:** Aaron Brosch (@YOUR_GITHUB_USERNAME)

SHENRON is an **adaptive red-team research framework** focused on **controlled, authorized testing** and **defensive simulation**. The goal is to explore techniques such as modular orchestration, decoying, and resilience under blue-team pressure **in lab environments**.

> ⚠️ **Ethics & Legal**  
> This project is for **research and education**, and for use **only** on systems you own or have *explicit written permission* to test. You are responsible for obeying laws and regulations.

## Highlights (Research Goals)
- Modular orchestrator with pluggable components.
- Emphasis on telemetry, observability, and replay in labs.
- Mutation sandbox for *benign* test fixtures and evasive-decoy research.
- Strict separation between core orchestration and any environment-specific modules.

## Quick start (dev)
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
make test
```

## Documentation
- See `/docs/` for architecture and module contracts.
- See `/examples/` for safe, local-only demos.

## Security / Responsible Disclosure
See [SECURITY.md](SECURITY.md).

## License
MIT (see [LICENSE](LICENSE))

## Links
- Part 1: https://dev.to/gnomeman4201/shenron-designing-adaptive-persistent-offense-for-the-real-world-part-1-3ooj
- Part 2: https://dev.to/gnomeman4201/shenron-part-2-anatomy-of-a-shape-shifter-inside-the-framework-1nk5
- Part 3: https://dev.to/gnomeman4201/shenron-part-3-mutation-misdirection-and-modern-anti-forensics-3dpp
