![SHENRON](assets/shenron_banner.png)

# SHENRON

Adaptive polymorphic payload framework. Part of the BANANA_TREE ecosystem.

## Overview

SHENRON is a modular, layered framework for adversary simulation and evasion research. It organizes 40+ payload layers into functional categories and chains them through a central orchestrator.

## Structure
## Categories

| Category    | Purpose                                      |
|-------------|----------------------------------------------|
| identity    | Fingerprint spoofing, bio-replication        |
| evasion     | Anti-forensics, log sanitization, cloaking   |
| payload     | Delivery, droppers, exfil shells             |
| persistence | Sleeper seeds, memory latches, rebuilders    |
| entropy     | Mutation, quantum state shuffling            |
| c2          | Beacon emission, mesh crawling, tunneling    |
| llm         | LLM-targeted layers, shroud writers          |
| meta        | Orchestration, chain tracking, holo emitters |

## Usage
```bash
# List all discovered canonical layers
python3 shenron.py --list

# Show categories
python3 shenron.py --cats

# Dry run a category pipeline
python3 shenron.py --categories identity,evasion --dry-run

# Run full pipeline
python3 shenron.py --categories all

# Run a single layer
python3 shenron.py --layer shenron_bio_replication
```

## Status

Active development. Orchestrator operational. Layer registration coverage expanding.

## Collective

gnomeman4201 // bad_banana

---

## Launch Article

[Observable Adversarial Behavior, Not Portable Adversarial Procedure](https://dev.to/gnomeman4201/THE-ACTUAL-PUBLISHED-SLUG)
