# SHENRON Dashboard — Setup

## Prerequisites
- Python 3.10+ with SHENRON dependencies installed
- Node.js 18+ and npm

## Installation

From the SHENRON repo root:

```bash
# 1. Copy all dashboard files into repo
cp -r shenron-dashboard/* ~/research_hub/shenron/

# 2. Install Flask
pip install flask --break-system-packages

# 3. Build the React frontend (one-time, ~60 seconds)
cd frontend
npm install
npm run build
cd ..

# 4. Launch
python3 app.py
```

Then open: http://localhost:5000

## Development mode (hot reload)

```bash
# Terminal 1: Flask backend
python3 app.py

# Terminal 2: Vite dev server (proxies /api to Flask)
cd frontend
npm run dev
```

Then open: http://localhost:5173

## What each view does

| View | What runs |
|---|---|
| Brittleness Scoreboard | core.sigma.evaluator.evaluate_sigma_rule + _score_brittleness per rule |
| Campaign Artifact | Loads JSONL, correlates events to sigma rules via MITRE tags |
| Scenario Comparison | python3 shenron.py compare-scenarios --format json |
| MITRE Coverage | taxonomy/mitre_mappings.json + sigma rule tags |
| Adaptation Engine | core.campaign.adaptation.run_adaptation (SSE stream) |
| Drift widget (sidebar) | python3 -m core.ci.drift_gate --quiet |

## Pointing at your own Sigma rules

In the Brittleness Scoreboard, validation always runs against sigma/rules/.
To validate your own rules, copy them into sigma/rules/custom/ and they
will be picked up automatically.

## Environment variable

Set PORT to change the Flask port:
    PORT=8080 python3 app.py
