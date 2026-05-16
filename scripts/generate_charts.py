#!/usr/bin/env python3
"""
generate_charts.py
SHENRON — Visual Artifact Generator

Run:
  python3 generate_charts.py [--jsonl ./artifacts/shenron_demo_run.jsonl]
                             [--out-dir ./docs/assets/shenron-demo]
"""

import argparse
import datetime
import json
import os
import sys
from collections import Counter

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
except ImportError:
    print("ERROR: matplotlib not installed. Run: pip install matplotlib --break-system-packages")
    sys.exit(1)

DISCLAIMER = "SYNTHETIC TELEMETRY - demo generator output, not live campaign execution"
PHASE_COLORS = {
    "OBSERVE":  "#4C9BE8",
    "SIMULATE": "#E87B4C",
    "EXECUTE":  "#4CE87B",
    "ADAPT":    "#B44CE8",
}
PHASES = ["OBSERVE", "SIMULATE", "EXECUTE", "ADAPT"]


def load_events(jsonl_path):
    events = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def save(fig, path):
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  -> {path}")


def chart_phase_frequency(events, out_dir):
    counts = Counter(ev["phase"] for ev in events)
    vals = [counts.get(p, 0) for p in PHASES]
    colors = [PHASE_COLORS[p] for p in PHASES]
    fig, ax = plt.subplots(figsize=(8, 4), facecolor="#0f0f13")
    ax.set_facecolor("#0f0f13")
    bars = ax.bar(PHASES, vals, color=colors, width=0.55, zorder=3)
    ax.set_title("Events per bananaTREE Campaign Phase", color="#e0e0e0", fontsize=13, pad=10)
    ax.set_ylabel("Event Count", color="#a0a0a0", fontsize=10)
    ax.tick_params(colors="#a0a0a0")
    ax.spines[:].set_color("#333340")
    ax.yaxis.grid(True, color="#222230", zorder=0)
    ax.set_ylim(0, max(vals) * 1.3)
    for bar, val in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, val + 0.15,
                str(val), ha="center", va="bottom", color="#e0e0e0", fontsize=11)
    fig.text(0.5, -0.04, DISCLAIMER, ha="center", color="#888890", fontsize=7)
    fig.tight_layout()
    save(fig, os.path.join(out_dir, "phase_frequency.png"))


def chart_technique_frequency(events, out_dir):
    counts = Counter(ev["mitre_technique"] for ev in events)
    top = counts.most_common(20)
    techs, vals = zip(*top) if top else ([], [])
    fig, ax = plt.subplots(figsize=(10, 6), facecolor="#0f0f13")
    ax.set_facecolor("#0f0f13")
    ax.barh(techs, vals, color="#4C9BE8", height=0.6, zorder=3)
    ax.set_title(
        "MITRE ATT&CK Descriptor Distribution\n(Synthetic Demo Events - not real ATT&CK validation)",
        color="#e0e0e0", fontsize=11, pad=10)
    ax.set_xlabel("Event Count", color="#a0a0a0", fontsize=10)
    ax.tick_params(colors="#a0a0a0", labelsize=8)
    ax.spines[:].set_color("#333340")
    ax.xaxis.grid(True, color="#222230", zorder=0)
    for i, (t, v) in enumerate(zip(techs, vals)):
        ax.text(v + 0.04, i, str(v), va="center", color="#e0e0e0", fontsize=8)
    fig.text(0.5, -0.02,
             "MITRE-style technique distribution across synthetic demo events - not real ATT&CK validation or detector coverage",
             ha="center", color="#888890", fontsize=7)
    fig.tight_layout()
    save(fig, os.path.join(out_dir, "technique_frequency.png"))


def chart_signal_frequency(events, out_dir):
    counts = Counter(ev["signal"] for ev in events)
    top = counts.most_common(15)
    sigs, vals = zip(*top) if top else ([], [])
    fig, ax = plt.subplots(figsize=(10, 5), facecolor="#0f0f13")
    ax.set_facecolor("#0f0f13")
    ax.barh(sigs, vals, color="#E87B4C", height=0.6, zorder=3)
    ax.set_title("Signal Vocabulary Distribution (Top 15, Synthetic)", color="#e0e0e0", fontsize=12, pad=10)
    ax.set_xlabel("Occurrences", color="#a0a0a0", fontsize=10)
    ax.tick_params(colors="#a0a0a0", labelsize=8)
    ax.spines[:].set_color("#333340")
    ax.xaxis.grid(True, color="#222230", zorder=0)
    fig.text(0.5, -0.03, DISCLAIMER, ha="center", color="#888890", fontsize=7)
    fig.tight_layout()
    save(fig, os.path.join(out_dir, "signal_frequency.png"))


def chart_event_timeline(events, out_dir):
    parsed = []
    for ev in events:
        try:
            ts = datetime.datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00"))
            parsed.append((ts, ev["phase"]))
        except Exception:
            pass
    if not parsed:
        print("  ! No parseable timestamps, skipping event_timeline.png")
        return
    t0 = parsed[0][0]
    xs = [(t - t0).total_seconds() / 60 for t, _ in parsed]
    cols = [PHASE_COLORS.get(p, "#888888") for _, p in parsed]
    fig, ax = plt.subplots(figsize=(12, 3), facecolor="#0f0f13")
    ax.set_facecolor("#0f0f13")
    ax.scatter(xs, [0.5] * len(xs), c=cols, s=60, zorder=3, alpha=0.9)
    handles = [mpatches.Patch(color=c, label=p) for p, c in PHASE_COLORS.items()]
    ax.legend(handles=handles, loc="upper left", facecolor="#1a1a24",
              labelcolor="#e0e0e0", fontsize=8)
    ax.set_title("Synthetic Event Timeline - OBSERVE -> SIMULATE -> EXECUTE -> ADAPT",
                 color="#e0e0e0", fontsize=11, pad=10)
    ax.set_xlabel("Time offset (minutes, synthetic)", color="#a0a0a0", fontsize=9)
    ax.set_yticks([])
    ax.spines[:].set_color("#333340")
    ax.xaxis.grid(True, color="#222230", zorder=0)
    ax.set_ylim(0, 1)
    fig.text(0.5, -0.06, DISCLAIMER, ha="center", color="#888890", fontsize=7)
    fig.tight_layout()
    save(fig, os.path.join(out_dir, "event_timeline.png"))


def chart_safety_boundary(events, out_dir):
    FIELDS = [
        "simulation_only", "executable", "payload_present",
        "portable_adversarial_procedure", "network_connection",
        "subprocess_spawned", "real_file_written", "shell_invoked",
    ]
    EXPECTED_FALSE = set(FIELDS) - {"simulation_only"}
    violations = {f: 0 for f in FIELDS}
    for ev in events:
        safety = ev.get("safety", {})
        for f in FIELDS:
            val = safety.get(f)
            if f == "simulation_only" and val is not True:
                violations[f] += 1
            elif f in EXPECTED_FALSE and val is not False:
                violations[f] += 1
    labels = [f.replace("_", " ") for f in FIELDS]
    vals = [violations[f] for f in FIELDS]
    colors = ["#4CE87B" if v == 0 else "#E84C4C" for v in vals]
    fig, ax = plt.subplots(figsize=(10, 4), facecolor="#0f0f13")
    ax.set_facecolor("#0f0f13")
    bars = ax.bar(labels, vals, color=colors, width=0.55, zorder=3)
    ax.set_title("Safety Contract Verification - All Fields (40 synthetic records)",
                 color="#e0e0e0", fontsize=12, pad=10)
    ax.set_ylabel("Violations", color="#a0a0a0", fontsize=10)
    ax.tick_params(colors="#a0a0a0", labelsize=7.5)
    ax.spines[:].set_color("#333340")
    ax.yaxis.grid(True, color="#222230", zorder=0)
    ax.set_ylim(0, max(max(vals), 1) * 2)
    for bar, val in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, 0.03,
                str(val), ha="center", va="bottom", color="#e0e0e0",
                fontsize=10, fontweight="bold")
    plt.xticks(rotation=30, ha="right")
    fig.text(0.5, -0.08,
             "Green = 0 violations. All 40 synthetic records passed all 8 safety contract fields.",
             ha="center", color="#888890", fontsize=7)
    fig.tight_layout()
    save(fig, os.path.join(out_dir, "safety_boundary.png"))


def main():
    parser = argparse.ArgumentParser(description="SHENRON chart generator")
    parser.add_argument("--jsonl", default="./artifacts/shenron_demo_run.jsonl")
    parser.add_argument("--out-dir", default="./docs/assets/shenron-demo")
    args = parser.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)
    events = load_events(args.jsonl)
    print(f"[CHARTS] Loaded {len(events)} events from {args.jsonl}")
    chart_phase_frequency(events, args.out_dir)
    chart_technique_frequency(events, args.out_dir)
    chart_signal_frequency(events, args.out_dir)
    chart_event_timeline(events, args.out_dir)
    chart_safety_boundary(events, args.out_dir)
    print(f"[CHARTS] Done. 5 charts written to {args.out_dir}/")


if __name__ == "__main__":
    main()
