#!/usr/bin/env python3
# SHENRON: Coverage history tracker
# Reads the run timeline, groups runs by campaign, builds coverage snapshots,
# detects technique drift, and produces a trend report + chart.
# No subprocess, no network, no execution.

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ── Snapshot dataclass ────────────────────────────────────────────────────────

@dataclass
class CoverageSnapshot:
    run_id:        str
    campaign_name: str
    timestamp:     str
    run_type:      str          # "bananatree" | "scenario"
    techniques:    List[str]    = field(default_factory=list)
    technique_count: int        = 0
    phase_count:   int          = 0


@dataclass
class CampaignHistory:
    campaign_name:  str
    snapshots:      List[CoverageSnapshot] = field(default_factory=list)

    def technique_sets(self) -> List[Set[str]]:
        return [set(s.techniques) for s in self.snapshots]

    def drift_events(self) -> List[dict]:
        """Identify runs where techniques were added or dropped."""
        events = []
        sets = self.technique_sets()
        for i in range(1, len(sets)):
            gained = sorted(sets[i] - sets[i-1])
            lost   = sorted(sets[i-1] - sets[i])
            if gained or lost:
                events.append({
                    "from_run":    self.snapshots[i-1].run_id[:8],
                    "to_run":      self.snapshots[i].run_id[:8],
                    "from_ts":     self.snapshots[i-1].timestamp[:10],
                    "to_ts":       self.snapshots[i].timestamp[:10],
                    "gained":      gained,
                    "lost":        lost,
                    "net":         len(gained) - len(lost),
                })
        return events


@dataclass
class HistoryReport:
    campaigns:         Dict[str, CampaignHistory] = field(default_factory=dict)
    total_runs:        int   = 0
    total_campaigns:   int   = 0
    drift_detected:    bool  = False
    generated_at:      str   = ""


# ── Builder ───────────────────────────────────────────────────────────────────

def build_history(runs: List[dict]) -> HistoryReport:
    """
    Build a HistoryReport from a list of run dicts
    (as returned by get_campaign_runs).
    """
    campaigns: Dict[str, CampaignHistory] = {}
    now = datetime.now(timezone.utc).isoformat()

    for run in runs:
        campaign = run.get("campaign_name", "unknown")
        run_id   = run.get("run_id", "")
        ts       = run.get("timestamp", "")
        run_type = run.get("_type", "bananatree")
        techniques = run.get("all_mitre", [])
        phases   = run.get("phases", [])

        snap = CoverageSnapshot(
            run_id        = run_id,
            campaign_name = campaign,
            timestamp     = ts,
            run_type      = run_type,
            techniques    = sorted(techniques),
            technique_count = len(techniques),
            phase_count   = len(phases),
        )

        if campaign not in campaigns:
            campaigns[campaign] = CampaignHistory(campaign_name=campaign)
        campaigns[campaign].snapshots.append(snap)

    drift_detected = any(
        len(hist.drift_events()) > 0
        for hist in campaigns.values()
        if len(hist.snapshots) > 1
    )

    return HistoryReport(
        campaigns       = campaigns,
        total_runs      = len(runs),
        total_campaigns = len(campaigns),
        drift_detected  = drift_detected,
        generated_at    = now,
    )


# ── Report formatter ──────────────────────────────────────────────────────────

def to_markdown(report: HistoryReport, max_runs_per_campaign: int = 10) -> str:
    lines = [
        "# SHENRON Coverage History Report",
        "",
        "> **SYNTHETIC TELEMETRY** — Coverage figures represent MITRE-style",
        "> descriptor presence in synthetic telemetry runs.",
        "> Not real ATT&CK validation or confirmed detector coverage.",
        "",
        f"**Generated:** {report.generated_at[:19]} UTC  ",
        f"**Total runs:** {report.total_runs}  ",
        f"**Campaigns:** {report.total_campaigns}  ",
        f"**Drift detected:** {'Yes ⚠' if report.drift_detected else 'No ✓'}  ",
        "",
        "---",
        "",
        "## Campaign Coverage Trend",
        "",
    ]

    for campaign_name, hist in sorted(report.campaigns.items()):
        snaps = hist.snapshots
        lines += [
            f"### {campaign_name}",
            f"",
            f"**Runs:** {len(snaps)}  ",
        ]

        if len(snaps) == 0:
            lines += ["No runs recorded.", ""]
            continue

        # Show most recent N runs
        recent = snaps[-max_runs_per_campaign:]
        lines += [
            f"",
            f"| Run | Date | Techniques | Delta |",
            f"|-----|------|:----------:|------:|",
        ]

        prev_count = None
        for snap in recent:
            delta_str = "—"
            if prev_count is not None:
                delta = snap.technique_count - prev_count
                if delta > 0:
                    delta_str = f"+{delta}"
                elif delta < 0:
                    delta_str = str(delta)
                else:
                    delta_str = "0"
            lines.append(
                f"| `{snap.run_id[:8]}` | {snap.timestamp[:10]} "
                f"| {snap.technique_count} | {delta_str} |"
            )
            prev_count = snap.technique_count

        # Drift events
        drift = hist.drift_events()
        if drift:
            lines += [
                f"",
                f"**Technique drift events:** {len(drift)}",
                f"",
            ]
            for ev in drift[-5:]:  # show last 5 drift events
                if ev["gained"]:
                    lines.append(
                        f"- `{ev['from_run']}` → `{ev['to_run']}` "
                        f"({ev['from_ts']} → {ev['to_ts']}): "
                        f"**gained** {', '.join(ev['gained'])}"
                    )
                if ev["lost"]:
                    lines.append(
                        f"- `{ev['from_run']}` → `{ev['to_run']}` "
                        f"({ev['from_ts']} → {ev['to_ts']}): "
                        f"**lost** {', '.join(ev['lost'])}"
                    )
        else:
            if len(snaps) > 1:
                lines += ["", "No technique drift detected across runs.", ""]

        # Current technique set
        if snaps:
            last = snaps[-1]
            if last.techniques:
                lines += [
                    f"",
                    f"**Current techniques ({len(last.techniques)}):**  ",
                    f"{', '.join(last.techniques)}",
                    f"",
                ]
        lines.append("")

    lines += [
        "---",
        "",
        "## Drift Summary",
        "",
    ]

    all_drift = []
    for hist in report.campaigns.values():
        for ev in hist.drift_events():
            ev["campaign"] = hist.campaign_name
            all_drift.append(ev)

    if not all_drift:
        lines += [
            "No technique drift detected across any campaign.",
            "All runs within each campaign produced consistent technique sets.",
            "",
        ]
    else:
        lines += [
            f"**{len(all_drift)} drift events** detected across "
            f"{len(report.campaigns)} campaigns.",
            "",
            "| Campaign | From | To | Gained | Lost | Net |",
            "|----------|------|-----|-------:|-----:|----:|",
        ]
        for ev in all_drift[-20:]:
            gained_str = ", ".join(ev["gained"]) if ev["gained"] else "—"
            lost_str   = ", ".join(ev["lost"])   if ev["lost"]   else "—"
            lines.append(
                f"| {ev['campaign']} | `{ev['from_run']}` | `{ev['to_run']}` "
                f"| {gained_str} | {lost_str} | {ev['net']:+d} |"
            )
        lines.append("")

    lines += [
        "---",
        "",
        "## What this does not prove",
        "",
        "- That technique coverage in SHENRON equals coverage in production",
        "- That dropped techniques are no longer detectable",
        "- That gained techniques are newly detectable",
        "- That drift in synthetic telemetry correlates with drift in real detection",
        "",
        "---",
        "",
        "*SHENRON — Observable adversarial behavior, not portable adversarial procedure.*",
    ]

    return "\n".join(lines)


def to_json(report: HistoryReport) -> str:
    data = {
        "generated_at":    report.generated_at,
        "total_runs":      report.total_runs,
        "total_campaigns": report.total_campaigns,
        "drift_detected":  report.drift_detected,
        "simulation_only": True,
        "campaigns": {
            name: {
                "run_count": len(hist.snapshots),
                "drift_events": len(hist.drift_events()),
                "snapshots": [
                    {
                        "run_id":          s.run_id[:8],
                        "timestamp":       s.timestamp[:19],
                        "type":            s.run_type,
                        "technique_count": s.technique_count,
                        "techniques":      s.techniques,
                    }
                    for s in hist.snapshots[-20:]  # cap at 20 per campaign
                ],
            }
            for name, hist in report.campaigns.items()
        },
    }
    return json.dumps(data, indent=2)


def print_history_summary(report: HistoryReport):
    print()
    print(f"  [HISTORY]     {report.total_runs} runs · {report.total_campaigns} campaigns")
    print()

    for name, hist in sorted(report.campaigns.items()):
        snaps = hist.snapshots
        if not snaps:
            continue
        first = snaps[0]
        last  = snaps[-1]
        drift = hist.drift_events()
        drift_indicator = f"  ⚠ {len(drift)} drift events" if drift else ""
        print(
            f"  {name:<40} "
            f"{len(snaps):>4} runs  "
            f"{last.technique_count:>3} techniques"
            f"{drift_indicator}"
        )

    if report.drift_detected:
        print()
        print(f"  [DRIFT]       Technique changes detected — see report for details")
    else:
        print()
        print(f"  [DRIFT]       No technique drift detected")
    print()


def generate_history_chart(report: HistoryReport, out_path: str):
    """Generate a technique count trend chart for all campaigns."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return False

    fig, ax = plt.subplots(figsize=(12, 5), facecolor="#0f0f13")
    ax.set_facecolor("#0f0f13")

    COLORS = [
        "#4C9BE8", "#E87B4C", "#4CE87B", "#B44CE8",
        "#E84C9B", "#9BE84C", "#4CE8B4", "#E8C44C",
    ]

    plotted = 0
    for i, (name, hist) in enumerate(sorted(report.campaigns.items())):
        snaps = hist.snapshots
        if len(snaps) < 2:
            continue
        color = COLORS[i % len(COLORS)]
        xs = list(range(len(snaps)))
        ys = [s.technique_count for s in snaps]
        ax.plot(xs, ys, color=color, linewidth=2, marker="o", markersize=4,
                label=name, alpha=0.9)
        plotted += 1

    if plotted == 0:
        # Single-run campaigns — show bar chart instead
        names = sorted(report.campaigns.keys())
        counts = [
            report.campaigns[n].snapshots[-1].technique_count
            if report.campaigns[n].snapshots else 0
            for n in names
        ]
        ax.bar(names, counts, color=COLORS[:len(names)], width=0.55, zorder=3)
        ax.set_xlabel("Campaign", color="#a0a0a0", fontsize=9)
        plt.xticks(rotation=30, ha="right")
    else:
        ax.set_xlabel("Run sequence", color="#a0a0a0", fontsize=9)
        ax.legend(facecolor="#1a1a24", labelcolor="#e0e0e0", fontsize=8)

    ax.set_title("MITRE Descriptor Coverage Trend (Synthetic Runs)",
                 color="#e0e0e0", fontsize=12, pad=10)
    ax.set_ylabel("Technique count", color="#a0a0a0", fontsize=10)
    ax.tick_params(colors="#a0a0a0")
    ax.spines[:].set_color("#333340")
    ax.yaxis.grid(True, color="#222230", zorder=0)
    fig.text(
        0.5, -0.04,
        "SYNTHETIC TELEMETRY — not real ATT&CK validation or detector coverage",
        ha="center", color="#888890", fontsize=7
    )
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close(fig)
    return True
