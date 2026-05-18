"""
SHENRON HTML Report Generator
Produces standalone HTML with inline CSS — no external dependencies.
"""
from datetime import datetime, timezone
from pathlib import Path
from core.config import get_report_dir


VERDICT_COLOR = {
    "PASS":                  "#22c55e",
    "PARTIAL":               "#f59e0b",
    "FAIL":                  "#ef4444",
    "UNSAFE":                "#dc2626",
    "SUPPORTED":             "#22c55e",
    "PARTIALLY_SUPPORTED":   "#f59e0b",
    "UNSUPPORTED":           "#ef4444",
    "OUT_OF_SCOPE_VIOLATION":"#dc2626",
    "TRIGGERED":             "#22c55e",
    "NOT_TRIGGERED":         "#ef4444",
}

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
    background: #0f172a; color: #e2e8f0;
    padding: 2rem; line-height: 1.6;
}
.container { max-width: 1100px; margin: 0 auto; }
h1 { font-size: 2rem; color: #f8fafc; margin-bottom: 0.25rem; }
h2 { font-size: 1.2rem; color: #94a3b8; margin: 2rem 0 1rem;
     border-bottom: 1px solid #1e293b; padding-bottom: 0.5rem; }
h3 { font-size: 1rem; color: #cbd5e1; margin: 1rem 0 0.5rem; }
.meta { color: #64748b; font-size: 0.85rem; margin-bottom: 2rem; }
.badge {
    display: inline-block; padding: 0.25rem 0.75rem;
    border-radius: 999px; font-weight: 700; font-size: 0.8rem;
    letter-spacing: 0.05em;
}
.card {
    background: #1e293b; border-radius: 12px;
    padding: 1.25rem 1.5rem; margin-bottom: 1rem;
    border: 1px solid #334155;
}
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th { text-align: left; color: #64748b; font-weight: 600;
     padding: 0.5rem 0.75rem; border-bottom: 1px solid #334155; }
td { padding: 0.5rem 0.75rem; border-bottom: 1px solid #1e293b; }
tr:last-child td { border-bottom: none; }
.pass   { color: #22c55e; }
.warn   { color: #f59e0b; }
.fail   { color: #ef4444; }
.unsafe { color: #dc2626; }
.mono   { font-family: monospace; font-size: 0.85rem; color: #94a3b8; }
.safety-ok   { color: #22c55e; }
.safety-fail { color: #dc2626; font-weight: 700; }
.section-header { display: flex; justify-content: space-between;
                  align-items: center; }
footer { margin-top: 3rem; color: #475569; font-size: 0.8rem;
         text-align: center; border-top: 1px solid #1e293b;
         padding-top: 1rem; }
"""


def _badge(text: str, color: str = None) -> str:
    c = color or VERDICT_COLOR.get(text, "#64748b")
    return (f'<span class="badge" style="background:{c}22;color:{c};'
            f'border:1px solid {c}44">{text}</span>')


def _verdict_class(v: str) -> str:
    if v in ("PASS", "SUPPORTED", "TRIGGERED"):       return "pass"
    if v in ("PARTIAL", "PARTIALLY_SUPPORTED"):        return "warn"
    if v in ("FAIL", "UNSUPPORTED", "NOT_TRIGGERED"):  return "fail"
    if v in ("UNSAFE", "OUT_OF_SCOPE_VIOLATION"):      return "unsafe"
    return ""


def generate_html_report(
    report_data: dict,
    output_path: str = None,
    sigma_results: list = None,
    assumption_results: list = None,
) -> str:
    """
    report_data: ShenronReport.to_dict() or similar dict with keys:
        run_id, campaign_name, timestamp, safety, coverage,
        findings, mitre_coverage
    sigma_results: list of SigmaResult.to_dict()
    assumption_results: list of AssumptionResult.to_dict()
    """
    run_id   = report_data.get("run_id", "unknown")
    campaign = report_data.get("campaign_name", "unknown")
    ts       = report_data.get("timestamp", datetime.now(timezone.utc).isoformat())[:19]
    safety   = report_data.get("safety", {})
    coverage = report_data.get("coverage", {})
    findings = report_data.get("findings", [])
    mitre    = report_data.get("mitre_coverage", {})

    safe_verdict  = safety.get("verdict", "UNKNOWN")
    safe_class    = "safety-ok" if safe_verdict not in ("UNSAFE",) else "safety-fail"
    cov_score     = coverage.get("score", 0)
    cov_verdict   = coverage.get("verdict", "UNKNOWN")

    sections = []

    # ── Header ──────────────────────────────────────────────────────────────
    sections.append(f"""
    <h1>SHENRON Detection Report</h1>
    <div class="meta">
        Run ID: <span class="mono">{run_id}</span> &nbsp;|&nbsp;
        Campaign: <span class="mono">{campaign}</span> &nbsp;|&nbsp;
        Generated: {ts} UTC
    </div>
    """)

    # ── Summary card ─────────────────────────────────────────────────────────
    sections.append(f"""
    <h2>Summary</h2>
    <div class="card">
        <table>
            <tr><th>Safety Verdict</th>
                <td class="{safe_class}">{safe_verdict}</td></tr>
            <tr><th>Coverage Score</th>
                <td class="{_verdict_class(cov_verdict)}">{cov_score:.1%} — {cov_verdict}</td></tr>
            <tr><th>Findings</th><td>{len(findings)}</td></tr>
            <tr><th>MITRE Techniques</th><td>{len(mitre)}</td></tr>
        </table>
    </div>
    """)

    # ── Safety contract ───────────────────────────────────────────────────────
    violations = safety.get("violations", [])
    sections.append(f"""
    <h2>Safety Contract</h2>
    <div class="card">
        <table>
            <tr><th>Check</th><th>Result</th></tr>
            <tr><td>simulation_only</td>
                <td class="safety-ok">&#10003; enforced</td></tr>
            <tr><td>executable: false</td>
                <td class="safety-ok">&#10003; enforced</td></tr>
            <tr><td>no_payload_present</td>
                <td class="safety-ok">&#10003; enforced</td></tr>
            <tr><td>Violations</td>
                <td class="{'safety-fail' if violations else 'safety-ok'}">
                    {len(violations)} {'&#9888; UNSAFE' if violations else '&#10003; clean'}
                </td></tr>
        </table>
    </div>
    """)

    # ── Findings ──────────────────────────────────────────────────────────────
    if findings:
        rows = ""
        for f in findings:
            layer   = f.get("layer", "")
            phase   = f.get("phase", "")
            signals = ", ".join(f.get("detection_opportunities", []))
            techs   = ", ".join(f.get("mitre_techniques", []))
            rows += f"""
            <tr>
                <td class="mono">{layer}</td>
                <td class="mono">{phase}</td>
                <td class="mono">{techs}</td>
                <td class="mono">{signals[:80]}{'...' if len(signals)>80 else ''}</td>
            </tr>"""
        sections.append(f"""
        <h2>Findings ({len(findings)})</h2>
        <div class="card">
            <table>
                <tr><th>Layer</th><th>Phase</th>
                    <th>MITRE</th><th>Signals</th></tr>
                {rows}
            </table>
        </div>
        """)

    # ── MITRE coverage ────────────────────────────────────────────────────────
    if mitre:
        rows = ""
        for tech, data in sorted(mitre.items()):
            count = data.get("count", data) if isinstance(data, dict) else data
            rows += f"<tr><td class='mono'>{tech}</td><td>{count}</td></tr>"
        sections.append(f"""
        <h2>MITRE Coverage ({len(mitre)} techniques)</h2>
        <div class="card">
            <table>
                <tr><th>Technique</th><th>Artifact Count</th></tr>
                {rows}
            </table>
        </div>
        """)

    # ── Sigma results ─────────────────────────────────────────────────────────
    if sigma_results:
        rows = ""
        for r in sigma_results:
            v    = r.get("verdict", "")
            vc   = _verdict_class(v)
            rows += f"""
            <tr>
                <td class="mono">{r.get('rule_id','')}</td>
                <td>{r.get('rule_title','')}</td>
                <td class="{vc}">{v}</td>
                <td>{r.get('triggered_count', 0)}</td>
            </tr>"""
        sections.append(f"""
        <h2>Sigma Rule Validation ({len(sigma_results)} rules)</h2>
        <div class="card">
            <table>
                <tr><th>Rule ID</th><th>Title</th>
                    <th>Verdict</th><th>Triggered</th></tr>
                {rows}
            </table>
        </div>
        """)

    # ── Assumption results ────────────────────────────────────────────────────
    if assumption_results:
        rows = ""
        for r in assumption_results:
            v  = r.get("status", "")
            vc = _verdict_class(v)
            rows += f"""
            <tr>
                <td class="mono">{r.get('assumption_id','')}</td>
                <td class="{vc}">{v}</td>
                <td>{r.get('supported_count',0)}</td>
                <td>{r.get('unsupported_count',0)}</td>
                <td class="mono" style="font-size:0.8rem">
                    {', '.join(r.get('out_of_scope_violations',[]))}</td>
            </tr>"""
        sections.append(f"""
        <h2>Assumption Validation ({len(assumption_results)} assumptions)</h2>
        <div class="card">
            <table>
                <tr><th>Assumption</th><th>Status</th>
                    <th>Supported</th><th>Unsupported</th>
                    <th>OOS Violations</th></tr>
                {rows}
            </table>
        </div>
        """)

    # ── Safe conclusion ───────────────────────────────────────────────────────
    conclusions = []
    if assumption_results:
        for r in assumption_results:
            sc = r.get("safe_conclusion", "")
            if sc:
                conclusions.append(f"<p style='margin-bottom:0.5rem'>{sc}</p>")
    if conclusions:
        sections.append(f"""
        <h2>Safe Conclusion</h2>
        <div class="card">
            {"".join(conclusions)}
        </div>
        """)

    # ── Footer ────────────────────────────────────────────────────────────────
    sections.append("""
    <footer>
        Generated by SHENRON &mdash;
        Observable adversarial behavior, not portable adversarial procedure.
    </footer>
    """)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SHENRON Report — {run_id}</title>
<style>{CSS}</style>
</head>
<body>
<div class="container">
{"".join(sections)}
</div>
</body>
</html>"""

    if output_path is None:
        out_dir = get_report_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        fname = f"report_{run_id}.html"
        output_path = str(out_dir / fname)

    Path(output_path).write_text(html)
    return output_path
