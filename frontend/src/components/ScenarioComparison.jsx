import React, { useState, useEffect, useMemo } from 'react';
import { getJson } from '../api.js';
import { Spinner, ErrorBanner } from './shared.jsx';

export default function ScenarioComparison() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState(null);
  useEffect(() => { getJson('/api/scenarios').then(setData).catch(setErr).finally(() => setLoading(false)); }, []);

  if (loading) return <div className="page-loading"><Spinner size={24}/> running <code>shenron.py compare-scenarios</code>…</div>;
  if (err) return <ErrorBanner err={err} />;

  const scenarios = normalizeScenarios(data);
  const tactics = collectTactics(scenarios);

  return (
    <div className="view scenarios">
      <header className="view-header">
        <div><h1>Scenario Comparison</h1><p className="muted">{scenarios.length} adversary scenarios · raw vs weighted vs correlation brittleness</p></div>
      </header>
      <div className="scenario-grid">
        <div className="panel"><div className="panel-title">brittleness radar</div><RadarChart scenarios={scenarios} /></div>
        <div className="panel"><div className="panel-title">scenario × MITRE tactic heatmap</div><Heatmap scenarios={scenarios} tactics={tactics} /></div>
      </div>
      <div className="panel">
        <div className="panel-title">most brittle tactic per scenario</div>
        <div className="callout-grid">
          {scenarios.map(s => (
            <div key={s.name} className="callout-card">
              <div className="callout-name mono">{s.name}</div>
              <div className="callout-tactic">{s.mostBrittleTactic || '—'}</div>
              <div className="callout-score mono">{typeof s.maxScore === 'number' ? s.maxScore.toFixed(3) : '—'}</div>
            </div>
          ))}
          {scenarios.length === 0 && <div className="muted">no scenario data available yet — run compare-scenarios</div>}
        </div>
      </div>
      <details><summary>raw payload</summary><pre className="mono small raw-json">{JSON.stringify(data, null, 2)}</pre></details>
    </div>
  );
}

function normalizeScenarios(data) {
  if (!data) return [];
  if (Array.isArray(data)) return data.map((s, i) => normalizeScenario(s, `scenario_${i}`));
  if (Array.isArray(data.scenarios)) return data.scenarios.map((s, i) => normalizeScenario(s, `scenario_${i}`));
  if (Array.isArray(data.results)) return data.results.map((s, i) => normalizeScenario(s, `scenario_${i}`));
  if (typeof data === 'object') return Object.entries(data).filter(([k]) => !['scenarios','results','metadata','summary','_meta'].includes(k)).map(([k, v]) => normalizeScenario(v, k));
  return [];
}

function normalizeScenario(s, fallbackName) {
  if (typeof s !== 'object' || s === null) return { name: String(s), scores: {}, tactics: {} };
  const name = s.name || s.scenario || s.id || fallbackName || 'unknown';
  const scores = { raw: s.raw ?? s.raw_brittleness ?? s.scores?.raw, weighted: s.weighted ?? s.weighted_brittleness ?? s.scores?.weighted, correlation: s.correlation ?? s.correlation_brittleness ?? s.scores?.correlation };
  const tactics = s.tactics || s.by_tactic || s.mitre || s.tactic_scores || {};
  let maxScore = -1; let mostBrittleTactic = null;
  for (const [t, v] of Object.entries(tactics)) { const n = typeof v === 'number' ? v : (v?.score ?? v?.brittleness); if (typeof n === 'number' && n > maxScore) { maxScore = n; mostBrittleTactic = t; } }
  return { name, scores, tactics, maxScore: maxScore >= 0 ? maxScore : null, mostBrittleTactic };
}

function collectTactics(scenarios) {
  const s = new Set();
  for (const sc of scenarios) for (const t of Object.keys(sc.tactics || {})) s.add(t);
  return Array.from(s).sort();
}

function shortName(s) { return String(s).replace(/-style$/, '').replace(/-/g, ' ').slice(0, 18); }

function RadarChart({ scenarios }) {
  if (scenarios.length < 3) return <div className="muted">need at least 3 scenarios for radar — got {scenarios.length}<br/><br/><span style={{fontSize:11}}>Run more scenarios to populate this view.</span></div>;
  const W = 480, H = 360, cx = W / 2, cy = H / 2, R = 130;
  const n = Math.max(scenarios.length, 3);
  const angle = i => (Math.PI * 2 * i) / n - Math.PI / 2;
  const pt = (i, r) => [cx + Math.cos(angle(i)) * r, cy + Math.sin(angle(i)) * r];
  const allVals = scenarios.flatMap(s => Object.values(s.scores).filter(v => typeof v === 'number'));
  const max = Math.max(0.001, ...allVals, 1);
  const series = [{ key: 'raw', color: '#5b8def' }, { key: 'weighted', color: '#a371f7' }, { key: 'correlation', color: '#39c5cf' }];
  return (
    <svg className="radar" viewBox={`0 0 ${W} ${H}`} width={W} height={H}>
      {[0.25, 0.5, 0.75, 1].map(r => <circle key={r} cx={cx} cy={cy} r={R * r} fill="none" stroke="#2a3550" strokeWidth="0.5" />)}
      {scenarios.map((_, i) => { const [x, y] = pt(i, R); return <line key={i} x1={cx} y1={cy} x2={x} y2={y} stroke="#2a3550" strokeWidth="0.5" />; })}
      {series.map(s => {
        const pts = scenarios.map((sc, i) => { const v = sc.scores[s.key]; const r = typeof v === 'number' ? (v / max) * R : 0; return pt(i, r).join(','); }).join(' ');
        return <polygon key={s.key} points={pts} fill={s.color} fillOpacity="0.12" stroke={s.color} strokeWidth="1.5" />;
      })}
      {scenarios.map((sc, i) => { const [x, y] = pt(i, R + 22); return <text key={i} x={x} y={y} textAnchor="middle" className="radar-label" fill="#9ba8bd">{shortName(sc.name)}</text>; })}
      <g transform={`translate(10, ${H - 60})`}>
        {series.map((s, i) => <g key={s.key} transform={`translate(0, ${i * 16})`}><rect width="10" height="10" fill={s.color} /><text x="16" y="9" className="legend-text" fill="#9ba8bd">{s.key}</text></g>)}
      </g>
    </svg>
  );
}

function Heatmap({ scenarios, tactics }) {
  if (!scenarios.length || !tactics.length) return <div className="muted">no tactic-level data in compare-scenarios output</div>;
  return (
    <div className="heatmap-wrap">
      <table className="heatmap">
        <thead><tr><th></th>{tactics.map(t => <th key={t} className="heatmap-th">{t}</th>)}</tr></thead>
        <tbody>
          {scenarios.map(s => (
            <tr key={s.name}>
              <td className="heatmap-row-label mono">{shortName(s.name)}</td>
              {tactics.map(t => { const v = s.tactics?.[t]; const n = typeof v === 'number' ? v : (v?.score ?? v?.brittleness); const bg = typeof n === 'number' ? heatColor(n) : '#1a2235'; return <td key={t} className="heatmap-cell" style={{ background: bg }}>{typeof n === 'number' ? n.toFixed(2) : '·'}</td>; })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function heatColor(v) {
  if (v >= 0.5) return `rgba(248,81,73,${Math.min(1, 0.35 + v * 0.65)})`;
  if (v >= 0.3) return `rgba(212,167,44,${0.35 + v * 0.4})`;
  return `rgba(63,185,80,${0.25 + v * 0.5})`;
}
