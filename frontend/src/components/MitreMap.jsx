import React, { useState, useEffect, useMemo } from 'react';
import { getJson } from '../api.js';
import { Spinner, ErrorBanner } from './shared.jsx';

const TACTICS = ['reconnaissance','resource-development','initial-access','execution','persistence','privilege-escalation','defense-evasion','credential-access','discovery','lateral-movement','collection','command-and-control','exfiltration','impact'];

export default function MitreMap() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState(null);
  const [selected, setSelected] = useState(null);
  useEffect(() => { getJson('/api/mitre').then(setData).catch(setErr).finally(() => setLoading(false)); }, []);
  const grid = useMemo(() => buildGrid(data), [data]);
  if (loading) return <div className="page-loading"><Spinner size={24}/> building MITRE coverage map…</div>;
  if (err) return <ErrorBanner err={err} />;
  const stats = { covered: grid.filter(c => c.status === 'covered').length, empty: grid.filter(c => c.status === 'empty').length, total: grid.length };
  return (
    <div className="view mitre">
      <header className="view-header">
        <div><h1>MITRE ATT&amp;CK Coverage</h1><p className="muted">derived from sigma rule tags + <code>taxonomy/mitre_mappings.json</code></p></div>
        <div className="legend"><span className="legend-item covered">covered</span><span className="legend-item empty">no rule</span></div>
      </header>
      <div className="stats-row">
        <div className="stat"><div className="stat-label">techniques mapped</div><div className="stat-value">{stats.total}</div></div>
        <div className="stat robust"><div className="stat-label">covered</div><div className="stat-value">{stats.covered}</div></div>
        <div className="stat"><div className="stat-label">no rule</div><div className="stat-value">{stats.empty}</div></div>
      </div>
      <div className="mitre-grid">
        {TACTICS.map(tactic => {
          const cells = grid.filter(c => c.tactic === tactic);
          if (!cells.length) return null;
          return (
            <div key={tactic} className="mitre-column">
              <div className="mitre-column-header">{tactic.replace(/-/g, ' ')}</div>
              <div className="mitre-cells">
                {cells.map(c => (
                  <button key={c.technique} className={`mitre-cell ${c.status} ${selected?.technique === c.technique ? 'sel' : ''}`} onClick={() => setSelected(c)} title={`${c.technique} · ${c.status} · ${c.rules.length} rule(s)`}>
                    <span className="mitre-cell-id mono">{c.technique}</span>
                    {c.rules.length > 0 && <span className="mitre-cell-count">{c.rules.length}</span>}
                  </button>
                ))}
              </div>
            </div>
          );
        })}
      </div>
      {selected && (
        <div className="panel mitre-detail">
          <div className="panel-title">{selected.technique} <span className="muted">· {selected.tactic}</span></div>
          {selected.rules.length ? <ul className="rule-list">{selected.rules.map(p => <li key={p} className="mono">{p}</li>)}</ul> : <p className="muted">no sigma rules cover this technique</p>}
        </div>
      )}
      <details><summary>raw taxonomy + technique_rules</summary><pre className="mono small raw-json">{JSON.stringify(data, null, 2)}</pre></details>
    </div>
  );
}

function buildGrid(data) {
  if (!data) return [];
  const { taxonomy, technique_rules, technique_tactics, rules } = data;
  const seen = new Map();
  for (const r of rules || []) {
    let tac = null;
    for (const tag of r.tags || []) { if (typeof tag === 'string' && tag.startsWith('attack.') && !/^attack\.t\d/i.test(tag)) tac = tag.replace('attack.', '').replace(/_/g, '-'); }
    for (const tag of r.tags || []) {
      if (typeof tag !== 'string' || !/^attack\.t\d/i.test(tag)) continue;
      const technique = tag.split('.').pop().toUpperCase();
      if (!seen.has(technique)) seen.set(technique, { technique, tactic: tac || 'execution', rules: [], layers: [] });
      const entry = seen.get(technique);
      if (!entry.rules.includes(r.path)) entry.rules.push(r.path);
      if (tac && !entry.tactic) entry.tactic = tac;
    }
  }
  for (const [tech, paths] of Object.entries(technique_rules || {})) {
    const k = tech.toUpperCase();
    if (!seen.has(k)) seen.set(k, { technique: k, tactic: technique_tactics?.[tech] || 'execution', rules: [], layers: [] });
    const ex = seen.get(k);
    for (const p of paths) if (!ex.rules.includes(p)) ex.rules.push(p);
  }
  return Array.from(seen.values()).map(c => ({ ...c, status: c.rules.length ? 'covered' : 'empty' })).sort((a, b) => a.technique.localeCompare(b.technique));
}
