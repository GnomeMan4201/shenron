import React, { useState, useEffect, useMemo } from 'react';
import { getJson } from '../api.js';
import { Spinner, ErrorBanner } from './shared.jsx';

const DEFAULT_PATH = 'artifacts/demo/shenron_demo_run.jsonl';
const PHASE_ORDER = ['RECON','INITIAL-ACCESS','EXECUTE','PERSIST','C2','PRIV-ESC','DEFENSE-EVASION','DISCOVERY','LATERAL','COLLECT','EXFIL','IMPACT'];

export default function ArtifactInspector() {
  const [path, setPath] = useState(DEFAULT_PATH);
  const [pathInput, setPathInput] = useState(DEFAULT_PATH);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState(null);
  const [phaseFilter, setPhaseFilter] = useState('all');
  const [layerFilter, setLayerFilter] = useState('all');
  const [techFilter, setTechFilter] = useState('all');
  const [view, setView] = useState('timeline');

  const load = (p) => {
    setLoading(true); setErr(null);
    getJson(`/api/artifact?path=${encodeURIComponent(p)}`).then(setData).catch(setErr).finally(() => setLoading(false));
  };
  useEffect(() => { load(path); }, [path]);

  const events = data?.events || [];
  const phases = useMemo(() => Array.from(new Set(events.map(e => e.phase).filter(Boolean))).sort((a, b) => {
    const ia = PHASE_ORDER.indexOf(a); const ib = PHASE_ORDER.indexOf(b);
    return (ia === -1 ? 999 : ia) - (ib === -1 ? 999 : ib);
  }), [events]);
  const layers = useMemo(() => Array.from(new Set(events.map(e => e.layer).filter(Boolean))).sort(), [events]);
  const techs = useMemo(() => Array.from(new Set(events.flatMap(e => e.mitre_techniques || []).filter(Boolean))).sort(), [events]);
  const filtered = useMemo(() => events.filter(e => {
    if (phaseFilter !== 'all' && e.phase !== phaseFilter) return false;
    if (layerFilter !== 'all' && e.layer !== layerFilter) return false;
    if (techFilter !== 'all' && !(e.mitre_techniques || []).includes(techFilter)) return false;
    return true;
  }), [events, phaseFilter, layerFilter, techFilter]);
  const byPhase = useMemo(() => {
    const m = new Map();
    for (const e of filtered) { const p = e.phase || 'UNKNOWN'; if (!m.has(p)) m.set(p, []); m.get(p).push(e); }
    return Array.from(m.entries()).sort((a, b) => { const ia = PHASE_ORDER.indexOf(a[0]); const ib = PHASE_ORDER.indexOf(b[0]); return (ia === -1 ? 999 : ia) - (ib === -1 ? 999 : ib); });
  }, [filtered]);

  return (
    <div className="view artifact">
      <header className="view-header">
        <div><h1>Campaign Artifact Inspector</h1><p className="muted">{data ? `${data.count} events · ${data.path}` : 'load a JSONL artifact'}</p></div>
        <div className="view-actions">
          <input className="path-input mono" value={pathInput} onChange={e => setPathInput(e.target.value)} placeholder="artifacts/demo/shenron_demo_run.jsonl" />
          <button className="primary-btn" onClick={() => setPath(pathInput)}>load</button>
        </div>
      </header>
      {loading && <div className="page-loading"><Spinner size={24}/> parsing JSONL…</div>}
      {err && <ErrorBanner err={err} />}
      {data && !loading && (
        <>
          <div className="filter-bar">
            <div className="filter-group"><label>phase</label>
              <select value={phaseFilter} onChange={e => setPhaseFilter(e.target.value)}>
                <option value="all">all ({events.length})</option>
                {phases.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </div>
            <div className="filter-group"><label>layer</label>
              <select value={layerFilter} onChange={e => setLayerFilter(e.target.value)}>
                <option value="all">all</option>
                {layers.map(l => <option key={l} value={l}>{l}</option>)}
              </select>
            </div>
            <div className="filter-group"><label>technique</label>
              <select value={techFilter} onChange={e => setTechFilter(e.target.value)}>
                <option value="all">all</option>
                {techs.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div className="filter-group view-toggle">
              <button className={view === 'timeline' ? 'active' : ''} onClick={() => setView('timeline')}>timeline</button>
              <button className={view === 'swimlane' ? 'active' : ''} onClick={() => setView('swimlane')}>swimlane</button>
            </div>
            <div className="filter-count mono">{filtered.length} shown</div>
          </div>
          {view === 'timeline' ? (
            <div className="timeline">{filtered.map((e, i) => <EventCard key={i} event={e} index={i} />)}</div>
          ) : (
            <div className="swimlane">
              {byPhase.map(([phase, evs]) => (
                <div key={phase} className="swimlane-row">
                  <div className="swimlane-label">{phase}<br/><span className="muted">· {evs.length}</span></div>
                  <div className="swimlane-cards">{evs.map((e, i) => <EventCard key={i} event={e} index={i} compact />)}</div>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

function EventCard({ event, index, compact }) {
  const [open, setOpen] = useState(false);
  const ts = event.timestamp || event.ts;
  const matched = event._matched_rules || [];
  return (
    <div className="event-card">
      <div className="event-card-head" onClick={() => setOpen(o => !o)}>
        <span className="event-idx mono">{String(index + 1).padStart(3, '0')}</span>
        <span className="event-layer">{event.layer}</span>
        <span className="event-phase-badge">{event.phase}</span>
        <span className="event-class">{event.behavior_class}</span>
        {ts && <span className="event-ts mono muted">{ts}</span>}
        {!compact && (event.simulation_only ? <span className="badge sim">SIM</span> : <span className="badge live">LIVE</span>)}
        {matched.length > 0 && <span className="badge robust">{matched.length} RULES MATCH</span>}
      </div>
      <div className="event-card-body">
        {(event.mitre_techniques || []).length > 0 && (
          <div className="tag-list" style={{ marginBottom: 6 }}>{event.mitre_techniques.map(t => <span key={t} className="mitre-tag">{t}</span>)}</div>
        )}
        {(event.detection_opportunities || []).length > 0 && (
          <ul className="detection-opp">{event.detection_opportunities.map((d, i) => <li key={i} className="mono">{d}</li>)}</ul>
        )}
        {matched.length > 0 && (
          <div className="matched-rules">
            <div className="matched-label">matched by sigma rules</div>
            {matched.map((r, i) => <div key={i} className="matched-name">{r}</div>)}
          </div>
        )}
        {open && <pre className="mono small raw-json">{JSON.stringify(event, null, 2)}</pre>}
      </div>
    </div>
  );
}
