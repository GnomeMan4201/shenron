import React, { useState, useRef } from 'react';
import { streamSse } from '../api.js';
import { Spinner, ErrorBanner } from './shared.jsx';

export default function AdaptationView() {
  const [running, setRunning] = useState(false);
  const [iterations, setIterations] = useState([]);
  const [err, setErr] = useState(null);
  const [done, setDone] = useState(null);
  const abortRef = useRef(null);

  const run = async () => {
    setRunning(true); setErr(null); setIterations([]); setDone(null);
    const ctrl = new AbortController(); abortRef.current = ctrl;
    try {
      await streamSse({
        url: '/api/adaptation', body: { max_iterations: 8 }, signal: ctrl.signal,
        onEvent: ({ event, data }) => {
          if (event === 'iteration') setIterations(a => [...a, data]);
          else if (event === 'done') { setDone(data); setRunning(false); }
          else if (event === 'error') { setErr(new Error(data.error || 'adaptation error')); setRunning(false); }
        },
      });
    } catch (e) {
      if (e.name !== 'AbortError') setErr(e);
      setRunning(false);
    }
  };

  const stop = () => { abortRef.current?.abort(); setRunning(false); };

  return (
    <div className="view adaptation">
      <header className="view-header">
        <div><h1>Adaptation Engine — Live</h1><p className="muted">runs <code>core.campaign.adaptation.run_adaptation</code> · feedback-driven strategy selection</p></div>
        <div className="view-actions">
          {!running ? <button className="primary-btn" onClick={run}>▶ run adaptation</button> : <button className="danger-btn" onClick={stop}>■ stop</button>}
        </div>
      </header>
      {err && <ErrorBanner err={err} />}
      {(iterations.length > 0 || running) && (
        <div className="adapt-layout">
          <div className="panel"><div className="panel-title">convergence — rules firing per iteration</div><ConvergenceChart iterations={iterations} /></div>
          <div className="panel">
            <div className="panel-title">final state</div>
            {done ? (
              <ul className="final-list">
                <li>iterations run: <b className="mono">{iterations.length}</b></li>
                <li>evasion achieved: <b className="mono">{String(done.evasion_achieved)}</b></li>
                {done.iterations_to_evasion && <li>iterations to evasion: <b className="mono">{done.iterations_to_evasion}</b></li>}
                {Array.isArray(done.surviving_rules) && done.surviving_rules.length > 0 && (
                  <li className="survivors">
                    <h5>detection-robust (survived all mutations)</h5>
                    <ul>{done.surviving_rules.map((s, i) => <li key={i} className="mono">{s}</li>)}</ul>
                  </li>
                )}
                {Array.isArray(done.evaded_rules) && done.evaded_rules.length > 0 && (
                  <li className="survivors">
                    <h5>evaded</h5>
                    <ul>{done.evaded_rules.map((s, i) => <li key={i} className="mono">{s}</li>)}</ul>
                  </li>
                )}
              </ul>
            ) : <div className="page-loading"><Spinner size={16}/> running…</div>}
          </div>
        </div>
      )}
      <div className="panel">
        <div className="panel-title">iteration log</div>
        <div className="iter-log">
          {iterations.length === 0 && !running && <p className="muted">press "run adaptation" to begin</p>}
          {iterations.map((it, i) => (
            <div key={i} className="iter-row">
              <span className="iter-idx mono">#{String(i + 1).padStart(3, '0')}</span>
              <span className="iter-strategy">{it.strategy || it.mutation_applied || '—'}</span>
              <span className="iter-firing mono">firing: {it.rules_firing_count ?? '—'}</span>
              <span className="iter-evasion mono">rate: {typeof it.evasion_rate === 'number' ? it.evasion_rate.toFixed(3) : '—'}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ConvergenceChart({ iterations }) {
  const W = 560, H = 220, pad = 30;
  const vals = iterations.map(it => it.rules_firing_count ?? 0);
  if (vals.length < 2) return <div className="muted">awaiting more iterations… ({vals.length} so far)</div>;
  const max = Math.max(...vals, 1);
  const stepX = (W - pad * 2) / Math.max(1, vals.length - 1);
  const points = vals.map((v, i) => [pad + i * stepX, H - pad - (v / max) * (H - pad * 2)]);
  const path = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${p[0]},${p[1]}`).join(' ');
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width={W} height={H} style={{ maxWidth: '100%' }}>
      {[0, 0.25, 0.5, 0.75, 1].map(t => <line key={t} x1={pad} y1={H - pad - t * (H - pad * 2)} x2={W - pad} y2={H - pad - t * (H - pad * 2)} stroke="#2a3550" strokeWidth="0.5" />)}
      <path d={path} fill="none" stroke="#5b8def" strokeWidth="2" />
      {points.map((p, i) => <circle key={i} cx={p[0]} cy={p[1]} r="3" fill="#5b8def" />)}
      <text x={pad} y={H - 8} className="axis-label" fill="#6b7896">iteration</text>
      <text x={pad - 8} y={pad} className="axis-label" fill="#6b7896" textAnchor="end">firing</text>
    </svg>
  );
}
