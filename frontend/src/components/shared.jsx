import React, { useState, useEffect } from 'react';
import { getJson } from '../api.js';

export function Spinner({ size = 16 }) {
  return <div className="spinner" style={{ width: size, height: size }} />;
}

export function ErrorBanner({ err }) {
  if (!err) return null;
  return (
    <div className="error-banner">
      <div className="error-banner-title">⚠ backend error</div>
      <pre className="error-banner-detail">{err.message || String(err)}</pre>
    </div>
  );
}

export function StatusBadge({ score, verdict }) {
  let label = 'NO COVERAGE';
  let cls = 'badge no-coverage';
  if (verdict && /no.cover|untrigger|miss/i.test(verdict)) {
    label = 'NO COVERAGE'; cls = 'badge no-coverage';
  } else if (typeof score === 'number') {
    if (score >= 0.5) { label = 'BRITTLE'; cls = 'badge brittle'; }
    else if (score >= 0.3) { label = 'MODERATE'; cls = 'badge moderate'; }
    else { label = 'ROBUST'; cls = 'badge robust'; }
  }
  return <span className={cls}>{label}</span>;
}

export function HealthBadge({ health, err }) {
  if (err) return <div className="health err">backend unreachable</div>;
  if (!health) return <div className="health">checking…</div>;
  return (
    <div className="health">
      <div className="health-row"><span>rules</span><b>{health.rules_count}</b></div>
      <div className="health-row"><span>shenron.py</span><b className={health.shenron_py ? 'ok' : 'bad'}>{health.shenron_py ? 'ok' : 'missing'}</b></div>
      <div className="health-row"><span>taxonomy</span><b className={health.taxonomy ? 'ok' : 'bad'}>{health.taxonomy ? 'ok' : 'missing'}</b></div>
      <div className="health-row"><span>demo artifact</span><b className={health.demo_artifact ? 'ok' : 'bad'}>{health.demo_artifact ? 'ok' : 'missing'}</b></div>
      <div className="health-row"><span>python</span><b>{health.python}</b></div>
    </div>
  );
}

export function DriftWidget() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [running, setRunning] = useState(false);
  const run = () => {
    setRunning(true); setErr(null);
    getJson('/api/drift').then(setData).catch(setErr).finally(() => setRunning(false));
  };
  useEffect(() => { run(); }, []);
  const cls = data ? (data.verdict === 'pass' ? 'pass' : data.verdict === 'warn' ? 'warn' : 'fail') : '';
  return (
    <div className="drift-widget">
      <div className="drift-header">
        <span className="drift-label">MITRE drift gate</span>
        <button className="mini-btn" onClick={run} disabled={running}>{running ? '…' : '↻'}</button>
      </div>
      {err && <div className="drift-err">{err.message}</div>}
      {data && (
        <>
          <div className={`drift-verdict ${cls}`}>{data.verdict.toUpperCase()}</div>
          {data.stdout && <pre className="drift-out">{data.stdout.slice(0, 400)}</pre>}
          {data.stderr && <pre className="drift-out" style={{ color: 'var(--red)' }}>{data.stderr.slice(0, 400)}</pre>}
        </>
      )}
    </div>
  );
}

export function ScoreBar({ score }) {
  if (typeof score !== 'number') return <span className="muted">—</span>;
  const pct = Math.max(0, Math.min(1, score)) * 100;
  const color = score >= 0.5 ? 'var(--red)' : score >= 0.3 ? 'var(--yellow)' : 'var(--green)';
  return (
    <div className="score-bar">
      <div className="score-bar-fill" style={{ width: `${pct}%`, background: color }} />
      <span className="score-bar-label">{score.toFixed(3)}</span>
    </div>
  );
}
