import React, { useState, useEffect, useMemo, useRef } from 'react';
import { getJson, streamSse } from '../api.js';
import { Spinner, ErrorBanner, StatusBadge, ScoreBar } from './shared.jsx';

export default function Scoreboard() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState(null);
  const [scores, setScores] = useState({});
  const [progress, setProgress] = useState(null);
  const [running, setRunning] = useState(false);
  const [expanded, setExpanded] = useState(null);
  const [sortDir, setSortDir] = useState('desc');
  const abortRef = useRef(null);

  useEffect(() => {
    getJson('/api/rules').then(d => setRules(d.rules || [])).catch(setErr).finally(() => setLoading(false));
  }, []);

  const runValidation = async () => {
    setRunning(true); setProgress({ index: 0, total: rules.length, rule_name: 'starting…' }); setErr(null);
    const ctrl = new AbortController(); abortRef.current = ctrl;
    try {
      await streamSse({
        url: '/api/validate', body: {}, signal: ctrl.signal,
        onEvent: ({ event, data }) => {
          if (event === 'progress') setProgress(data);
          else if (event === 'result') setScores(s => ({ ...s, [data.rule_path]: data }));
          else if (event === 'error') setScores(s => ({ ...s, [data.rule_path]: { ...data, _error: true } }));
          else if (event === 'done') { setRunning(false); setProgress(null); }
        },
      });
    } catch (e) {
      if (e.name !== 'AbortError') setErr(e);
      setRunning(false); setProgress(null);
    }
  };

  const sortedRules = useMemo(() => {
    const arr = [...rules];
    arr.sort((a, b) => {
      const va = typeof scores[a.path]?.brittleness === 'number' ? scores[a.path].brittleness : -1;
      const vb = typeof scores[b.path]?.brittleness === 'number' ? scores[b.path].brittleness : -1;
      return sortDir === 'desc' ? vb - va : va - vb;
    });
    return arr;
  }, [rules, scores, sortDir]);

  const stats = useMemo(() => {
    const vals = Object.values(scores).filter(s => typeof s.brittleness === 'number').map(s => s.brittleness);
    if (!vals.length) return null;
    return { total: vals.length, robust: vals.filter(v => v < 0.3).length, moderate: vals.filter(v => v >= 0.3 && v < 0.5).length, brittle: vals.filter(v => v >= 0.5).length, avg: vals.reduce((a, b) => a + b, 0) / vals.length };
  }, [scores]);

  if (loading) return <div className="page-loading"><Spinner size={24}/> loading rules…</div>;
  if (err && !rules.length) return <ErrorBanner err={err} />;

  return (
    <div className="view scoreboard">
      <header className="view-header">
        <div><h1>Brittleness Scoreboard</h1><p className="muted">{rules.length} sigma rules · live scoring via <code>core.sigma.evaluator</code></p></div>
        <div className="view-actions">
          <button className="primary-btn" onClick={runValidation} disabled={running}>
            {running ? <><Spinner size={12}/> scoring…</> : '▶ Run validation'}
          </button>
        </div>
      </header>
      {err && <ErrorBanner err={err} />}
      {stats && (
        <div className="stats-row">
          <div className="stat"><div className="stat-label">scored</div><div className="stat-value">{stats.total}/{rules.length}</div></div>
          <div className="stat"><div className="stat-label">avg brittleness</div><div className="stat-value mono">{stats.avg.toFixed(3)}</div></div>
          <div className="stat robust"><div className="stat-label">robust</div><div className="stat-value">{stats.robust}</div></div>
          <div className="stat moderate"><div className="stat-label">moderate</div><div className="stat-value">{stats.moderate}</div></div>
          <div className="stat brittle"><div className="stat-label">brittle</div><div className="stat-value">{stats.brittle}</div></div>
        </div>
      )}
      {progress && (
        <div className="progress-bar">
          <div className="progress-fill" style={{ width: `${(progress.index / Math.max(1, progress.total)) * 100}%` }} />
          <span className="progress-label">{progress.index} / {progress.total} — {progress.rule_name}</span>
        </div>
      )}
      <div className="table-wrap">
        <table className="data-table">
          <thead><tr>
            <th className="col-name">rule</th>
            <th className="col-cat">category</th>
            <th className="col-verdict">verdict</th>
            <th className="col-score sortable" onClick={() => setSortDir(d => d === 'desc' ? 'asc' : 'desc')}>brittleness {sortDir === 'desc' ? '↓' : '↑'}</th>
            <th className="col-status">status</th>
            <th className="col-mitre">mitre</th>
          </tr></thead>
          <tbody>
            {sortedRules.map(r => {
              const s = scores[r.path];
              const isExpanded = expanded === r.path;
              const triggered = s?.triggered;
              const verdict = triggered === true ? 'TRIGGERED' : triggered === false ? 'NO COVERAGE' : null;
              return (
                <React.Fragment key={r.path}>
                  <tr className={`row ${isExpanded ? 'expanded' : ''}`} onClick={() => setExpanded(isExpanded ? null : r.path)}>
                    <td className="col-name"><div className="rule-name">{r.name}</div><div className="rule-path mono">{r.path}</div></td>
                    <td className="col-cat"><span className="chip">{r.category}</span></td>
                    <td className="col-verdict">{s ? (s._error ? <span className="badge error">ERROR</span> : <span className="mono">{verdict || '—'}</span>) : <span className="muted">—</span>}</td>
                    <td className="col-score">{s && !s._error ? <ScoreBar score={s.brittleness} /> : <span className="muted">—</span>}</td>
                    <td className="col-status">{s && !s._error ? <StatusBadge score={s.brittleness} verdict={verdict} /> : <span className="muted">—</span>}</td>
                    <td className="col-mitre">
                      <div className="tag-list">
                        {(r.tags || []).filter(t => typeof t === 'string' && /^attack\.t/i.test(t)).slice(0, 2).map(t => <span key={t} className="mitre-tag">{t.split('.').pop().toUpperCase()}</span>)}
                        {(r.tags || []).filter(t => typeof t === 'string' && /^attack\.t/i.test(t)).length > 2 && <span className="more-tag">+{(r.tags || []).filter(t => typeof t === 'string' && /^attack\.t/i.test(t)).length - 2}</span>}
                      </div>
                    </td>
                  </tr>
                  {isExpanded && <tr className="row-detail"><td colSpan={6}><RuleDetail rule={r} score={s} /></td></tr>}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RuleDetail({ rule, score }) {
  const nonAttackTags = (rule.tags || []).filter(t => typeof t === 'string' && !/^attack\./i.test(t));
  const attackTags = (rule.tags || []).filter(t => typeof t === 'string' && /^attack\./i.test(t));
  return (
    <div className="rule-detail">
      <div className="detail-grid">
        <section>
          <h4>description</h4>
          <p className="muted">{rule.description || '—'}</p>
          {rule.level && <div className="kv"><span>level</span><b className="mono">{rule.level}</b></div>}
          {rule.status && <div className="kv"><span>status</span><b className="mono">{rule.status}</b></div>}
        </section>
        <section>
          <h4>logsource</h4>
          <pre className="mono small raw-json">{JSON.stringify(rule.logsource, null, 2)}</pre>
        </section>
        <section>
          <h4>MITRE techniques</h4>
          <div className="tag-list">{attackTags.length ? attackTags.map(t => <span key={t} className="mitre-tag">{t}</span>) : <span className="muted">—</span>}</div>
          {nonAttackTags.length > 0 && <><h4 style={{marginTop:8}}>other tags</h4><ul className="bullet-list">{nonAttackTags.map(t => <li key={t} className="mono">{t}</li>)}</ul></>}
        </section>
        {score && (
          <section style={{ gridColumn: '1 / -1' }}>
            <h4>brittleness evaluation</h4>
            {score._error ? (
              <div className="error-banner"><div className="error-banner-title">scoring failed</div><pre className="error-banner-detail">{score.error}{score.traceback ? '\n\n' + score.traceback : ''}</pre></div>
            ) : (
              <>
                <div className="kv"><span>brittleness score</span><b className="mono">{typeof score.brittleness === 'number' ? score.brittleness.toFixed(4) : 'null'}</b></div>
                <div className="kv"><span>triggered</span><b className="mono">{String(score.triggered)}</b></div>
                <div className="kv"><span>triggered count</span><b className="mono">{score.triggered_count}</b></div>
                <div className="kv"><span>duration</span><b className="mono">{score.duration_ms} ms</b></div>
                <details style={{marginTop:8}}><summary>raw score payload</summary><pre className="mono small raw-json">{JSON.stringify(score, null, 2)}</pre></details>
              </>
            )}
          </section>
        )}
      </div>
    </div>
  );
}
