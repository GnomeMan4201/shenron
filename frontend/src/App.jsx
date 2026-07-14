import React, { useState, useEffect } from 'react';
import Scoreboard from './components/Scoreboard.jsx';
import ArtifactInspector from './components/ArtifactInspector.jsx';
import ScenarioComparison from './components/ScenarioComparison.jsx';
import MitreMap from './components/MitreMap.jsx';
import AdaptationView from './components/AdaptationView.jsx';
import { DriftWidget, HealthBadge } from './components/shared.jsx';
import { getJson } from './api.js';

const NAV = [
  { id: 'scoreboard', label: 'Brittleness Scoreboard', icon: '◈' },
  { id: 'artifact', label: 'Campaign Artifact', icon: '▤' },
  { id: 'scenarios', label: 'Scenario Comparison', icon: '⬡' },
  { id: 'mitre', label: 'MITRE Coverage', icon: '▦' },
  { id: 'adaptation', label: 'Adaptation Engine', icon: '↻' },
];

export default function App() {
  const [view, setView] = useState('scoreboard');
  const [health, setHealth] = useState(null);
  const [healthErr, setHealthErr] = useState(null);

  useEffect(() => {
    getJson('/api/health').then(setHealth).catch(setHealthErr);
  }, []);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">⌬</div>
          <div className="brand-text">
            <div className="brand-name">SHENRON</div>
            <div className="brand-sub">detection engineering</div>
          </div>
        </div>
        <nav className="nav">
          {NAV.map(n => (
            <button
              key={n.id}
              className={`nav-item ${view === n.id ? 'active' : ''}`}
              onClick={() => setView(n.id)}
            >
              <span className="nav-icon">{n.icon}</span>
              <span>{n.label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <HealthBadge health={health} err={healthErr} />
          <DriftWidget />
        </div>
      </aside>
      <main className="main">
        {view === 'scoreboard' && <Scoreboard />}
        {view === 'artifact' && <ArtifactInspector />}
        {view === 'scenarios' && <ScenarioComparison />}
        {view === 'mitre' && <MitreMap />}
        {view === 'adaptation' && <AdaptationView />}
      </main>
    </div>
  );
}
