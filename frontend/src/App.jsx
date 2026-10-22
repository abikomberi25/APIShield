import { useState, useEffect, useCallback } from 'react';
import { getHealth, getLabMode, getDefenses, patchDefenses, getEvents, login } from './api';
import './App.css';

// Load experiment results from JSON files bundled with the frontend
const resultFiles = {
  bola: '/results/bola_results.json',
  bopla: '/results/bopla_read_results.json',
  rbac: '/results/rbac_results.json',
  auth: '/results/auth_results.json',
  rate_limit: '/results/rate_limit_results.json',
};

// Severity badge colors
const severityColor = { HIGH: '#c0392b', MEDIUM: '#e67e22', LOW: '#27ae60', CRITICAL: '#8e44ad' };
const actionColor = { blocked: '#c0392b', detected: '#e67e22' };

function Badge({ text, color }) {
  return (
    <span style={{
      background: color || '#555', color: '#fff', borderRadius: 4,
      padding: '2px 8px', fontSize: 12, fontWeight: 600,
    }}>{text}</span>
  );
}

function StatusPill({ ok, label }) {
  return (
    <span style={{
      background: ok ? '#27ae60' : '#c0392b', color: '#fff',
      borderRadius: 12, padding: '4px 14px', fontSize: 13, fontWeight: 700,
    }}>{label}</span>
  );
}

function Card({ title, children }) {
  return (
    <div style={{
      background: '#1e1e2e', borderRadius: 10, padding: '20px 24px',
      marginBottom: 20, border: '1px solid #2d2d44',
    }}>
      {title && <h3 style={{ margin: '0 0 16px', color: '#a6adc8', fontWeight: 600, fontSize: 15, letterSpacing: 1 }}>{title.toUpperCase()}</h3>}
      {children}
    </div>
  );
}

// ─── Login Panel ────────────────────────────────────────────────────────────
function LoginPanel({ onLogin }) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await login(username, password);
      if (data.user.role !== 'admin') {
        setError('Admin role required to access the dashboard.');
        return;
      }
      // token held in component state only — never persisted to localStorage
      onLogin(data.access_token, data.user);
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
      setPassword(''); // clear password immediately after use
    }
  }

  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '80vh' }}>
      <Card title="APIShield Admin Login">
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 12, minWidth: 280 }}>
          <input
            value={username} onChange={e => setUsername(e.target.value)}
            placeholder="Username" required style={inputStyle}
            autoComplete="username"
          />
          <input
            type="password" value={password} onChange={e => setPassword(e.target.value)}
            placeholder="Password" required style={inputStyle}
            autoComplete="current-password"
          />
          {error && <div style={{ color: '#f38ba8', fontSize: 13 }}>{error}</div>}
          <button type="submit" disabled={loading} style={btnStyle(loading)}>
            {loading ? 'Signing in…' : 'Sign In'}
          </button>
        </form>
      </Card>
    </div>
  );
}

// ─── System Status ───────────────────────────────────────────────────────────
function SystemStatus({ token }) {
  const [health, setHealth] = useState(null);
  const [labMode, setLabMode] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    getHealth().then(setHealth).catch(() => setHealth({ status: 'error' }));
    getLabMode(token).then(d => setLabMode(d.lab_mode)).catch(err => setError(err.message));
  }, [token]);

  return (
    <Card title="System Status">
      <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap', alignItems: 'center' }}>
        <div>
          <span style={{ color: '#6c7086', fontSize: 12 }}>API Health</span><br />
          <StatusPill ok={health?.status === 'ok'} label={health?.status === 'ok' ? '● Online' : '● Offline'} />
        </div>
        <div>
          <span style={{ color: '#6c7086', fontSize: 12 }}>Lab Mode</span><br />
          {labMode === null
            ? <span style={{ color: '#6c7086' }}>Loading…</span>
            : <StatusPill ok={!labMode} label={labMode ? '⚠ LAB MODE ON' : '✓ Safe Mode'} />}
        </div>
        {error && <span style={{ color: '#f38ba8', fontSize: 12 }}>{error}</span>}
      </div>
      {labMode && (
        <p style={{ color: '#f9e2af', fontSize: 13, marginTop: 12 }}>
          ⚠ The server is running in experimental lab mode. Intentionally vulnerable behaviors are enabled.
        </p>
      )}
    </Card>
  );
}

// ─── Defense Controls ────────────────────────────────────────────────────────
const DEFENSE_LABELS = {
  bola: 'BOLA (API1) — Object Ownership',
  auth_hardening: 'Auth Hardening (API2) — Login Lockout',
  schema_validation: 'Schema Validation (API3) — Property Access',
  rate_limit: 'Rate Limit (API4) — Resource Consumption',
  rbac: 'RBAC (API5) — Function Authorization',
};

function DefenseControls({ token }) {
  const [defenses, setDefenses] = useState(null);
  const [loading, setLoading] = useState({});
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const fetchDefenses = useCallback(async () => {
    try {
      const d = await getDefenses(token);
      setDefenses(d.defenses);
    } catch (err) {
      setError(err.message);
    }
  }, [token]);

  useEffect(() => { fetchDefenses(); }, [fetchDefenses]);

  async function toggle(key, current) {
    setLoading(l => ({ ...l, [key]: true }));
    setError(''); setSuccess('');
    try {
      const res = await patchDefenses(token, { [key]: !current });
      setDefenses(res.defenses);
      setSuccess(`${key} set to ${!current ? 'ON' : 'OFF'}`);
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(l => ({ ...l, [key]: false }));
    }
  }

  if (!defenses) return <Card title="Defense Controls"><span style={{ color: '#6c7086' }}>{error || 'Loading…'}</span></Card>;

  return (
    <Card title="Defense Controls">
      {error && <div style={{ color: '#f38ba8', marginBottom: 10, fontSize: 13 }}>{error}</div>}
      {success && <div style={{ color: '#a6e3a1', marginBottom: 10, fontSize: 13 }}>✓ {success}</div>}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {Object.entries(defenses).map(([key, val]) => (
          <div key={key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: '#181825', borderRadius: 8, padding: '10px 16px' }}>
            <span style={{ fontSize: 14, color: '#cdd6f4' }}>{DEFENSE_LABELS[key] || key}</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <Badge text={val ? 'ON' : 'OFF'} color={val ? '#27ae60' : '#6c7086'} />
              <button
                onClick={() => toggle(key, val)}
                disabled={loading[key]}
                style={btnStyle(loading[key], val ? '#c0392b' : '#27ae60')}
              >
                {loading[key] ? '…' : val ? 'Disable' : 'Enable'}
              </button>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

// ─── Event Viewer ─────────────────────────────────────────────────────────────
function EventViewer({ token }) {
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [actionFilter, setActionFilter] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const LIMIT = 20;

  const fetchEvents = useCallback(async () => {
    setLoading(true); setError('');
    try {
      const d = await getEvents(token, { limit: LIMIT, offset, action: actionFilter || undefined });
      setEvents(d.events);
      setTotal(d.total);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [token, offset, actionFilter]);

  useEffect(() => { fetchEvents(); }, [fetchEvents]);

  const pages = Math.ceil(total / LIMIT);
  const currentPage = Math.floor(offset / LIMIT) + 1;

  return (
    <Card title={`Security Events (${total} total)`}>
      <div style={{ display: 'flex', gap: 10, marginBottom: 14, alignItems: 'center', flexWrap: 'wrap' }}>
        <select value={actionFilter} onChange={e => { setActionFilter(e.target.value); setOffset(0); }} style={selectStyle}>
          <option value="">All Actions</option>
          <option value="detected">Detected</option>
          <option value="blocked">Blocked</option>
        </select>
        <button onClick={fetchEvents} style={btnStyle(loading)} disabled={loading}>↻ Refresh</button>
        <span style={{ color: '#6c7086', fontSize: 12 }}>{loading ? 'Loading…' : ''}</span>
      </div>
      {error && <div style={{ color: '#f38ba8', marginBottom: 10 }}>{error}</div>}
      {events.length === 0 && !loading && <div style={{ color: '#6c7086', fontSize: 13 }}>No events found.</div>}
      {events.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ color: '#6c7086', textAlign: 'left', borderBottom: '1px solid #2d2d44' }}>
                {['ID', 'Time', 'Category', 'Rule', 'Action', 'Severity', 'Endpoint', 'User'].map(h => (
                  <th key={h} style={{ padding: '6px 10px', whiteSpace: 'nowrap' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {events.map(ev => (
                <tr key={ev.id} style={{ borderBottom: '1px solid #1a1a2e' }}>
                  <td style={td}>{ev.id}</td>
                  <td style={td}>{new Date(ev.timestamp).toLocaleTimeString()}</td>
                  <td style={td}><Badge text={ev.owasp_category} color="#313244" /></td>
                  <td style={td}>{ev.rule_name}</td>
                  <td style={td}><Badge text={ev.action} color={actionColor[ev.action] || '#555'} /></td>
                  <td style={td}><Badge text={ev.severity} color={severityColor[ev.severity] || '#555'} /></td>
                  <td style={td}><code style={{ fontSize: 11 }}>{ev.method} {ev.endpoint}</code></td>
                  <td style={td}>{ev.user_id || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {pages > 1 && (
        <div style={{ display: 'flex', gap: 8, marginTop: 12, alignItems: 'center' }}>
          <button onClick={() => setOffset(Math.max(0, offset - LIMIT))} disabled={offset === 0} style={btnStyle(offset === 0)}>← Prev</button>
          <span style={{ color: '#6c7086', fontSize: 12 }}>Page {currentPage} / {pages}</span>
          <button onClick={() => setOffset(offset + LIMIT)} disabled={offset + LIMIT >= total} style={btnStyle(offset + LIMIT >= total)}>Next →</button>
        </div>
      )}
    </Card>
  );
}

// ─── Experiment Results ───────────────────────────────────────────────────────
function ResultPanel({ name, file }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [missing, setMissing] = useState(false);

  useEffect(() => {
    fetch(file)
      .then(r => { if (!r.ok) throw new Error('not found'); return r.json(); })
      .then(setData)
      .catch(() => setMissing(true))
      .finally(() => setLoading(false));
  }, [file]);

  if (loading) return <div style={{ color: '#6c7086', fontSize: 13 }}>Loading {name}…</div>;
  if (missing) return (
    <div style={{ background: '#1a1a2e', borderRadius: 8, padding: '12px 16px', marginBottom: 10 }}>
      <strong style={{ color: '#f9e2af' }}>{name}</strong>
      <div style={{ color: '#6c7086', fontSize: 12, marginTop: 4 }}>No result file found — run the experiment script to generate results.</div>
    </div>
  );

  const vr = data.vulnerable_run || {};
  const dr = data.defended_run || {};

  return (
    <div style={{ background: '#1a1a2e', borderRadius: 8, padding: '14px 18px', marginBottom: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 8 }}>
        <div>
          <strong style={{ color: '#cdd6f4', fontSize: 14 }}>{data.experiment || name}</strong>
          <div style={{ color: '#6c7086', fontSize: 11, marginTop: 2 }}>{data.timestamp ? new Date(data.timestamp).toLocaleString() : ''}</div>
        </div>
      </div>
      <div style={{ display: 'flex', gap: 16, marginTop: 12, flexWrap: 'wrap' }}>
        <RunBox label="Vulnerable Run" run={vr} />
        <RunBox label="Defended Run" run={dr} />
      </div>
    </div>
  );
}

function RunBox({ label, run }) {
  if (!run || Object.keys(run).length === 0) return null;
  const outcomeColor = {
    vulnerability_exploited: '#c0392b',
    attack_blocked: '#27ae60',
    unverified_detection: '#e67e22',
    unexpected: '#6c7086',
  };
  return (
    <div style={{ flex: '1 1 220px', background: '#181825', borderRadius: 8, padding: '10px 14px', minWidth: 200 }}>
      <div style={{ color: '#a6adc8', fontSize: 12, marginBottom: 8 }}>{label}</div>
      {run.outcome && <Badge text={run.outcome.replace(/_/g, ' ')} color={outcomeColor[run.outcome] || '#555'} />}
      <div style={{ marginTop: 8, fontSize: 12, color: '#cdd6f4' }}>
        {run.status_code !== undefined && <div>HTTP: {run.status_code}</div>}
        {run.detection_verified !== undefined && (
          <div>Detection: <span style={{ color: run.detection_verified ? '#a6e3a1' : '#f38ba8' }}>{run.detection_verified ? '✓ Verified' : '✗ Unverified'}</span></div>
        )}
        {run.matched_event_id !== undefined && run.matched_event_id !== null && <div>Event ID: {run.matched_event_id}</div>}
        {run.failed_401 !== undefined && <div>401 Failures: {run.failed_401}</div>}
        {run.failed_429 !== undefined && <div>429 Locked: {run.failed_429}</div>}
        {run.results_200_allowed !== undefined && <div>Allowed: {run.results_200_allowed}</div>}
        {run.results_429_limited !== undefined && <div>Limited: {run.results_429_limited}</div>}
        {run.block_rate !== undefined && <div>Block Rate: {(run.block_rate * 100).toFixed(1)}%</div>}
      </div>
    </div>
  );
}

function ExperimentResults() {
  return (
    <Card title="Experiment Results">
      <p style={{ color: '#6c7086', fontSize: 12, marginTop: 0 }}>
        Results are loaded from <code>docs/results/*.json</code>. Run the experiment scripts to generate or update them.
      </p>
      {Object.entries(resultFiles).map(([name, file]) => (
        <ResultPanel key={name} name={name.toUpperCase().replace('_', ' ')} file={file} />
      ))}
    </Card>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
const TABS = ['Status', 'Defenses', 'Events', 'Results'];

export default function App() {
  const [token, setToken] = useState(null);
  const [user, setUser] = useState(null);
  const [tab, setTab] = useState('Status');

  function handleLogin(tok, u) {
    setToken(tok);
    setUser(u);
  }

  function handleLogout() {
    setToken(null);
    setUser(null);
  }

  if (!token) return <LoginPanel onLogin={handleLogin} />;

  return (
    <div style={{ fontFamily: "'Inter', system-ui, sans-serif", background: '#11111b', minHeight: '100vh', color: '#cdd6f4' }}>
      {/* Header */}
      <header style={{ background: '#1e1e2e', borderBottom: '1px solid #2d2d44', padding: '14px 32px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 22, fontWeight: 800, letterSpacing: 1, color: '#89b4fa' }}>🛡 APIShield</span>
          <span style={{ fontSize: 12, color: '#6c7086', marginTop: 2 }}>Security Research Dashboard</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <span style={{ color: '#a6adc8', fontSize: 13 }}>{user?.username} <Badge text={user?.role} color="#313244" /></span>
          <button onClick={handleLogout} style={{ ...btnStyle(false, '#45475a'), fontSize: 12, padding: '4px 12px' }}>Logout</button>
        </div>
      </header>

      {/* Tab Navigation */}
      <nav style={{ background: '#181825', borderBottom: '1px solid #2d2d44', padding: '0 32px', display: 'flex', gap: 0 }}>
        {TABS.map(t => (
          <button key={t} onClick={() => setTab(t)} style={{
            background: 'none', border: 'none', color: tab === t ? '#89b4fa' : '#6c7086',
            padding: '12px 20px', cursor: 'pointer', fontSize: 14, fontWeight: tab === t ? 700 : 400,
            borderBottom: tab === t ? '2px solid #89b4fa' : '2px solid transparent',
          }}>{t}</button>
        ))}
      </nav>

      {/* Content */}
      <main style={{ maxWidth: 1100, margin: '0 auto', padding: '28px 24px' }}>
        {tab === 'Status' && <SystemStatus token={token} />}
        {tab === 'Defenses' && <DefenseControls token={token} />}
        {tab === 'Events' && <EventViewer token={token} />}
        {tab === 'Results' && <ExperimentResults />}
      </main>
    </div>
  );
}

// ─── Styles ──────────────────────────────────────────────────────────────────
const inputStyle = {
  background: '#1e1e2e', border: '1px solid #313244', color: '#cdd6f4',
  borderRadius: 6, padding: '9px 13px', fontSize: 14, outline: 'none',
};
const selectStyle = {
  ...inputStyle, cursor: 'pointer',
};
const td = { padding: '7px 10px', color: '#cdd6f4', verticalAlign: 'middle' };

function btnStyle(disabled, bg = '#89b4fa') {
  return {
    background: disabled ? '#313244' : bg,
    color: disabled ? '#6c7086' : '#11111b',
    border: 'none', borderRadius: 6,
    padding: '8px 18px', cursor: disabled ? 'not-allowed' : 'pointer',
    fontWeight: 700, fontSize: 13, transition: 'background 0.15s',
  };
}
