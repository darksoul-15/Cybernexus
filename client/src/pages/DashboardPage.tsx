import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts';
import type { DashboardSummary, ThreatEvent, ThreatNewPayload } from '@cybernexus/shared';
import { SOCKET_EVENTS } from '@cybernexus/shared';
import { api } from '../api';
import { getSocket, disconnectSocket } from '../socket';
import { StatCard } from '../components/StatCard';
import { TopNav } from '../components/TopNav';

const SEV_COLORS: Record<string, string> = {
  critical: '#ff6f7a', high: '#ffab5e', medium: '#f5c451', low: '#6ea8ff', info: '#8d8ba1',
};
const CAT_COLOR = '#9b9ae8';
const AXIS_TICK = '#8d8ba1';

export function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [liveFeed, setLiveFeed] = useState<ThreatEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [connected, setConnected] = useState(false);
  const refetchTimer = useRef<number | null>(null);

  const load = async () => {
    try {
      setSummary(await api.dashboard());
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  // Debounced refetch so a burst of live events triggers one summary reload.
  const scheduleRefetch = () => {
    if (refetchTimer.current) window.clearTimeout(refetchTimer.current);
    refetchTimer.current = window.setTimeout(load, 400);
  };

  useEffect(() => {
    load();
    const socket = getSocket();
    socket.on('connect', () => setConnected(true));
    socket.on('disconnect', () => setConnected(false));
    socket.on(SOCKET_EVENTS.threatNew, (payload: ThreatNewPayload) => {
      setLiveFeed((prev) => [...payload.threats, ...prev].slice(0, 15));
      scheduleRefetch();
    });
    socket.on(SOCKET_EVENTS.dashboardUpdate, scheduleRefetch);
    return () => {
      socket.off(SOCKET_EVENTS.threatNew);
      socket.off(SOCKET_EVENTS.dashboardUpdate);
      disconnectSocket();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const runSample = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.ingestSample();
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const catData = useMemo(
    () => (summary?.threats.byCategory ?? []).map((b) => ({ name: b.key, count: b.count })),
    [summary]
  );
  const sevData = useMemo(
    () => (summary?.threats.bySeverity ?? []).map((b) => ({ name: b.key, value: b.count })),
    [summary]
  );

  if (!summary) {
    return <div className="center-screen">{error ? <span className="error">{error}</span> : 'Loading dashboard…'}</div>;
  }

  const t = summary.threats;

  return (
    <div className="app-shell">
      <TopNav>
        <span className={connected ? 'pill live' : 'pill'}>
          <span className="dot" /> {connected ? 'LIVE' : 'offline'}
        </span>
        <button className="btn" onClick={runSample} disabled={busy}>
          {busy ? 'Ingesting…' : 'Ingest sample logs'}
        </button>
      </TopNav>

      {error && <div className="error banner">{error}</div>}

      <section className="stat-grid">
        <StatCard label="Assets monitored" value={summary.assets.total} sub={`${summary.assets.scannable} scannable`} />
        <StatCard label="Open vulnerabilities" value={summary.vulnerabilities.open} accent="#fb8c00" sub={`${summary.vulnerabilities.total} total`} />
        <StatCard label="Threat events" value={t.total} accent="#2f9d4e" sub={`${t.unacknowledged} unacknowledged`} />
        <StatCard label="Incidents" value={summary.incidents.total} sub="open cases" />
      </section>

      <section className="grid-2">
        <div className="card">
          <h3>Threats by category</h3>
          {catData.length === 0 ? (
            <Empty />
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={catData} margin={{ top: 8, right: 8, bottom: 8, left: -18 }}>
                <XAxis dataKey="name" tick={{ fill: AXIS_TICK, fontSize: 11 }} interval={0} angle={-12} textAnchor="end" height={50} />
                <YAxis allowDecimals={false} tick={{ fill: AXIS_TICK, fontSize: 11 }} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(155,154,232,0.10)' }} />
                <Bar dataKey="count" fill={CAT_COLOR} radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card">
          <h3>Severity distribution</h3>
          {sevData.length === 0 ? (
            <Empty />
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie data={sevData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={90} paddingAngle={2}>
                  {sevData.map((d) => (
                    <Cell key={d.name} fill={SEV_COLORS[d.name] ?? '#8a94a6'} />
                  ))}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </section>

      <section className="grid-2">
        <div className="card">
          <h3>Asset risk heat map</h3>
          {summary.assets.heatmap.length === 0 ? (
            <Empty text="No assets yet — add one to start scanning" />
          ) : (
            <div className="heatmap">
              {summary.assets.heatmap.map((a) => (
                <div key={a._id} className="heat-row">
                  <span className="heat-name" title={a.ipAddress}>{a.name}</span>
                  <div className="heat-bar-track">
                    <div className="heat-bar" style={{ width: `${a.riskScore}%`, background: SEV_COLORS[a.band] }} />
                  </div>
                  <span className="heat-score" style={{ color: SEV_COLORS[a.band] }}>{a.riskScore}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card">
          <h3>Live threat feed {liveFeed.length > 0 && <span className="pill live sm"><span className="dot" /> {liveFeed.length}</span>}</h3>
          <ThreatList threats={liveFeed.length ? liveFeed : t.recent} onAck={async (id) => { await api.acknowledgeThreat(id); load(); }} />
        </div>
      </section>

      <footer className="foot muted">
        Generated {new Date(summary.generatedAt).toLocaleTimeString()} · every number traces to a real DB record
      </footer>
    </div>
  );
}

function ThreatList({ threats, onAck }: { threats: ThreatEvent[]; onAck: (id: string) => void }) {
  if (threats.length === 0) return <Empty text="No threats detected yet — try ‘Ingest sample logs’" />;
  return (
    <ul className="threat-list">
      {threats.map((th) => (
        <li key={th._id} className="threat-item">
          <span className="sev-dot" style={{ background: SEV_COLORS[th.severity] }} />
          <div className="threat-main">
            <div className="threat-desc">{th.description}</div>
            <div className="threat-meta muted">
              {th.category} · {th.sourceIp ?? 'n/a'} · score {th.score}
            </div>
          </div>
          {!th.acknowledged && (
            <button className="btn ghost sm" onClick={() => onAck(th._id)}>ack</button>
          )}
        </li>
      ))}
    </ul>
  );
}

function Empty({ text = 'No data yet' }: { text?: string }) {
  return <div className="empty muted">{text}</div>;
}

const tooltipStyle = { background: '#1e1c29', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 10, color: '#eeedf6', boxShadow: '0 12px 30px rgba(0,0,0,0.5)' } as const;
