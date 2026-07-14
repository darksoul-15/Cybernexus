import { useEffect, useState } from 'react';
import type { AutoRespondResult, BlockedIpRecord, Incident } from '@cybernexus/shared';
import { api } from '../api';
import { useAuth } from '../auth';
import { TopNav } from '../components/TopNav';

const SEV_COLORS: Record<string, string> = {
  critical: '#e53935', high: '#fb8c00', medium: '#f9a825', low: '#1e88e5', info: '#78909c',
};
const STATUSES = ['new', 'investigating', 'contained', 'resolved', 'closed'];

export function IncidentsPage() {
  const { user } = useAuth();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [blocklist, setBlocklist] = useState<BlockedIpRecord[]>([]);
  const [liveMode, setLiveMode] = useState(false);
  const [lastRun, setLastRun] = useState<AutoRespondResult | null>(null);
  const [autoBlock, setAutoBlock] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [ipToBlock, setIpToBlock] = useState('');

  const load = async () => {
    try {
      const [inc, bl] = await Promise.all([api.incidents(), api.blocklist()]);
      setIncidents(inc.incidents);
      setBlocklist(bl.blocklist);
      setLiveMode(bl.liveMode);
      setError(null);
    } catch (e) { setError((e as Error).message); }
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, []);

  const run = async () => {
    setBusy(true); setError(null);
    try { setLastRun(await api.autoRespond({ autoBlock })); await load(); }
    catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  };

  const setStatus = async (id: string, status: string) => {
    try { await api.updateIncident(id, { status }); await load(); }
    catch (e) { setError((e as Error).message); }
  };

  const block = async () => {
    setError(null);
    try { await api.blockIp(ipToBlock.trim(), 'manual block from console'); setIpToBlock(''); await load(); }
    catch (e) { setError((e as Error).message); }
  };

  return (
    <div className="app-shell">
      <TopNav />
      {error && <div className="error banner">{error}</div>}

      <section className="card" style={{ marginTop: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0 }}>Auto-response engine</h3>
            <p className="muted" style={{ margin: '4px 0 0', fontSize: 13 }}>
              Correlates unacknowledged high-severity threats by source IP into incident tickets.
              Containment is <b>{liveMode ? 'LIVE mode' : 'simulated'}</b> (real firewall stays gated off).
            </p>
          </div>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <label style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 13 }}>
              <input type="checkbox" checked={autoBlock} onChange={(e) => setAutoBlock(e.target.checked)} />
              auto-block source IPs
            </label>
            <button className="btn primary" onClick={run} disabled={busy}>
              {busy ? 'Responding…' : 'Run auto-response'}
            </button>
          </div>
        </div>
        {lastRun && (
          <div className="ingest-summary" style={{ marginTop: 12 }}>
            <b>{lastRun.qualifyingThreats}</b> qualifying threats → <b>{lastRun.incidentsCreated}</b> incidents ·
            <b> {lastRun.alertsSent}</b> alerts · <b>{lastRun.blocks.length}</b> blocks
            {lastRun.incidentsCreated === 0 && <span className="muted"> (nothing new to correlate)</span>}
          </div>
        )}
      </section>

      <section className="card">
        <h3>Incidents ({incidents.length})</h3>
        {incidents.length === 0 ? <div className="empty muted">No incidents yet — run the auto-response engine after threats are detected.</div> : (
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>Sev</th><th>Title</th><th>Threats</th><th>Opened</th><th>Status</th></tr></thead>
              <tbody>
                {incidents.map((i) => (
                  <tr key={i._id}>
                    <td><span className="tag" style={{ color: SEV_COLORS[i.severity] }}>{i.severity}</span></td>
                    <td>{i.title}</td>
                    <td>{i.relatedThreats.length}</td>
                    <td className="muted nowrap">{new Date(i.openedAt).toLocaleTimeString()}</td>
                    <td>
                      <select className="input sm-select" value={i.status} onChange={(e) => setStatus(i._id, e.target.value)}>
                        {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card">
        <h3>Containment blocklist ({blocklist.length})</h3>
        {user?.role === 'admin' && (
          <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
            <input className="input" placeholder="IPv4 to block" value={ipToBlock} onChange={(e) => setIpToBlock(e.target.value)} />
            <button className="btn" onClick={block} disabled={!ipToBlock.trim()} style={{ whiteSpace: 'nowrap' }}>Block IP</button>
          </div>
        )}
        {blocklist.length === 0 ? <div className="empty muted">No IPs blocked.</div> : (
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>IP</th><th>Mode</th><th>Enforced</th><th>Reason</th><th>When</th></tr></thead>
              <tbody>
                {blocklist.map((b) => (
                  <tr key={b._id}>
                    <td className="mono">{b.ip}</td>
                    <td><span className="tag">{b.mode}</span></td>
                    <td>{b.enforced ? <span className="bad-code">enforced</span> : <span className="muted">simulated</span>}</td>
                    <td className="muted">{b.reason}</td>
                    <td className="muted nowrap">{new Date(b.createdAt).toLocaleTimeString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
