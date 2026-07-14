import { useEffect, useRef, useState, type DragEvent } from 'react';
import type { IndicatorReputation, IngestSummary, ThreatEvent } from '@cybernexus/shared';
import { api } from '../api';
import { TopNav } from '../components/TopNav';

const SEV_COLORS: Record<string, string> = {
  critical: '#e53935', high: '#fb8c00', medium: '#f9a825', low: '#1e88e5', info: '#78909c',
};
const VERDICT_COLORS: Record<string, string> = {
  malicious: '#e53935', suspicious: '#fb8c00', clean: '#2f9d4e', unknown: '#78909c',
};

export function ThreatsPage() {
  const [threats, setThreats] = useState<ThreatEvent[]>([]);
  const [summary, setSummary] = useState<IngestSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const load = async () => {
    try { setThreats((await api.threats()).threats); setError(null); }
    catch (e) { setError((e as Error).message); }
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, []);

  const ingestText = async (text: string) => {
    setBusy(true);
    setError(null);
    try {
      const res = await api.ingest('combined', text);
      setSummary(res);
      await load();
    } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  };

  const onFile = async (file: File) => {
    const text = await file.text();
    await ingestText(text);
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) onFile(file);
  };

  const genSample = async () => {
    setBusy(true);
    setError(null);
    try { setSummary(await api.ingestSample()); await load(); }
    catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  };

  const ack = async (id: string) => { await api.acknowledgeThreat(id); load(); };

  return (
    <div className="app-shell">
      <TopNav />
      {error && <div className="error banner">{error}</div>}

      <section className="grid-2" style={{ marginTop: 20 }}>
        <div className="card">
          <h3>Ingest access logs</h3>
          <div
            className={dragOver ? 'dropzone over' : 'dropzone'}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={onDrop}
            onClick={() => fileInput.current?.click()}
          >
            <div className="dz-icon">⬆</div>
            <div>{busy ? 'Analyzing…' : 'Drop an Apache/Nginx access log here'}</div>
            <div className="muted" style={{ fontSize: 12 }}>or click to browse · combined/common format</div>
            <input ref={fileInput} type="file" accept=".log,.txt" hidden
              onChange={(e) => { const f = e.target.files?.[0]; if (f) onFile(f); }} />
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 12, alignItems: 'center' }}>
            <button className="btn" onClick={genSample} disabled={busy}>Generate sample attack logs</button>
            <span className="muted" style={{ fontSize: 12 }}>no log handy? synthesize one</span>
          </div>

          {summary && (
            <div className="ingest-summary">
              <div><b>{summary.entriesParsed}</b> parsed · <b>{summary.entriesSkipped}</b> skipped · <b>{summary.threatsDetected}</b> threats</div>
              <div className="chip-row" style={{ marginTop: 6 }}>
                {Object.entries(summary.byCategory).map(([k, v]) => <span key={k} className="tag">{k}: {v}</span>)}
              </div>
            </div>
          )}
        </div>

        <IntelPanel />
      </section>

      <section className="card">
        <h3>Detected threats ({threats.length})</h3>
        {threats.length === 0 ? <div className="empty muted">No threats yet — ingest a log or generate a sample.</div> : (
          <div className="table-wrap" style={{ maxHeight: 420, overflowY: 'auto' }}>
            <table className="data-table">
              <thead><tr><th>Sev</th><th>Category</th><th>Source IP</th><th>Description</th><th>Score</th><th></th></tr></thead>
              <tbody>
                {threats.map((t) => (
                  <tr key={t._id}>
                    <td><span className="sev-dot" style={{ background: SEV_COLORS[t.severity], display: 'inline-block', width: 9, height: 9, borderRadius: '50%' }} /></td>
                    <td><span className="tag">{t.category}</span></td>
                    <td className="mono">{t.sourceIp ?? '—'}</td>
                    <td className="muted" style={{ maxWidth: 340, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{t.description}</td>
                    <td>{t.score}</td>
                    <td>{!t.acknowledged && <button className="btn ghost sm" onClick={() => ack(t._id)}>ack</button>}</td>
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

function IntelPanel() {
  const [indicator, setIndicator] = useState('8.8.8.8');
  const [result, setResult] = useState<IndicatorReputation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const lookup = async () => {
    setBusy(true); setError(null);
    try { setResult((await api.lookup(indicator.trim())).reputation); }
    catch (e) { setError((e as Error).message); setResult(null); }
    finally { setBusy(false); }
  };

  return (
    <div className="card">
      <h3>Threat intel lookup</h3>
      <div style={{ display: 'flex', gap: 8 }}>
        <input className="input" placeholder="IP or domain" value={indicator}
          onChange={(e) => setIndicator(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && lookup()} />
        <button className="btn primary" onClick={lookup} disabled={busy} style={{ whiteSpace: 'nowrap' }}>
          {busy ? '…' : 'Look up'}
        </button>
      </div>
      {error && <div className="error" style={{ marginTop: 8 }}>{error}</div>}
      {result && (
        <div style={{ marginTop: 12 }}>
          <div className="verdict" style={{ color: VERDICT_COLORS[result.verdict] }}>
            {result.verdict.toUpperCase()} <span className="muted">· score {result.score}</span>
          </div>
          <div className="detail" style={{ marginTop: 8 }}>
            {result.sources.map((s) => (
              <div key={s.provider} className="kv">
                <span>{s.provider}</span>
                <span style={{ color: s.available ? VERDICT_COLORS[s.verdict] : '#8a94a6' }}>
                  {s.available ? `${s.verdict} (${s.score})` : `unavailable — ${s.error ?? 'no key'}`}
                  {s.cached && s.available ? ' · cached' : ''}
                </span>
              </div>
            ))}
          </div>
          <p className="hint muted" style={{ textAlign: 'left', marginTop: 6 }}>
            Add ABUSEIPDB_API_KEY / VIRUSTOTAL_API_KEY to the server .env for live verdicts.
          </p>
        </div>
      )}
    </div>
  );
}
