import { useEffect, useState } from 'react';
import type { ChainVerificationResult, EvidenceRecord } from '@cybernexus/shared';
import { api } from '../api';
import { TopNav } from '../components/TopNav';

const TYPES: EvidenceRecord['type'][] = ['note', 'log', 'scan', 'threat', 'file'];

export function EvidencePage() {
  const [records, setRecords] = useState<EvidenceRecord[]>([]);
  const [verification, setVerification] = useState<ChainVerificationResult | null>(null);
  const [selected, setSelected] = useState<EvidenceRecord | null>(null);
  const [type, setType] = useState<EvidenceRecord['type']>('note');
  const [payloadText, setPayloadText] = useState('{\n  "note": "collected during triage"\n}');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    try {
      const [{ evidence }, v] = await Promise.all([api.evidenceList(), api.evidenceVerify()]);
      setRecords(evidence);
      setVerification(v);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const addRecord = async () => {
    setBusy(true);
    setError(null);
    try {
      const payload = JSON.parse(payloadText) as Record<string, unknown>;
      await api.addEvidence(type, payload);
      await load();
    } catch (e) {
      setError(e instanceof SyntaxError ? 'Payload must be valid JSON' : (e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const view = async (id: string) => {
    try {
      setSelected((await api.evidenceGet(id)).evidence);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const exportRec = async (id: string) => {
    try {
      setSelected((await api.evidenceExport(id)).evidence);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  return (
    <div className="app-shell">
      <TopNav />
      {error && <div className="error banner">{error}</div>}

      <section className="grid-2" style={{ marginTop: 20 }}>
        <div className="card">
          <h3>Chain integrity</h3>
          {verification ? (
            <div className={verification.valid ? 'attest ok' : 'attest bad'}>
              <div className="attest-headline">
                {verification.valid ? '● CHAIN VERIFIED' : '● CHAIN INVALID'}
              </div>
              <div className="muted">
                {verification.length} record{verification.length === 1 ? '' : 's'} ·
                head <code className="hash">{verification.headHash ? verification.headHash.slice(0, 16) + '…' : '(empty)'}</code>
              </div>
              {!verification.valid && (
                <ul className="issues">
                  {verification.issues.map((i, idx) => (
                    <li key={idx}>#{i.index}: {i.problem}</li>
                  ))}
                </ul>
              )}
            </div>
          ) : (
            <div className="empty muted">Verifying…</div>
          )}
          <button className="btn" style={{ marginTop: 12 }} onClick={load}>Re-verify chain</button>
        </div>

        <div className="card">
          <h3>Add evidence to the chain</h3>
          <label className="field-label">Type</label>
          <select className="input" value={type} onChange={(e) => setType(e.target.value as EvidenceRecord['type'])}>
            {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <label className="field-label">Payload (JSON)</label>
          <textarea className="input mono" rows={5} value={payloadText} onChange={(e) => setPayloadText(e.target.value)} />
          <button className="btn primary" style={{ marginTop: 10 }} onClick={addRecord} disabled={busy}>
            {busy ? 'Sealing…' : 'Append record'}
          </button>
        </div>
      </section>

      <section className="grid-2">
        <div className="card">
          <h3>Evidence ledger ({records.length})</h3>
          {records.length === 0 ? (
            <div className="empty muted">No evidence recorded yet — append one above.</div>
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr><th>#</th><th>Type</th><th>Hash</th><th></th></tr>
                </thead>
                <tbody>
                  {records.map((r) => (
                    <tr key={r._id} className={selected?._id === r._id ? 'row-active' : ''}>
                      <td>{r.index}</td>
                      <td><span className="tag">{r.type}</span></td>
                      <td><code className="hash">{r.hash.slice(0, 14)}…</code></td>
                      <td className="row-actions">
                        <button className="btn ghost sm" onClick={() => view(r._id)}>view</button>
                        <button className="btn ghost sm" onClick={() => exportRec(r._id)}>export</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="card">
          <h3>Record detail {selected && <span className="muted">#{selected.index}</span>}</h3>
          {!selected ? (
            <div className="empty muted">Select a record to view its payload + chain-of-custody.</div>
          ) : (
            <div className="detail">
              <div className="kv"><span>contentHash</span><code className="hash">{selected.contentHash}</code></div>
              <div className="kv"><span>previousHash</span><code className="hash">{selected.previousHash}</code></div>
              <div className="kv"><span>hash</span><code className="hash">{selected.hash}</code></div>
              <h4>Payload</h4>
              <pre className="json-block">{JSON.stringify(selected.payload, null, 2)}</pre>
              <h4>Chain of custody</h4>
              <ul className="custody">
                {selected.custody.map((c, i) => (
                  <li key={i}>
                    <span className={`tag tag-${c.action}`}>{c.action}</span>
                    <span className="muted">{new Date(c.at).toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
