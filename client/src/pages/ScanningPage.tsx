import { useEffect, useState } from 'react';
import type { Asset, ScanResult, Vulnerability } from '@cybernexus/shared';
import { api } from '../api';
import { TopNav } from '../components/TopNav';

const SEV_COLORS: Record<string, string> = {
  critical: '#e53935', high: '#fb8c00', medium: '#f9a825', low: '#1e88e5', info: '#78909c',
};
const ASSET_TYPES: Asset['type'][] = ['host', 'service', 'container', 'web-app'];

export function ScanningPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [selected, setSelected] = useState<Asset | null>(null);
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);

  // add-asset form
  const [name, setName] = useState('Localhost');
  const [ip, setIp] = useState('127.0.0.1');
  const [type, setType] = useState<Asset['type']>('host');
  const [startPort, setStartPort] = useState(1);
  const [endPort, setEndPort] = useState(1024);

  const loadAssets = async () => {
    try {
      setAssets((await api.assets()).assets);
      setError(null);
    } catch (e) { setError((e as Error).message); }
  };

  useEffect(() => { loadAssets(); /* eslint-disable-next-line */ }, []);

  const addAsset = async () => {
    setError(null);
    try {
      await api.createAsset({ name, type, ipAddress: ip, authorizedForScan: true });
      await loadAssets();
    } catch (e) { setError((e as Error).message); }
  };

  const runScan = async (asset: Asset) => {
    setSelected(asset);
    setScanning(true);
    setScan(null);
    setError(null);
    try {
      const res = await api.startScan(asset._id, { startPort, endPort, enrich: true });
      setScan(res.scan);
      setVulns((await api.vulnerabilities(asset._id)).vulnerabilities);
      await loadAssets();
    } catch (e) { setError((e as Error).message); }
    finally { setScanning(false); }
  };

  const del = async (id: string) => {
    try { await api.deleteAsset(id); if (selected?._id === id) { setSelected(null); setScan(null); } await loadAssets(); }
    catch (e) { setError((e as Error).message); }
  };

  return (
    <div className="app-shell">
      <TopNav />
      {error && <div className="error banner">{error}</div>}

      <section className="grid-2" style={{ marginTop: 20 }}>
        <div className="card">
          <h3>Add asset</h3>
          <label className="field-label">Name</label>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} />
          <div className="grid-2" style={{ gap: 10, marginBottom: 0 }}>
            <div>
              <label className="field-label">IP address</label>
              <input className="input" value={ip} onChange={(e) => setIp(e.target.value)} />
            </div>
            <div>
              <label className="field-label">Type</label>
              <select className="input" value={type} onChange={(e) => setType(e.target.value as Asset['type'])}>
                {ASSET_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
          </div>
          <p className="hint muted" style={{ textAlign: 'left', marginTop: 8 }}>
            Only localhost / private ranges are scannable (127.0.0.1, 10.x, 172.16–31.x, 192.168.x).
          </p>
          <button className="btn primary" onClick={addAsset} style={{ marginTop: 6 }}>Add asset</button>
        </div>

        <div className="card">
          <h3>Scan settings</h3>
          <div className="grid-2" style={{ gap: 10, marginBottom: 0 }}>
            <div>
              <label className="field-label">Start port</label>
              <input className="input" type="number" value={startPort} onChange={(e) => setStartPort(Number(e.target.value))} />
            </div>
            <div>
              <label className="field-label">End port</label>
              <input className="input" type="number" value={endPort} onChange={(e) => setEndPort(Number(e.target.value))} />
            </div>
          </div>
          <p className="hint muted" style={{ textAlign: 'left', marginTop: 8 }}>
            Tip: to see live services, include the ports your dev servers use (e.g. scan 1–6000 to catch 4000/5173).
            Open ports with a product/version are matched against the live NVD CVE database.
          </p>
        </div>
      </section>

      <section className="card">
        <h3>Assets ({assets.length})</h3>
        {assets.length === 0 ? (
          <div className="empty muted">No assets yet — add one above.</div>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>Name</th><th>IP</th><th>Type</th><th>Risk</th><th>Last scan</th><th></th></tr></thead>
              <tbody>
                {assets.map((a) => (
                  <tr key={a._id} className={selected?._id === a._id ? 'row-active' : ''}>
                    <td>{a.name}</td>
                    <td className="mono">{a.ipAddress}</td>
                    <td><span className="tag">{a.type}</span></td>
                    <td><RiskPill score={a.riskScore} /></td>
                    <td className="muted">{a.lastScannedAt ? new Date(a.lastScannedAt).toLocaleTimeString() : '—'}</td>
                    <td className="row-actions">
                      <button className="btn sm" onClick={() => runScan(a)} disabled={scanning}>
                        {scanning && selected?._id === a._id ? 'Scanning…' : 'Scan'}
                      </button>
                      <button className="btn ghost sm" onClick={() => del(a._id)}>del</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {selected && (
        <section className="grid-2">
          <div className="card">
            <h3>Open ports {scan && <span className="muted">· {selected.name}</span>}</h3>
            {scanning ? <div className="empty muted">Scanning {selected.ipAddress}…</div> :
              !scan ? <div className="empty muted">Run a scan to see results.</div> :
              scan.ports.length === 0 ? <div className="empty muted">No open ports found in {scan.portRange.start}–{scan.portRange.end}.</div> : (
                <div className="table-wrap">
                  <table className="data-table">
                    <thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Banner</th></tr></thead>
                    <tbody>
                      {scan.ports.map((p) => (
                        <tr key={p.port}>
                          <td className="mono">{p.port}</td>
                          <td>{p.service ?? '—'}</td>
                          <td>{p.product ? `${p.product} ${p.version ?? ''}` : '—'}</td>
                          <td className="muted mono" style={{ maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.banner ?? '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
          </div>

          <div className="card">
            <h3>Vulnerabilities ({vulns.length})</h3>
            {vulns.length === 0 ? <div className="empty muted">No CVEs matched (open ports had no identifiable product/version, or NVD returned none).</div> : (
              <div className="table-wrap" style={{ maxHeight: 320, overflowY: 'auto' }}>
                <table className="data-table">
                  <thead><tr><th>CVE</th><th>Sev</th><th>CVSS</th></tr></thead>
                  <tbody>
                    {vulns.map((v) => (
                      <tr key={v._id}>
                        <td className="mono">{v.cveId ?? v.title}</td>
                        <td><span className="tag" style={{ color: SEV_COLORS[v.cvss.baseSeverity] }}>{v.cvss.baseSeverity}</span></td>
                        <td>{v.cvss.baseScore.toFixed(1)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </section>
      )}
    </div>
  );
}

function RiskPill({ score }: { score: number }) {
  const color = score >= 80 ? '#ff3b6b' : score >= 50 ? '#ff8a3d' : score >= 25 ? '#ffd23d' : score > 0 ? '#3dd6ff' : '#8a94a6';
  return <span style={{ color, fontWeight: 700 }}>{score}</span>;
}
