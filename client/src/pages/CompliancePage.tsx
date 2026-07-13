import { useEffect, useState } from 'react';
import type { AuditLog, ComplianceReport } from '@cybernexus/shared';
import { api } from '../api';
import { TopNav } from '../components/TopNav';
import { StatCard } from '../components/StatCard';

export function CompliancePage() {
  const [report, setReport] = useState<ComplianceReport | null>(null);
  const [audit, setAudit] = useState<AuditLog[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);

  const load = async () => {
    try {
      const [rep, logs] = await Promise.all([api.complianceReport(), api.auditLogs({ limit: 50 })]);
      setReport(rep);
      setAudit(logs.items);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const download = async () => {
    setDownloading(true);
    setError(null);
    try {
      await api.downloadReportPdf();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="app-shell">
      <TopNav>
        <button className="btn primary" onClick={download} disabled={downloading}>
          {downloading ? 'Generating…' : '⬇ Download PDF report'}
        </button>
      </TopNav>

      {error && <div className="error banner">{error}</div>}

      {!report ? (
        <div className="center-screen">{error ? null : 'Loading compliance data…'}</div>
      ) : (
        <>
          <section className="stat-grid" style={{ marginTop: 20 }}>
            <StatCard label="Audited actions" value={report.audit.total} sub={`${report.audit.uniqueActors} distinct actors`} />
            <StatCard label="Incidents" value={report.incidents.total} accent="#ff8a3d" />
            <StatCard label="Evidence records" value={report.evidence.length} />
            <StatCard
              label="Chain integrity"
              value={report.evidence.chainValid ? 'VERIFIED' : 'INVALID'}
              accent={report.evidence.chainValid ? '#00e0c6' : '#ff3b6b'}
              sub={report.evidence.headHash ? report.evidence.headHash.slice(0, 12) + '…' : 'empty chain'}
            />
          </section>

          <section className="grid-2">
            <div className="card">
              <h3>Actions by type</h3>
              {report.audit.byAction.length === 0 ? (
                <div className="empty muted">No audited actions yet.</div>
              ) : (
                <div className="heatmap">
                  {report.audit.byAction.map((b) => {
                    const max = Math.max(...report.audit.byAction.map((x) => x.count));
                    return (
                      <div key={b.key} className="heat-row">
                        <span className="heat-name" title={b.key}>{b.key}</span>
                        <div className="heat-bar-track">
                          <div className="heat-bar" style={{ width: `${(b.count / max) * 100}%`, background: '#3d7bff' }} />
                        </div>
                        <span className="heat-score">{b.count}</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            <div className="card">
              <h3>Incident posture</h3>
              <h4 className="muted">By status</h4>
              <div className="chip-row">
                {report.incidents.byStatus.length === 0 ? <span className="muted">none</span> :
                  report.incidents.byStatus.map((b) => <span key={b.key} className="tag">{b.key}: {b.count}</span>)}
              </div>
              <h4 className="muted">By severity</h4>
              <div className="chip-row">
                {report.incidents.bySeverity.length === 0 ? <span className="muted">none</span> :
                  report.incidents.bySeverity.map((b) => <span key={b.key} className={`tag sev-${b.key}`}>{b.key}: {b.count}</span>)}
              </div>
            </div>
          </section>

          <section className="card">
            <h3>Audit trail ({audit.length})</h3>
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr><th>When</th><th>Actor</th><th>Action</th><th>Method</th><th>Path</th><th>Status</th></tr>
                </thead>
                <tbody>
                  {audit.map((a) => (
                    <tr key={a._id}>
                      <td className="nowrap">{new Date(a.createdAt).toLocaleString()}</td>
                      <td>{a.actorEmail ?? 'anonymous'}</td>
                      <td><span className="tag">{a.action}</span></td>
                      <td>{a.method}</td>
                      <td className="path">{a.path}</td>
                      <td><span className={a.statusCode < 400 ? 'ok-code' : 'bad-code'}>{a.statusCode}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <footer className="foot muted">
            Report generated {new Date(report.generatedAt).toLocaleString()} · sourced from immutable audit records + SHA-256 evidence chain
          </footer>
        </>
      )}
    </div>
  );
}
