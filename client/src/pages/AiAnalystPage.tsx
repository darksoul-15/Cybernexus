import { useEffect, useState } from 'react';
import type { AiAnalysisResponse, AiThreatAssessment } from '@cybernexus/shared';
import { api } from '../api';
import { TopNav } from '../components/TopNav';

const SEV_COLORS: Record<string, string> = {
  critical: '#ff6f7a', high: '#ffab5e', medium: '#f5c451', low: '#6ea8ff',
};

export function AiAnalystPage() {
  const [result, setResult] = useState<AiAnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      setResult(await api.analyzeThreats());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  // Auto-run once on load so the page shows an assessment immediately.
  useEffect(() => {
    run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="app-shell">
      <TopNav>
        <button className="btn primary" onClick={run} disabled={busy}>
          {busy ? 'Analyzing…' : result ? 'Re-analyze' : 'Run AI analysis'}
        </button>
      </TopNav>

      {error && <div className="error banner">{error}</div>}

      <section style={{ marginTop: 20 }}>
        <div className="card">
          <h3>AI Threat Analyst</h3>
          <p className="muted" style={{ margin: '0 0 4px', fontSize: 13, lineHeight: 1.6 }}>
            Claude ({result?.model ?? 'claude-sonnet-5'}) reasons over your most recent{' '}
            <b>real detected threats</b> and returns a prioritized assessment. It never invents
            threats — with no API key configured it reports as unavailable rather than fabricating.
          </p>
        </div>
      </section>

      <section style={{ marginTop: 16 }}>
        {busy && !result ? (
          <div className="card"><div className="empty muted">Consulting the AI analyst…</div></div>
        ) : !result ? null : !result.available ? (
          <div className="card">
            <div className="attest bad">
              <div className="attest-headline">● AI analyst unavailable</div>
              <div className="muted">{result.error ?? 'ANTHROPIC_API_KEY is not configured on the server.'}</div>
            </div>
          </div>
        ) : !result.assessment ? (
          <div className="card">
            <div className="empty muted">
              {result.error ?? 'No threats available to analyze yet.'}{' '}
              Try ingesting sample logs from the Dashboard, then re-analyze.
            </div>
          </div>
        ) : (
          <Assessment a={result.assessment} analyzed={result.analyzedThreats ?? 0} model={result.model} />
        )}
      </section>
    </div>
  );
}

function Assessment({ a, analyzed, model }: { a: AiThreatAssessment; analyzed: number; model?: string }) {
  const sevColor = SEV_COLORS[a.severity] ?? '#8d8ba1';
  return (
    <>
      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
          <span className={`tag sev-${a.severity}`} style={{ fontSize: 12, padding: '4px 12px' }}>
            {a.severity.toUpperCase()}
          </span>
          <span className="pill"><span className="dot" style={{ background: sevColor }} /> {analyzed} threat{analyzed === 1 ? '' : 's'} analyzed</span>
          <span className="pill" style={{ marginLeft: 'auto' }}>confidence {a.confidence}%</span>
        </div>

        <h2 style={{ margin: '0 0 12px', fontSize: 20, fontWeight: 700, lineHeight: 1.3 }}>{a.headline}</h2>

        <div className="heat-bar-track" style={{ height: 8 }}>
          <div className="heat-bar" style={{ width: `${Math.max(0, Math.min(100, a.confidence))}%`, background: sevColor }} />
        </div>
      </div>

      <section className="grid-2">
        <div className="card">
          <h3>Attack narrative</h3>
          <p style={{ margin: 0, fontSize: 14, lineHeight: 1.7 }}>{a.attackNarrative}</p>

          {a.correlatedIps.length > 0 && (
            <>
              <h4 style={{ margin: '16px 0 8px', fontSize: 12, color: 'var(--muted)' }}>Correlated source IPs</h4>
              <div className="chip-row">
                {a.correlatedIps.map((ip) => (
                  <span key={ip} className="tag mono">{ip}</span>
                ))}
              </div>
            </>
          )}
        </div>

        <div className="card">
          <h3>Recommended actions</h3>
          {a.recommendedActions.length === 0 ? (
            <div className="empty muted">No specific actions recommended.</div>
          ) : (
            <ol className="ai-actions">
              {a.recommendedActions.map((step, i) => (
                <li key={i}><span className="ai-step-num">{i + 1}</span><span>{step}</span></li>
              ))}
            </ol>
          )}
        </div>
      </section>

      <footer className="foot muted">
        Generated by {model ?? 'Claude'} from {analyzed} real threat event{analyzed === 1 ? '' : 's'} · assessment grounded in DB records
      </footer>
    </>
  );
}
