/** Minimal typed API client. Attaches the JWT and unwraps JSON/errors. */
import type {
  AuditLog,
  AuthResponse,
  ChainVerificationResult,
  ComplianceReport,
  DashboardSummary,
  EvidenceRecord,
  IndicatorReputation,
  IngestSummary,
  ThreatEvent,
} from '@cybernexus/shared';

const TOKEN_KEY = 'cnx_token';

export const tokenStore = {
  get: () => localStorage.getItem(TOKEN_KEY),
  set: (t: string) => localStorage.setItem(TOKEN_KEY, t),
  clear: () => localStorage.removeItem(TOKEN_KEY),
};

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = tokenStore.get();
  const res = await fetch(`/api${path}`, {
    ...options,
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(options.headers ?? {}),
    },
  });
  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.error) message = body.error;
    } catch {
      /* ignore */
    }
    throw new Error(message);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  login: (email: string, password: string) =>
    request<AuthResponse>('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  register: (email: string, password: string, name: string, role?: 'admin' | 'analyst') =>
    request<AuthResponse>('/auth/register', { method: 'POST', body: JSON.stringify({ email, password, name, role }) }),
  me: () => request<{ user: AuthResponse['user'] }>('/auth/me'),

  dashboard: () => request<DashboardSummary>('/dashboard/summary'),

  threats: () => request<{ threats: ThreatEvent[] }>('/threats'),
  ingestSample: () =>
    request<IngestSummary & { sampleEntries: number }>('/threats/ingest/sample', { method: 'POST', body: '{}' }),
  acknowledgeThreat: (id: string) =>
    request<{ threat: ThreatEvent }>(`/threats/${id}/acknowledge`, { method: 'PATCH' }),

  lookup: (indicator: string) =>
    request<{ reputation: IndicatorReputation }>(`/intel/lookup/${encodeURIComponent(indicator)}`),

  // Module 7 — Evidence Vault
  evidenceList: () => request<{ evidence: EvidenceRecord[] }>('/evidence'),
  evidenceVerify: () => request<ChainVerificationResult>('/evidence/verify'),
  evidenceGet: (id: string) => request<{ evidence: EvidenceRecord }>(`/evidence/${id}`),
  evidenceExport: (id: string) => request<{ evidence: EvidenceRecord }>(`/evidence/${id}/export`),
  addEvidence: (type: EvidenceRecord['type'], payload: Record<string, unknown>) =>
    request<{ evidence: EvidenceRecord }>('/evidence', { method: 'POST', body: JSON.stringify({ type, payload }) }),

  // Module 8 — Compliance
  auditLogs: (params: { action?: string; limit?: number } = {}) => {
    const q = new URLSearchParams();
    if (params.action) q.set('action', params.action);
    if (params.limit) q.set('limit', String(params.limit));
    const qs = q.toString();
    return request<{ items: AuditLog[]; total: number }>(`/compliance/audit${qs ? `?${qs}` : ''}`);
  },
  auditStats: () =>
    request<{ total: number; uniqueActors: number; byAction: { key: string; count: number }[] }>('/compliance/audit/stats'),
  complianceReport: () => request<ComplianceReport>('/compliance/report'),
  // PDF is a binary download — fetch directly and trigger a browser save.
  downloadReportPdf: async () => {
    const token = tokenStore.get();
    const res = await fetch('/api/compliance/report.pdf', {
      headers: token ? { authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cybernexus-compliance-${Date.now()}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
};
