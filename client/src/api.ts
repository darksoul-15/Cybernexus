/** Minimal typed API client. Attaches the JWT and unwraps JSON/errors. */
import type {
  AiAnalysisResponse,
  Asset,
  AuditLog,
  AuthResponse,
  AutoRespondResult,
  BlockedIpRecord,
  BlockResult,
  ChainVerificationResult,
  ComplianceReport,
  DashboardSummary,
  EvidenceRecord,
  ForgotPasswordResponse,
  Incident,
  IndicatorReputation,
  IngestSummary,
  LogFormat,
  ScanResult,
  ThreatEvent,
  Vulnerability,
} from '@cybernexus/shared';

const TOKEN_KEY = 'cnx_token';

// Backend origin. Empty in dev (Vite proxies /api → :4000); set VITE_API_URL to
// the deployed backend URL (e.g. https://cybernexus-api.onrender.com) in prod.
export const API_BASE = import.meta.env.VITE_API_URL ?? '';

export const tokenStore = {
  get: () => localStorage.getItem(TOKEN_KEY),
  set: (t: string) => localStorage.setItem(TOKEN_KEY, t),
  clear: () => localStorage.removeItem(TOKEN_KEY),
};

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = tokenStore.get();
  const res = await fetch(`${API_BASE}/api${path}`, {
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
  forgotPassword: (email: string) =>
    request<ForgotPasswordResponse>('/auth/forgot-password', { method: 'POST', body: JSON.stringify({ email }) }),
  resetPassword: (token: string, password: string) =>
    request<{ message: string }>('/auth/reset-password', { method: 'POST', body: JSON.stringify({ token, password }) }),

  dashboard: () => request<DashboardSummary>('/dashboard/summary'),

  threats: () => request<{ threats: ThreatEvent[] }>('/threats'),
  ingestSample: () =>
    request<IngestSummary & { sampleEntries: number }>('/threats/ingest/sample', { method: 'POST', body: '{}' }),
  acknowledgeThreat: (id: string) =>
    request<{ threat: ThreatEvent }>(`/threats/${id}/acknowledge`, { method: 'PATCH' }),

  lookup: (indicator: string) =>
    request<{ reputation: IndicatorReputation }>(`/intel/lookup/${encodeURIComponent(indicator)}`),

  // Module 2 — Assets & Vulnerability Scanning
  assets: () => request<{ assets: Asset[] }>('/assets'),
  createAsset: (input: { name: string; type: Asset['type']; ipAddress: string; authorizedForScan: boolean }) =>
    request<{ asset: Asset }>('/assets', { method: 'POST', body: JSON.stringify(input) }),
  deleteAsset: (id: string) => request<void>(`/assets/${id}`, { method: 'DELETE' }),
  startScan: (assetId: string, opts: { startPort?: number; endPort?: number; enrich?: boolean } = {}) =>
    request<{ scan: ScanResult; openPorts: number; vulnerabilitiesFound: number; riskScore: number }>(
      `/assets/${assetId}/scan`, { method: 'POST', body: JSON.stringify(opts) }),
  scans: (assetId: string) => request<{ scans: ScanResult[] }>(`/assets/${assetId}/scans`),
  vulnerabilities: (assetId?: string) =>
    request<{ vulnerabilities: Vulnerability[] }>(`/vulnerabilities${assetId ? `?assetId=${assetId}` : ''}`),

  // Module 3 — Log ingest (raw text or JSON)
  ingest: (format: LogFormat, data: string | unknown[]) =>
    request<IngestSummary>('/threats/ingest', { method: 'POST', body: JSON.stringify({ format, data }) }),

  // AI Threat Analyst
  analyzeThreats: () => request<AiAnalysisResponse>('/ai/analyze', { method: 'POST', body: '{}' }),

  // Module 6 — Incidents & response
  incidents: (status?: string) =>
    request<{ incidents: Incident[] }>(`/incidents${status ? `?status=${status}` : ''}`),
  autoRespond: (opts: { minScore?: number; autoBlock?: boolean } = {}) =>
    request<AutoRespondResult>('/incidents/auto-respond', { method: 'POST', body: JSON.stringify(opts) }),
  updateIncident: (id: string, patch: { status?: string }) =>
    request<{ incident: Incident }>(`/incidents/${id}`, { method: 'PATCH', body: JSON.stringify(patch) }),
  blockIp: (ip: string, reason?: string) =>
    request<{ block: BlockResult }>('/incidents/block', { method: 'POST', body: JSON.stringify({ ip, reason }) }),
  blocklist: () =>
    request<{ blocklist: BlockedIpRecord[]; liveMode: boolean; realFirewall: boolean }>('/incidents/blocklist'),

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
    const res = await fetch(`${API_BASE}/api/compliance/report.pdf`, {
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
