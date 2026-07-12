/**
 * CYBERNEXUS X — Shared domain types
 * Single source of truth for the 8 core entities, shared by client + server.
 * Mongoose schemas on the server mirror these; API responses are typed to these.
 */

// ── Common ────────────────────────────────────────────────────────────────
export type ID = string; // Mongo ObjectId serialized as string over the wire
export type ISODate = string; // Dates serialized as ISO 8601 strings in API responses

export type UserRole = 'admin' | 'analyst';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

// ── 1. User ─────────────────────────────────────────────────────────────────
export interface User {
  _id: ID;
  email: string;
  name: string;
  role: UserRole;
  // passwordHash is server-only; never serialized to the client
  createdAt: ISODate;
  updatedAt: ISODate;
}

// ── 2. Asset ──────────────────────────────────────────────────────────────
// A monitored target (host/service) the SOC watches. Scans/scores attach here.
export type AssetType = 'host' | 'service' | 'container' | 'web-app';

export interface Asset {
  _id: ID;
  name: string;
  type: AssetType;
  ipAddress: string; // localhost / private range by default
  hostname?: string;
  tags: string[];
  owner: ID; // User._id
  authorizedForScan: boolean; // gate: only scan if explicitly authorized
  riskScore: number; // 0-100 aggregate, computed from vulnerabilities
  lastScannedAt?: ISODate;
  createdAt: ISODate;
  updatedAt: ISODate;
}

// ── 3. ScanResult ─────────────────────────────────────────────────────────
// One port-scan run against one Asset. Holds per-port findings.
export type PortState = 'open' | 'closed' | 'filtered';

export interface PortFinding {
  port: number;
  protocol: 'tcp' | 'udp';
  state: PortState;
  service?: string; // enumerated service name (e.g. "http")
  banner?: string; // grabbed banner text
  product?: string; // e.g. "nginx"
  version?: string; // e.g. "1.25.3"
}

export interface ScanResult {
  _id: ID;
  asset: ID; // Asset._id
  initiatedBy: ID; // User._id
  target: string; // resolved IP that was scanned
  portRange: { start: number; end: number };
  status: 'queued' | 'running' | 'completed' | 'failed';
  ports: PortFinding[];
  startedAt: ISODate;
  completedAt?: ISODate;
  durationMs?: number;
  error?: string;
  createdAt: ISODate;
  updatedAt: ISODate;
}

// ── 4. Vulnerability ──────────────────────────────────────────────────────
// A CVE match / finding tied to an asset + the scan that surfaced it.
export interface CvssV31Vector {
  vectorString: string; // e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  baseScore: number; // 0.0-10.0, computed from the real formula
  baseSeverity: Severity;
}

export interface Vulnerability {
  _id: ID;
  asset: ID; // Asset._id
  scanResult?: ID; // ScanResult._id that surfaced it (if any)
  cveId?: string; // e.g. "CVE-2023-12345" (from NVD match)
  title: string;
  description: string;
  affectedService?: string; // e.g. "nginx 1.25.3"
  cvss: CvssV31Vector;
  source: 'nvd' | 'manual' | 'heuristic';
  status: 'open' | 'triaged' | 'resolved' | 'accepted-risk';
  references: string[]; // URLs
  createdAt: ISODate;
  updatedAt: ISODate;
}

// ── 5. ThreatEvent ────────────────────────────────────────────────────────
// An anomaly / IDS hit flagged by the AI Threat Detection module.
export type ThreatCategory =
  | 'anomaly-rate'
  | 'port-scan'
  | 'brute-force'
  | 'syn-flood'
  | 'signature'
  | 'reputation';

export interface ThreatEvent {
  _id: ID;
  category: ThreatCategory;
  severity: Severity;
  sourceIp?: string;
  targetAsset?: ID; // Asset._id
  detectionMethod: 'statistical' | 'signature' | 'reputation';
  description: string;
  evidence: Record<string, unknown>; // metrics that triggered it (z-score, counts, etc.)
  score: number; // confidence/severity 0-100
  acknowledged: boolean;
  incident?: ID; // Incident._id if escalated
  detectedAt: ISODate;
  createdAt: ISODate;
  updatedAt: ISODate;
}

// ── 6. Incident ───────────────────────────────────────────────────────────
// A ticket auto-generated (or manually raised) from one or more ThreatEvents.
export type IncidentStatus = 'new' | 'investigating' | 'contained' | 'resolved' | 'closed';

export interface IncidentAction {
  at: ISODate;
  by: ID; // User._id
  action: string; // e.g. "blocked IP (simulated)"
  live: boolean; // false = simulated/logged, true = real disruptive action
}

export interface Incident {
  _id: ID;
  title: string;
  status: IncidentStatus;
  severity: Severity;
  assignee?: ID; // User._id
  relatedThreats: ID[]; // ThreatEvent._id[]
  relatedAsset?: ID; // Asset._id
  summary: string;
  actions: IncidentAction[]; // response timeline
  openedAt: ISODate;
  resolvedAt?: ISODate;
  createdAt: ISODate;
  updatedAt: ISODate;
}

// ── 7. EvidenceRecord ─────────────────────────────────────────────────────
// A tamper-evident record in the SHA-256 hash-chain evidence vault.
export interface EvidenceRecord {
  _id: ID;
  index: number; // position in the chain (0 = genesis)
  incident?: ID; // Incident._id this evidence belongs to
  type: 'log' | 'scan' | 'threat' | 'file' | 'note';
  payload: Record<string, unknown>; // the evidence content that gets hashed
  contentHash: string; // SHA-256 of canonicalized payload
  previousHash: string; // contentHash of record index-1 (genesis = "0"*64)
  hash: string; // SHA-256(index + contentHash + previousHash + timestamp)
  custody: Array<{ at: ISODate; by: ID; action: 'created' | 'accessed' | 'exported' }>;
  createdBy: ID; // User._id
  createdAt: ISODate;
}

// ── 8. AuditLog ───────────────────────────────────────────────────────────
// Immutable record of every sensitive action, for the Compliance module.
export interface AuditLog {
  _id: ID;
  actor?: ID; // User._id (absent for unauthenticated attempts)
  actorEmail?: string;
  action: string; // e.g. "asset.scan.start"
  method: string; // HTTP method
  path: string; // request path
  statusCode: number;
  ip: string;
  meta?: Record<string, unknown>;
  createdAt: ISODate;
}

// ── API envelope + auth ─────────────────────────────────────────────────────
export interface ApiError {
  error: string;
  details?: unknown;
}

export interface AuthTokens {
  accessToken: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  name: string;
  role?: UserRole; // defaults to 'analyst'
}

export interface AuthResponse {
  user: User;
  tokens: AuthTokens;
}

// ── Module 3: AI Threat Detection ───────────────────────────────────────────
// Normalized log entry — the unit of input to the detection engine. Produced
// by parsing access logs (combined/common format) or supplied as JSON.
export interface LogEntry {
  timestamp: ISODate;
  sourceIp: string;
  destIp?: string;
  destPort?: number;
  method?: string;
  path?: string;
  statusCode?: number;
  bytes?: number;
  protocol?: 'tcp' | 'udp';
  flags?: string; // TCP flags, e.g. "S" for a bare SYN
}

export type LogFormat = 'combined' | 'common' | 'json';

// Tunable detection thresholds (all have server-side defaults).
export interface ThreatDetectionConfig {
  rateWindowSec: number; // bucket size for rate anomaly
  rateZThreshold: number; // z-score to flag a rate spike
  rateMinCount: number; // floor so tiny buckets don't trip
  portScanWindowSec: number; // sliding window for distinct-port counting
  portScanDistinctPorts: number; // distinct ports from one IP to flag a scan
  bruteForceWindowSec: number; // sliding window for failed logins
  bruteForceAttempts: number; // failed logins from one IP to flag brute-force
  synFloodWindowSec: number; // sliding window for SYN counting
  synFloodCount: number; // SYNs from one IP to flag a flood
}

// Summary returned by an ingest+detect run.
export interface IngestSummary {
  entriesParsed: number;
  entriesSkipped: number;
  threatsDetected: number;
  byCategory: Partial<Record<ThreatCategory, number>>;
  threats: ThreatEvent[];
}

// ── Module 4: Threat Intelligence Center ────────────────────────────────────
export type IndicatorType = 'ip' | 'domain';
export type ReputationVerdict = 'clean' | 'suspicious' | 'malicious' | 'unknown';
export type IntelProvider = 'abuseipdb' | 'virustotal';

// One provider's normalized opinion about an indicator.
export interface ProviderReputation {
  provider: IntelProvider;
  available: boolean; // false when no API key or the request failed
  verdict: ReputationVerdict;
  score: number; // 0–100 maliciousness as judged by this provider
  detail: Record<string, unknown>; // normalized fields (reports, engine hits, ...)
  cached: boolean;
  error?: string;
}

// Aggregated reputation across providers.
export interface IndicatorReputation {
  indicator: string;
  type: IndicatorType;
  verdict: ReputationVerdict; // worst verdict across available sources
  score: number; // max provider score across available sources
  sources: ProviderReputation[];
  checkedAt: ISODate;
}

// ── Module 5: SOC Dashboard ─────────────────────────────────────────────────
export interface CountBucket {
  key: string;
  count: number;
}

export interface AssetRiskEntry {
  _id: ID;
  name: string;
  ipAddress: string;
  riskScore: number;
  band: Severity;
}

export interface DashboardSummary {
  assets: {
    total: number;
    scannable: number;
    heatmap: AssetRiskEntry[]; // sorted by riskScore desc
  };
  vulnerabilities: {
    total: number;
    open: number;
    bySeverity: CountBucket[];
  };
  threats: {
    total: number;
    unacknowledged: number;
    byCategory: CountBucket[];
    bySeverity: CountBucket[];
    recent: ThreatEvent[];
  };
  incidents: {
    total: number;
    byStatus: CountBucket[];
  };
  generatedAt: ISODate;
}

// Socket.io event channel names + payloads (shared client/server contract).
export const SOCKET_EVENTS = {
  threatNew: 'threat:new',
  scanCompleted: 'scan:completed',
  incidentNew: 'incident:new',
  dashboardUpdate: 'dashboard:update',
} as const;

export interface ThreatNewPayload {
  threats: ThreatEvent[];
}
export interface ScanCompletedPayload {
  assetId: ID;
  openPorts: number;
  vulnerabilitiesFound: number;
  riskScore: number;
}

// ── Module 6: Automated Incident Response ───────────────────────────────────
export type BlockMode = 'simulated' | 'live';

export interface BlockResult {
  ip: string;
  mode: BlockMode;
  enforced: boolean; // true only if a real firewall rule was actually applied
  message: string;
}

export interface AutoRespondResult {
  qualifyingThreats: number;
  incidentsCreated: number;
  incidents: Incident[];
  alertsSent: number;
  blocks: BlockResult[];
}

// A blocked-IP ledger entry (containment record; simulated unless live mode).
export interface BlockedIpRecord {
  _id: ID;
  ip: string;
  mode: BlockMode;
  enforced: boolean;
  reason: string;
  incident?: ID;
  active: boolean;
  createdBy?: ID;
  createdAt: ISODate;
}

// ── Module 7: Blockchain Evidence Vault ─────────────────────────────────────
export interface ChainIssue {
  index: number;
  recordId: ID;
  problem: string;
}

export interface ChainVerificationResult {
  valid: boolean;
  length: number;
  headHash: string | null; // hash of the latest record (chain head)
  issues: ChainIssue[];
  verifiedAt: ISODate;
}

// ── Module 8: Compliance Module ─────────────────────────────────────────────
export interface ComplianceReport {
  generatedAt: ISODate;
  generatedBy: { id: ID; email: string } | null;
  period: { from?: ISODate; to?: ISODate };
  audit: {
    total: number;
    uniqueActors: number;
    byAction: CountBucket[];
    recent: AuditLog[];
  };
  incidents: {
    total: number;
    byStatus: CountBucket[];
    bySeverity: CountBucket[];
  };
  evidence: {
    chainValid: boolean;
    length: number;
    headHash: string | null;
  };
}
