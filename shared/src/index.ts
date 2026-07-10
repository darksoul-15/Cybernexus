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
