# CYBERNEXUS X

A portfolio-grade **Security Operations Center (SOC)** platform — real working
functionality, not a UI mockup.

**Stack:** React + TypeScript · Node/Express + TypeScript · MongoDB/Mongoose ·
Socket.io · JWT auth.

## Monorepo layout
```
/shared   shared TypeScript domain types (single source of truth)
/server   Node/Express + TS API
/client   React + TS (Vite): Dashboard, Evidence Vault, Compliance
```

## Setup
1. **MongoDB Atlas** — create a free M0 cluster, then Database → Connect → Drivers,
   copy the connection string.
2. Configure the server:
   ```bash
   cp server/.env.example server/.env
   # paste your Atlas URI into MONGODB_URI, set a long JWT_SECRET
   ```
3. Install + build shared types + run the API:
   ```bash
   npm install
   npm run build:shared
   npm run dev:server        # http://localhost:4000
   ```
4. Health check: `GET http://localhost:4000/api/health`

## Run the whole stack with zero setup (no Atlas needed)
Boots the API against an in-memory MongoDB, plus the React client:
```bash
npm install && npm run build:shared
cd server && npm run dev:memory     # API + Socket.io on :4000 (in-memory Mongo)
cd client && npm run dev            # dashboard on http://localhost:5173
```
Open http://localhost:5173, register an admin, then click "Ingest sample logs"
to watch threats stream onto the dashboard live. (Data is discarded on exit —
use a real `MONGODB_URI` via `npm run dev:server` to persist.)

## Verify the auth slice (no Atlas needed)
Runs the API against an in-memory MongoDB and exercises register → login → /me:
```bash
cd server && npx tsx src/smoke.ts
```

---

## Module status

### ✅ Module 1 — Foundation
- Monorepo with npm workspaces (`/shared`, `/server`, `/client`).
- JWT auth: `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/auth/me`.
- Password reset: `POST /api/auth/forgot-password`, `POST /api/auth/reset-password` —
  single-use, hashed, 1-hour-expiry tokens; the response is identical whether or not
  the email is registered (no account-enumeration side channel).
- Roles: `admin` / `analyst`; `requireAuth` + `requireRole` middleware.
- All 8 domain schemas defined as shared TS types **and** Mongoose models:
  User, Asset, ScanResult, Vulnerability, ThreatEvent, Incident, EvidenceRecord, AuditLog.
- Audit-log middleware (records sensitive routes) — foundation for Module 8.
- Socket.io server bootstrapped (live channels wired in Module 5).

**What's real vs. architecturally simplified (Module 1):**
- *Real:* bcrypt password hashing, JWT signing/verification, Mongoose persistence,
  role-based route guards, request validation (zod), audit trail writes. Password
  reset sends a genuine email via the same SMTP transport as incident alerting
  (Module 6); with no SMTP configured, it degrades honestly — the link is logged
  server-side rather than the endpoint claiming a delivery that didn't happen.
- *Simplified:* access-token-only auth (no refresh-token rotation yet) — adequate for
  a portfolio SOC; documented rather than hidden.

### ✅ Module 2 — Vulnerability Assessment Engine
Full vertical slice: authorize target → TCP scan → banner enum → NVD CVE
enrichment (real CVSS v3.1) → persist vulnerabilities → per-asset risk score.

- **Real TCP connect scanner** (`net` sockets), bounded concurrency, per-port
  timeout, configurable range. Banner/service enumeration on open ports.
- **Real CVSS v3.1 Base Score calculator** — implements the FIRST.org formula
  (ISS/Impact/Exploitability/Roundup), not a lookup table. Verified against
  official test vectors (9.8, 10.0, 7.5, 5.5, 0.0).
- **NVD CVE matching** against the live NVD 2.0 API by product/version, cached in
  MongoDB (7-day TTL) to respect the free-tier rate limit.
- **Per-asset risk score** (0–100) via a documented cumulative heuristic.
- **Scope guard**: every scan target is CIDR-checked against
  `AUTHORIZED_SCAN_RANGES`; assets outside allowed ranges can't be marked scannable.

Endpoints (all require auth):
- `POST /api/assets` · `GET /api/assets` · `GET /api/assets/:id` · `DELETE /api/assets/:id` (admin)
- `POST /api/assets/:assetId/scan` · `GET /api/assets/:assetId/scans`
- `GET /api/vulnerabilities?assetId=` · `POST /api/cvss/score`

Verify (offline, in-memory DB): `cd server && npx tsx src/modules/vulnerability/vuln.smoke.ts` → 32/32 checks.

**What's real vs. architecturally simplified (Module 2):**
- *Real:* TCP scanning + banner grab, the full CVSS v3.1 math, live NVD lookups,
  Mongo caching, scope enforcement, risk aggregation.
- *Simplified:* TCP-connect scan only (no SYN/stealth or UDP); NVD matching is
  keyword (product/version) rather than precise CPE matching; risk score is a
  documented heuristic, not an industry-standard model (e.g. EPSS).

### ✅ Module 3 — AI Threat Detection
Full vertical slice: parse logs → run detectors → link target assets → persist
ThreatEvents.

- **Log parser** for Apache/Nginx **common & combined** access-log formats
  (real CLF date parsing with timezone offset) plus structured JSON entries;
  unparseable lines are counted as skipped, never fabricated.
- **Statistical detectors:** request-rate anomaly via **leave-one-out z-score**
  over time windows; **port-scan** detection (distinct ports from one source
  within a sliding window).
- **Signature detectors:** **brute-force** (repeated failed logins from one IP)
  and **SYN-flood** (burst of bare-SYN packets) via sliding-window counting.
- **Tunable thresholds** (z-score, window sizes, counts) overridable per request.
- **Synthetic sample-log generator** (deterministic PRNG) with optionally-embedded
  attacks — synthetic *input* you control, not fabricated threat output.
- Detections persist as `ThreatEvent`s with evidence + 0–100 score, and link to an
  `Asset` when the target IP matches.

Endpoints (all require auth):
- `POST /api/threats/ingest` (raw logs or JSON) · `POST /api/threats/ingest/sample`
- `GET /api/threats` (filter by category/severity/acknowledged) · `GET /api/threats/stats`
- `PATCH /api/threats/:id/acknowledge`

Verify (offline, in-memory DB): `cd server && npx tsx src/modules/threat/threat.smoke.ts` → 22/22 checks.

**What's real vs. architecturally simplified (Module 3):**
- *Real:* log parsing, z-score/sliding-window math, all four detectors, persistence,
  asset linking, tunable thresholds.
- *Simplified:* batch analysis of ingested logs (not a live streaming pipeline);
  SYN-flood relies on a TCP-flags field in the input rather than raw packet capture;
  detection is threshold/heuristic-based, not an ML-trained model ("AI" = statistical
  anomaly detection).

### ✅ Module 4 — Threat Intelligence Center
Reputation lookups for IPs/domains across two real free-tier providers, with a
MongoDB cache and graceful degradation.

- **AbuseIPDB** (v2 CHECK, IP-only) and **VirusTotal** (v3, IPs + domains) live
  reputation lookups; each provider response normalized to a verdict + 0–100 score.
- **Aggregation** across providers — worst verdict wins, max score wins.
- **MongoDB cache** keyed by `provider:type:indicator` (24h TTL) to respect
  free-tier rate limits (AbuseIPDB 1000/day, VirusTotal 4/min).
- **Graceful degradation**: missing API key or failed request → the provider
  reports `available:false` and the verdict is `unknown` — never fabricated.
  Misses/errors are not cached, so results self-heal once keys are configured.
- **Threat enrichment**: looks up recent `ThreatEvent` source IPs and raises a
  `reputation` ThreatEvent when a source is judged malicious (deduped per IP).
- Indicator validation rejects malformed IPs/domains (alphabetic-TLD rule stops
  dotted-numeric strings from being mistaken for domains).

Config: set `ABUSEIPDB_API_KEY` / `VIRUSTOTAL_API_KEY` in `.env` (both optional).

Endpoints (all require auth):
- `GET /api/intel/lookup/:indicator` (`?force=true` to bypass cache)
- `POST /api/intel/enrich` (enrich recent threat source IPs)

Verify (offline, in-memory DB): `cd server && npx tsx src/modules/intel/intel.smoke.ts` → 23/23 checks.

**What's real vs. architecturally simplified (Module 4):**
- *Real:* live AbuseIPDB + VirusTotal API integration, response normalization,
  cross-provider aggregation, Mongo caching, indicator validation, threat enrichment.
- *Simplified:* two providers (not a full intel fabric); VirusTotal score is a
  documented weighting of engine hits, not VT's own proprietary score; domain
  reputation uses VirusTotal only (AbuseIPDB is IP-only).

### ✅ Module 5 — SOC Dashboard
Live React dashboard over the whole backend, with real-time Socket.io updates.

- **React + TypeScript client** (Vite) in `/client` — the first UI in the project.
- **Auth flow**: register/login, JWT persisted in localStorage, guarded routes,
  `GET /api/auth/me` session restore.
- **Dashboard aggregation** endpoint `GET /api/dashboard/summary` built entirely
  from Mongo aggregations (no fabricated numbers).
- **Recharts** visualizations: threats-by-category bar, severity-distribution
  pie, plus a custom asset risk heat map.
- **Live updates via Socket.io**: the server emits `threat:new` / `scan:completed`
  / `dashboard:update` from the threat, vulnerability and intel services; the
  dashboard live-appends to a threat feed and debounce-refetches the summary.
  Socket connections require a valid JWT in the handshake.
- Verified end-to-end in a real browser: register → live dashboard → "Ingest
  sample logs" → 4 threats pushed live → charts populate → acknowledge decrements
  the unacknowledged counter.

Endpoints: `GET /api/dashboard/summary` (auth). Socket namespace `/` (JWT handshake).

Verify (server aggregation, offline): `cd server && npx tsx src/modules/dashboard/dashboard.smoke.ts` → 9/9 checks.

**What's real vs. architecturally simplified (Module 5):**
- *Real:* live Socket.io push, JWT-authenticated sockets, Mongo-aggregated
  summary, Recharts over real data, full auth flow.
- *Simplified:* dashboard broadcasts to all connected clients (no per-user rooms
  / RBAC on socket channels); the client bundle isn't code-split (Recharts makes
  it ~600 kB) — fine for a portfolio, noted for honesty.

### ✅ Module 6 — Automated Incident Response
Full vertical slice: correlate ThreatEvents → generate Incidents → alert →
(gated) containment.

- **Auto-response engine** (`POST /api/incidents/auto-respond`): selects
  unacknowledged, unlinked threats that are high/critical or score ≥
  `AUTO_INCIDENT_MIN_SCORE`, correlates them by source IP into Incident tickets,
  links the threats, and is idempotent (linked threats aren't re-processed).
- **Alerting**: email via nodemailer when SMTP is configured, plus an always-on
  in-app notification pushed over Socket.io. No SMTP → in-app only, no error.
- **IP blocking — safe by default (project rule 7):** two independent opt-ins.
  Blocks are **simulated/logged** unless `RESPONSE_LIVE_MODE=true`, and even then
  no OS firewall command executes unless `RESPONSE_ALLOW_REAL_FIREWALL=true`
  (off in this build). A `BlockedIp` ledger records every action with an
  `enforced` flag; blocking is admin-only and audited.
- Incident management: list/filter, get, status transitions (sets `resolvedAt`,
  appends to the action timeline), all reflected on the dashboard.

Endpoints (auth): `POST /api/incidents/auto-respond`, `GET /api/incidents`,
`GET /api/incidents/:id`, `PATCH /api/incidents/:id`, `GET /api/incidents/blocklist`,
`POST /api/incidents/block` (admin).

Config: `AUTO_INCIDENT_MIN_SCORE`, `RESPONSE_LIVE_MODE`,
`RESPONSE_ALLOW_REAL_FIREWALL`, `SMTP_*` / `ALERT_*`.

Verify (offline, in-memory DB): `cd server && npx tsx src/modules/incident/incident.smoke.ts` → 18/18 checks.

**What's real vs. architecturally simplified (Module 6):**
- *Real:* threat correlation, incident lifecycle, nodemailer email, live Socket.io
  alerts, the blocked-IP ledger, RBAC + audit on containment, and the actual
  `netsh`/`iptables` command construction.
- *Simplified / deliberately gated:* real firewall execution is OFF behind two
  flags and never runs in this build — a documented safety decision, not a
  limitation; correlation is by source IP (no time-window/kill-chain grouping).

### ✅ Module 7 — Blockchain Evidence Vault
A real SHA-256 hash-chain ledger with tamper detection and chain-of-custody.

- **Hash-chain**: each `EvidenceRecord` stores a `contentHash` (SHA-256 of the
  canonicalized payload) and a `hash` binding its index, contentHash, the
  previous record's hash, timestamp and type. Genesis links to 64 zeros.
- **Deterministic canonicalization** (recursively sorted keys) so the same
  payload always hashes identically — the basis for reliable verification.
- **Tamper detection** (`GET /api/evidence/verify`): re-walks the chain and
  reports the exact index of any altered payload, forged hash, broken link, or
  index gap. Editing a past record breaks that record *and* every link after it.
- **Chain-of-custody**: every record carries a custody log; accessing and
  exporting a record append `accessed`/`exported` entries (with who + when).
- Append is two-step so the stored hash and stored timestamp stay consistent;
  retries on a concurrent index collision (unique index on `index`).

Endpoints (auth): `POST /api/evidence`, `GET /api/evidence`,
`GET /api/evidence/verify`, `GET /api/evidence/:id`, `GET /api/evidence/:id/export`.

Verify (offline, in-memory DB): `cd server && npx tsx src/modules/evidence/evidence.smoke.ts` → 24/24 checks.

**What's real vs. architecturally simplified (Module 7):**
- *Real:* SHA-256 hashing, canonicalization, the full chain-linking + tamper
  verification, chain-of-custody logging.
- *Simplified (documented, per project scope):* a single-writer hash-chain in
  MongoDB — **not** a distributed blockchain (no P2P network, consensus, proof of
  work, or Merkle trees). It delivers tamper-evidence, not decentralization.

### Client UI coverage
The React client (`/client`) covers all 8 modules across authenticated views
sharing a top nav:
- **Dashboard** — live stats, Recharts, risk heat map, live threat feed.
- **Scanning** — add assets, run real TCP scans on localhost, view open ports +
  banners + matched CVEs + CVSS + per-asset risk score (Module 2).
- **Threats** — drag-drop an Apache/Nginx access log (or synthesize one) to
  detect threats, browse the threat table, and run IP/domain intel lookups
  (Modules 3 & 4).
- **Incidents** — run the auto-response engine, watch threats correlate into
  incident tickets, transition status, and view the simulated containment
  blocklist (Module 6).
- **Evidence Vault** — chain-integrity attestation, append records, browse the
  ledger, inspect payload + chain-of-custody (Module 7).
- **Compliance** *(admin-only)* — audit-trail table, actions-by-type + incident
  posture, and one-click **PDF report download** (Module 8). Nav link hidden and
  route guarded for non-admins.

### ✅ Module 8 — Compliance Module
Surfaces the audit trail and generates PDF compliance reports from real data.

- **Audit-log middleware** (`audit()`), wired across every sensitive route since
  Module 1 (auth, assets, scans, threats, intel, incidents, evidence, compliance),
  writes immutable AuditLog records.
- **Audit queries**: `GET /api/compliance/audit` (filter by actor/action/date
  range, paginated) and `GET /api/compliance/audit/stats`.
- **Compliance report**: assembled from AuditLog + Incident + live evidence-chain
  verification — available as JSON or a generated **PDF** (pdfkit) with an
  evidence-integrity attestation, audit summary, incident summary, and a recent-
  events table.
- Admin-only; report generation is itself audited.

Endpoints (admin): `GET /api/compliance/audit`, `GET /api/compliance/audit/stats`,
`GET /api/compliance/report`, `GET /api/compliance/report.pdf`.

Verify (offline, in-memory DB): `cd server && npx tsx src/modules/compliance/compliance.smoke.ts` → 15/15 checks.

**What's real vs. architecturally simplified (Module 8):**
- *Real:* immutable audit trail, filtered queries, report aggregation from real
  records, genuine PDF generation with the evidence-chain attestation.
- *Simplified:* reports map to no specific framework's exact control set (e.g.
  SOC 2 / ISO 27001) — it's a general security-operations compliance report.

---

## ✦ AI Threat Analyst (LLM analysis)
A genuine AI layer on top of the statistical/signature detectors: it sends the
recently detected `ThreatEvent`s to **Claude** (`claude-sonnet-5`) and gets back a
schema-validated assessment — severity, attack narrative, correlated IPs, and
prioritized recommended actions. The deterministic detectors remain the source of
truth; the LLM only reasons over their real output (no fabricated threats).

- Uses the Anthropic SDK with **structured outputs** (JSON-schema-constrained
  response) so the result always validates to a typed shape.
- Degrades gracefully: without `ANTHROPIC_API_KEY` the endpoint returns
  `available:false` instead of fabricating — same pattern as the NVD/AbuseIPDB
  integrations.
- Surfaced as an **"AI Threat Analyst" card** on the Threats page (button →
  assessment); endpoint `POST /api/ai/analyze` (auth, audited).
- Config: `ANTHROPIC_API_KEY` + optional `AI_MODEL` (default `claude-sonnet-5`).

Verify (offline; runs a live analysis too if `ANTHROPIC_API_KEY` is set):
`cd server && npx tsx src/modules/ai/ai.smoke.ts`.

## 🎉 All 8 modules complete
Every module ships end-to-end (scan/detect/enrich → store → display → report) and
is backed by an offline smoke test. Run them all:
```bash
cd server
for m in smoke \
  modules/vulnerability/vuln.smoke modules/threat/threat.smoke \
  modules/intel/intel.smoke modules/dashboard/dashboard.smoke \
  modules/incident/incident.smoke modules/evidence/evidence.smoke \
  modules/compliance/compliance.smoke; do npx tsx src/$m.ts; done
```

## Legal / safety scope
All network scanning defaults to **localhost / private ranges only**
(`AUTHORIZED_SCAN_RANGES` in `.env`). External targets are never scanned by default.
Disruptive actions (e.g. real IP blocking) stay simulated/logged behind an explicit
live-mode flag.
