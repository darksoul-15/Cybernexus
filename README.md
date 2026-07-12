# CYBERNEXUS X

A portfolio-grade **Security Operations Center (SOC)** platform — real working
functionality, not a UI mockup.

**Stack:** React + TypeScript · Node/Express + TypeScript · MongoDB/Mongoose ·
Socket.io · JWT auth.

## Monorepo layout
```
/shared   shared TypeScript domain types (single source of truth)
/server   Node/Express + TS API
/client   React + TS (Vite)   ← scaffolded in a later step
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
- Roles: `admin` / `analyst`; `requireAuth` + `requireRole` middleware.
- All 8 domain schemas defined as shared TS types **and** Mongoose models:
  User, Asset, ScanResult, Vulnerability, ThreatEvent, Incident, EvidenceRecord, AuditLog.
- Audit-log middleware (records sensitive routes) — foundation for Module 8.
- Socket.io server bootstrapped (live channels wired in Module 5).

**What's real vs. architecturally simplified (Module 1):**
- *Real:* bcrypt password hashing, JWT signing/verification, Mongoose persistence,
  role-based route guards, request validation (zod), audit trail writes.
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

### ⬜ Modules 6–8
Not started. Next up: **Module 6 — Automated Incident Response** (auto-generate
incident tickets from ThreatEvents, alerting, gated IP blocking).

## Legal / safety scope
All network scanning defaults to **localhost / private ranges only**
(`AUTHORIZED_SCAN_RANGES` in `.env`). External targets are never scanned by default.
Disruptive actions (e.g. real IP blocking) stay simulated/logged behind an explicit
live-mode flag.
