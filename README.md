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

### ⬜ Modules 3–8
Not started. Next up: **Module 3 — AI Threat Detection** (log ingest, statistical
anomaly detection, signature IDS rules → ThreatEvents).

## Legal / safety scope
All network scanning defaults to **localhost / private ranges only**
(`AUTHORIZED_SCAN_RANGES` in `.env`). External targets are never scanned by default.
Disruptive actions (e.g. real IP blocking) stay simulated/logged behind an explicit
live-mode flag.
