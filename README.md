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

### ⬜ Modules 2–8
Not started. Next up: **Module 2 — Vulnerability Assessment Engine** (TCP port
scanner → banner enum → CVSS v3.1 → NVD match → per-asset risk score).

## Legal / safety scope
All network scanning defaults to **localhost / private ranges only**
(`AUTHORIZED_SCAN_RANGES` in `.env`). External targets are never scanned by default.
Disruptive actions (e.g. real IP blocking) stay simulated/logged behind an explicit
live-mode flag.
