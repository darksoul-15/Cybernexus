/**
 * Module 4 smoke test — Threat Intelligence Center. Runs fully offline (no API
 * keys / network): normalizers are tested against real provider response shapes,
 * and the cache path is tested by pre-seeding IntelCache.
 *
 * Run from /server:  npx tsx src/modules/intel/intel.smoke.ts
 */
import { MongoMemoryServer } from 'mongodb-memory-server';
import mongoose from 'mongoose';
import net from 'node:net';

let passed = 0;
const assert = (cond: boolean, msg: string) => {
  if (!cond) throw new Error('ASSERT FAILED: ' + msg);
  passed++;
  console.log('  ok -', msg);
};

async function run(): Promise<void> {
  const mem = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mem.getUri();
  process.env.JWT_SECRET = 'intel-smoke-secret';
  // Ensure no keys so provider calls are deterministic (unavailable, not network).
  delete process.env.ABUSEIPDB_API_KEY;
  delete process.env.VIRUSTOTAL_API_KEY;

  // ── 1. Indicator classification ────────────────────────────────────────
  console.log('\n[Indicator classification]');
  const { classifyIndicator } = await import('./indicator.util.js');
  assert(classifyIndicator('8.8.8.8') === 'ip', 'IPv4 classified as ip');
  assert(classifyIndicator('evil.example.com') === 'domain', 'hostname classified as domain');
  assert(classifyIndicator('999.1.1.1') === null, 'out-of-range octets rejected');
  assert(classifyIndicator('not a thing') === null, 'garbage rejected');

  // ── 2. Provider normalizers vs real response shapes ────────────────────
  console.log('\n[Normalizers]');
  const { normalizeAbuse } = await import('./abuseipdb.service.js');
  const { normalizeVt } = await import('./virustotal.service.js');

  const abuseMal = normalizeAbuse({
    data: { ipAddress: '118.25.6.39', abuseConfidenceScore: 100, totalReports: 50, countryCode: 'CN', isp: 'Tencent', domain: 'tencent.com' },
  });
  assert(abuseMal.verdict === 'malicious' && abuseMal.score === 100, 'AbuseIPDB score 100 → malicious');
  assert(abuseMal.detail.totalReports === 50, 'AbuseIPDB detail carries totalReports');
  assert(normalizeAbuse({ data: { abuseConfidenceScore: 0 } }).verdict === 'clean', 'AbuseIPDB score 0 → clean');
  assert(normalizeAbuse({ data: { abuseConfidenceScore: 30 } }).verdict === 'suspicious', 'AbuseIPDB score 30 → suspicious');

  const vtMal = normalizeVt({ data: { attributes: { last_analysis_stats: { harmless: 60, malicious: 5, suspicious: 1, undetected: 10, timeout: 0 }, reputation: -30 } } });
  assert(vtMal.verdict === 'malicious' && vtMal.score === 64, `VT 5 malicious → malicious, score 64 (got ${vtMal.score})`);
  assert(vtMal.detail.engines === 76, 'VT engine total computed');
  assert(normalizeVt({ data: { attributes: { last_analysis_stats: { harmless: 80, malicious: 0, suspicious: 0, undetected: 5 } } } }).verdict === 'clean', 'VT no hits → clean');

  // ── 3. Aggregation (pure) ──────────────────────────────────────────────
  console.log('\n[Aggregation]');
  const { aggregate } = await import('./intel.service.js');
  const agg = aggregate('118.25.6.39', 'ip', [abuseMal, vtMal]);
  assert(agg.verdict === 'malicious', 'worst verdict wins (malicious)');
  assert(agg.score === 100, 'max provider score wins (100)');
  const none = aggregate('1.2.3.4', 'ip', [
    { provider: 'abuseipdb', available: false, verdict: 'unknown', score: 0, cached: false, detail: {} },
  ]);
  assert(none.verdict === 'unknown' && none.score === 0, 'no available sources → unknown');

  // ── 4. Cache round-trip via lookupIndicator ────────────────────────────
  console.log('\n[Cache]');
  await mongoose.connect(process.env.MONGODB_URI);
  const { IntelCacheModel } = await import('./intelCache.model.js');
  const { lookupIndicator } = await import('./intel.service.js');

  for (const provider of ['virustotal', 'abuseipdb'] as const) {
    await IntelCacheModel.create({
      cacheKey: `${provider}:ip:8.8.4.4`,
      provider, type: 'ip', indicator: '8.8.4.4',
      result: { provider, available: true, verdict: 'malicious', score: 90, cached: false, detail: { seeded: true } },
      fetchedAt: new Date(),
    });
  }
  const cachedRep = await lookupIndicator('8.8.4.4');
  assert(cachedRep.verdict === 'malicious' && cachedRep.score === 90, 'cached providers drive the verdict');
  assert(cachedRep.sources.every((s) => s.cached === true), 'sources served from cache (cached:true)');
  assert(cachedRep.sources.length === 2, 'both providers present for an IP');

  // No key + not cached → unknown (graceful degradation, no fabrication)
  const uncached = await lookupIndicator('9.9.9.9');
  assert(uncached.verdict === 'unknown', 'uncached + no key → unknown');
  assert(uncached.sources.every((s) => !s.available), 'providers report unavailable, not fake data');

  // ── 5. HTTP endpoints ──────────────────────────────────────────────────
  console.log('\n[HTTP]');
  const { createApp } = await import('../../app.js');
  const { createServer } = await import('node:http');
  const httpServer = createServer(createApp());
  await new Promise<void>((r) => httpServer.listen(0, r));
  const base = `http://localhost:${(httpServer.address() as net.AddressInfo).port}`;
  const reg = await (await fetch(`${base}/api/auth/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'i@nexus.io', password: 'password123', name: 'I', role: 'admin' }),
  })).json();
  const authH = { authorization: `Bearer ${reg.tokens.accessToken}`, 'content-type': 'application/json' };

  const httpCached = await (await fetch(`${base}/api/intel/lookup/8.8.4.4`, { headers: authH })).json();
  assert(httpCached.reputation.verdict === 'malicious', 'GET /api/intel/lookup returns cached malicious verdict');

  const bad = await fetch(`${base}/api/intel/lookup/not-an-indicator`, { headers: authH });
  assert(bad.status === 400, 'invalid indicator → 400');

  const noauth = await fetch(`${base}/api/intel/lookup/8.8.8.8`);
  assert(noauth.status === 401, 'lookup requires auth');

  const enrichRes = await (await fetch(`${base}/api/intel/enrich`, { method: 'POST', headers: authH, body: '{}' })).json();
  assert(typeof enrichRes.checked === 'number', 'POST /api/intel/enrich returns a summary');

  console.log(`\nALL ${passed} MODULE-4 CHECKS PASSED ✅`);
  await mongoose.disconnect();
  httpServer.close();
  await mem.stop();
  process.exit(0);
}

run().catch((e) => {
  console.error('\nMODULE-4 SMOKE FAILED ❌', e);
  process.exit(1);
});
