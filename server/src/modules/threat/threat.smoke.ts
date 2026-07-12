/**
 * Module 3 smoke test — AI Threat Detection.
 *   - log parser on a real combined-format line
 *   - each detector fires on its pattern and NOT on a benign baseline
 *   - full ingest → persist → asset-link pipeline via HTTP + in-memory MongoDB
 *
 * Run from /server:  npx tsx src/modules/threat/threat.smoke.ts
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
  process.env.JWT_SECRET = 'threat-smoke-secret';

  // ── 1. Log parser ──────────────────────────────────────────────────────
  console.log('\n[Log parser]');
  const { parseLogs, parseClfDate } = await import('./logParser.service.js');
  const line = '198.51.100.9 - - [10/Oct/2026:13:55:36 -0700] "GET /admin HTTP/1.1" 403 512 "-" "curl/8"';
  const { entries, skipped } = parseLogs(line, 'combined');
  assert(entries.length === 1 && skipped === 0, 'combined line parsed');
  assert(entries[0].sourceIp === '198.51.100.9', 'sourceIp extracted');
  assert(entries[0].statusCode === 403 && entries[0].path === '/admin', 'status + path extracted');
  assert(parseClfDate('10/Oct/2026:13:55:36 -0700')!.startsWith('2026-10-10T20:55:36'), 'CLF date → UTC ISO');
  assert(parseLogs('garbage line', 'combined').skipped === 1, 'unparseable line skipped, not fabricated');

  // ── 2. Detectors on synthetic patterns ────────────────────────────────
  console.log('\n[Detectors]');
  const { runDetectors } = await import('./detection.service.js');
  const { generateSampleLogs } = await import('./sampleLogs.js');

  const benign = generateSampleLogs({ minutes: 10, ratePerMin: 12 });
  const benignDet = runDetectors(benign);
  assert(benignDet.length === 0, `benign baseline yields no detections (got ${benignDet.length})`);

  const cats = (dets: ReturnType<typeof runDetectors>) => new Set(dets.map((d) => d.category));

  assert(cats(runDetectors(generateSampleLogs({ includeRateSpike: true }))).has('anomaly-rate'), 'rate spike → anomaly-rate');
  assert(cats(runDetectors(generateSampleLogs({ includePortScan: true }))).has('port-scan'), 'port scan → port-scan');
  assert(cats(runDetectors(generateSampleLogs({ includeBruteForce: true }))).has('brute-force'), 'failed logins → brute-force');
  assert(cats(runDetectors(generateSampleLogs({ includeSynFlood: true }))).has('syn-flood'), 'SYN burst → syn-flood');

  const all = runDetectors(generateSampleLogs({
    includeRateSpike: true, includePortScan: true, includeBruteForce: true, includeSynFlood: true,
  }));
  assert(cats(all).size === 4, `all four categories detected together (got ${[...cats(all)].join(',')})`);
  const bf = all.find((d) => d.category === 'brute-force')!;
  assert(bf.sourceIp === '203.0.113.66', 'brute-force attributes correct source IP');
  assert(typeof bf.evidence.failedAttempts === 'number' && bf.score > 0, 'detection carries evidence + score');

  // ── 3. HTTP pipeline (ingest → persist → asset link) ──────────────────
  console.log('\n[HTTP pipeline]');
  const { createApp } = await import('../../app.js');
  const app = createApp();
  const { createServer } = await import('node:http');
  const httpServer = createServer(app);
  await mongoose.connect(process.env.MONGODB_URI);
  await new Promise<void>((r) => httpServer.listen(0, r));
  const base = `http://localhost:${(httpServer.address() as net.AddressInfo).port}`;

  const reg = await (await fetch(`${base}/api/auth/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 't@nexus.io', password: 'password123', name: 'T', role: 'admin' }),
  })).json();
  const authH = { authorization: `Bearer ${reg.tokens.accessToken}`, 'content-type': 'application/json' };

  // Register an asset at 127.0.0.1 so detections targeting it get linked.
  const asset = await (await fetch(`${base}/api/assets`, {
    method: 'POST', headers: authH,
    body: JSON.stringify({ name: 'Web', type: 'host', ipAddress: '127.0.0.1', authorizedForScan: true }),
  })).json();

  const sample = await (await fetch(`${base}/api/threats/ingest/sample`, {
    method: 'POST', headers: authH, body: JSON.stringify({ destIp: '127.0.0.1' }),
  })).json();
  assert(sample.threatsDetected >= 4, `sample ingest persisted >=4 threats (got ${sample.threatsDetected})`);
  assert(Object.keys(sample.byCategory).length === 4, 'all four categories present in summary');
  const linked = sample.threats.find((t: any) => t.targetAsset);
  assert(!!linked && linked.targetAsset === asset.asset._id, 'threat linked to matching asset by destIp');

  // Persistence + query
  const listed = await (await fetch(`${base}/api/threats?severity=critical`, { headers: authH })).json();
  assert(Array.isArray(listed.threats), 'GET /api/threats returns list');

  const statsRes = await (await fetch(`${base}/api/threats/stats`, { headers: authH })).json();
  assert(statsRes.total === sample.threatsDetected, 'stats total matches persisted count');
  assert(statsRes.unacknowledged === statsRes.total, 'all threats start unacknowledged');

  // Acknowledge one
  const oneId = sample.threats[0]._id;
  const ackRes = await (await fetch(`${base}/api/threats/${oneId}/acknowledge`, { method: 'PATCH', headers: authH })).json();
  assert(ackRes.threat.acknowledged === true, 'PATCH acknowledge flips flag');

  // Raw combined-log ingest through HTTP
  const rawLog = [
    '203.0.113.5 - - [01/Jan/2026:00:00:01 +0000] "POST /api/auth/login HTTP/1.1" 401 0 "-" "x"',
  ].concat(
    Array.from({ length: 20 }, (_, i) =>
      `203.0.113.5 - - [01/Jan/2026:00:00:${String(2 + i).padStart(2, '0')} +0000] "POST /api/auth/login HTTP/1.1" 401 0 "-" "x"`)
  ).join('\n');
  const rawRes = await (await fetch(`${base}/api/threats/ingest`, {
    method: 'POST', headers: authH, body: JSON.stringify({ format: 'combined', data: rawLog }),
  })).json();
  assert(rawRes.entriesParsed === 21, `raw combined ingest parsed 21 lines (got ${rawRes.entriesParsed})`);
  assert((rawRes.byCategory['brute-force'] ?? 0) >= 1, 'raw combined logs → brute-force detected');

  console.log(`\nALL ${passed} MODULE-3 CHECKS PASSED ✅`);
  await mongoose.disconnect();
  httpServer.close();
  await mem.stop();
  process.exit(0);
}

run().catch((e) => {
  console.error('\nMODULE-3 SMOKE FAILED ❌', e);
  process.exit(1);
});
