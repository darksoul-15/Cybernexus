/**
 * Module 6 smoke test — Automated Incident Response. Runs offline (no SMTP, no
 * real firewall). Verifies threat→incident correlation, gated/simulated blocking,
 * the live-mode dry-run guard, and the full HTTP flow.
 *
 * Run from /server:  npx tsx src/modules/incident/incident.smoke.ts
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
  process.env.JWT_SECRET = 'incident-smoke-secret';

  // ── 1. Firewall / containment (safe by default) ────────────────────────
  console.log('\n[Containment gating]');
  const { buildFirewallCommand, applyBlock } = await import('./firewall.service.js');
  const cmd = buildFirewallCommand('1.2.3.4');
  assert(cmd.includes('1.2.3.4'), 'firewall command targets the IP');
  assert(/netsh|iptables/.test(cmd), 'firewall command is platform-appropriate');

  const sim = await applyBlock('1.2.3.4');
  assert(sim.mode === 'simulated' && sim.enforced === false, 'default block is simulated, not enforced');

  // Toggle live mode (but NOT real-firewall) → dry-run, still not enforced.
  const { env } = await import('../../config/env.js');
  (env as { responseLiveMode: boolean }).responseLiveMode = true;
  const live = await applyBlock('1.2.3.4');
  assert(live.mode === 'live' && live.enforced === false, 'live mode records intent but does NOT enforce without real-firewall opt-in');
  assert(/RESPONSE_ALLOW_REAL_FIREWALL/.test(live.message), 'live dry-run explains how to enable real enforcement');
  (env as { responseLiveMode: boolean }).responseLiveMode = false; // reset

  // ── 2. HTTP flow ───────────────────────────────────────────────────────
  console.log('\n[Auto-respond + correlation]');
  const { createApp } = await import('../../app.js');
  const { createServer } = await import('node:http');
  const httpServer = createServer(createApp());
  await mongoose.connect(process.env.MONGODB_URI);
  await new Promise<void>((r) => httpServer.listen(0, r));
  const base = `http://localhost:${(httpServer.address() as net.AddressInfo).port}`;

  const reg = await (await fetch(`${base}/api/auth/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'ir@nexus.io', password: 'password123', name: 'IR', role: 'admin' }),
  })).json();
  const authH = { authorization: `Bearer ${reg.tokens.accessToken}`, 'content-type': 'application/json' };

  // Seed threats directly for deterministic correlation.
  const { ThreatEventModel } = await import('../../models/ThreatEvent.js');
  await ThreatEventModel.insertMany([
    { category: 'brute-force', severity: 'high', score: 100, sourceIp: '203.0.113.5', detectionMethod: 'signature', description: 'bf1', evidence: {}, acknowledged: false, detectedAt: new Date() },
    { category: 'port-scan', severity: 'high', score: 100, sourceIp: '203.0.113.5', detectionMethod: 'statistical', description: 'ps1', evidence: {}, acknowledged: false, detectedAt: new Date() },
    { category: 'syn-flood', severity: 'critical', score: 100, sourceIp: '203.0.113.9', detectionMethod: 'signature', description: 'syn1', evidence: {}, acknowledged: false, detectedAt: new Date() },
    { category: 'anomaly-rate', severity: 'low', score: 40, sourceIp: '10.0.0.2', detectionMethod: 'statistical', description: 'low-rate', evidence: {}, acknowledged: false, detectedAt: new Date() },
  ]);

  const resp = await (await fetch(`${base}/api/incidents/auto-respond`, {
    method: 'POST', headers: authH, body: JSON.stringify({ autoBlock: true }),
  })).json();
  assert(resp.qualifyingThreats === 3, `3 threats qualify (high/critical or score>=70); low-rate excluded (got ${resp.qualifyingThreats})`);
  assert(resp.incidentsCreated === 2, `2 incidents (correlated by source IP; got ${resp.incidentsCreated})`);
  const correlated = resp.incidents.find((i: any) => i.title.includes('203.0.113.5'));
  assert(correlated && correlated.relatedThreats.length === 2, 'two threats from one IP fold into one incident');
  assert(resp.alertsSent === 2, 'an in-app alert fired per incident');
  assert(resp.blocks.length === 2 && resp.blocks.every((b: any) => b.mode === 'simulated' && !b.enforced), 'source IPs blocked in simulated mode (not enforced)');

  // Idempotency: threats are now linked, so a second run creates nothing.
  const resp2 = await (await fetch(`${base}/api/incidents/auto-respond`, { method: 'POST', headers: authH, body: '{}' })).json();
  assert(resp2.incidentsCreated === 0, 're-running auto-respond creates no duplicate incidents');

  // ── 3. Incident management ─────────────────────────────────────────────
  console.log('\n[Incident management]');
  const list = await (await fetch(`${base}/api/incidents`, { headers: authH })).json();
  assert(list.incidents.length === 2, 'GET /api/incidents lists both');
  const incId = list.incidents[0]._id;

  const patched = await (await fetch(`${base}/api/incidents/${incId}`, {
    method: 'PATCH', headers: authH, body: JSON.stringify({ status: 'resolved' }),
  })).json();
  assert(patched.incident.status === 'resolved' && !!patched.incident.resolvedAt, 'status update sets resolvedAt + logs action');

  // ── 4. Blocklist + manual block ────────────────────────────────────────
  console.log('\n[Blocklist]');
  const bl = await (await fetch(`${base}/api/incidents/blocklist`, { headers: authH })).json();
  assert(bl.blocklist.length === 2 && bl.liveMode === false, 'blocklist has 2 active entries, live mode off');

  const manual = await (await fetch(`${base}/api/incidents/block`, {
    method: 'POST', headers: authH, body: JSON.stringify({ ip: '203.0.113.200', reason: 'manual' }),
  })).json();
  assert(manual.block.mode === 'simulated', 'manual block is simulated by default');
  const badIp = await fetch(`${base}/api/incidents/block`, { method: 'POST', headers: authH, body: JSON.stringify({ ip: 'nope' }) });
  assert(badIp.status === 400, 'invalid IP rejected');

  // Analyst cannot block (admin-only)
  const analystReg = await (await fetch(`${base}/api/auth/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'an@nexus.io', password: 'password123', name: 'An' }),
  })).json();
  const anBlock = await fetch(`${base}/api/incidents/block`, {
    method: 'POST', headers: { authorization: `Bearer ${analystReg.tokens.accessToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({ ip: '203.0.113.201' }),
  });
  assert(anBlock.status === 403, 'analyst is forbidden from blocking (admin-only)');

  // ── 5. Dashboard reflects incidents ────────────────────────────────────
  const dash = await (await fetch(`${base}/api/dashboard/summary`, { headers: authH })).json();
  assert(dash.incidents.total === 2, 'dashboard incident total reflects real records');

  console.log(`\nALL ${passed} MODULE-6 CHECKS PASSED ✅`);
  await mongoose.disconnect();
  httpServer.close();
  await mem.stop();
  process.exit(0);
}

run().catch((e) => {
  console.error('\nMODULE-6 SMOKE FAILED ❌', e);
  process.exit(1);
});
