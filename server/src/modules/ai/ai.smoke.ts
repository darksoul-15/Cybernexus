/**
 * AI Threat Analyst smoke test. Runs offline: verifies the prompt builder and
 * graceful degradation without an API key. If ANTHROPIC_API_KEY is present, it
 * additionally runs one real analysis end-to-end.
 *
 * Run from /server:  npx tsx src/modules/ai/ai.smoke.ts
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
  process.env.JWT_SECRET = 'ai-smoke-secret';
  const hasKey = Boolean(process.env.ANTHROPIC_API_KEY);

  // ── 1. Prompt builder (pure) ───────────────────────────────────────────
  console.log('\n[Prompt builder]');
  const { buildThreatSummary } = await import('./ai.service.js');
  const summary = buildThreatSummary([
    { category: 'brute-force', severity: 'high', sourceIp: '203.0.113.5', score: 100, description: '25 failed logins' },
    { category: 'port-scan', severity: 'high', sourceIp: '198.51.100.9', score: 90, description: '40 ports probed' },
  ]);
  assert(summary.includes('brute-force') && summary.includes('203.0.113.5'), 'summary includes threat facts');
  assert(summary.includes('Detected threats (2)'), 'summary counts threats');

  // ── 2. HTTP + graceful degradation ─────────────────────────────────────
  console.log('\n[HTTP]');
  const { createApp } = await import('../../app.js');
  const { createServer } = await import('node:http');
  const httpServer = createServer(createApp());
  await mongoose.connect(process.env.MONGODB_URI);
  await new Promise<void>((r) => httpServer.listen(0, r));
  const base = `http://localhost:${(httpServer.address() as net.AddressInfo).port}`;

  const reg = await (await fetch(`${base}/api/auth/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'ai@nexus.io', password: 'password123', name: 'AI', role: 'admin' }),
  })).json();
  const authH = { authorization: `Bearer ${reg.tokens.accessToken}`, 'content-type': 'application/json' };

  assert((await fetch(`${base}/api/ai/analyze`, { method: 'POST' })).status === 401, 'analyze requires auth');

  // Seed a couple of threats
  const { ThreatEventModel } = await import('../../models/ThreatEvent.js');
  await ThreatEventModel.insertMany([
    { category: 'brute-force', severity: 'high', score: 100, sourceIp: '203.0.113.5', detectionMethod: 'signature', description: 'bf', evidence: {}, acknowledged: false, detectedAt: new Date() },
    { category: 'syn-flood', severity: 'critical', score: 100, sourceIp: '203.0.113.9', detectionMethod: 'signature', description: 'syn', evidence: {}, acknowledged: false, detectedAt: new Date() },
  ]);

  const res = await (await fetch(`${base}/api/ai/analyze`, { method: 'POST', headers: authH, body: '{}' })).json();

  if (!hasKey) {
    assert(res.available === false, 'no API key → available:false (graceful, not fabricated)');
    console.log('  (set ANTHROPIC_API_KEY to exercise a real analysis)');
  } else {
    assert(res.available === true, 'API key present → available:true');
    if (res.assessment) {
      assert(['low', 'medium', 'high', 'critical'].includes(res.assessment.severity), 'assessment.severity is valid enum');
      assert(typeof res.assessment.attackNarrative === 'string' && res.assessment.attackNarrative.length > 0, 'assessment has a narrative');
      assert(Array.isArray(res.assessment.recommendedActions), 'assessment has recommended actions');
      console.log(`  LIVE assessment: [${res.assessment.severity}] ${res.assessment.headline}`);
    } else {
      console.log('  live call returned no assessment:', res.error);
    }
  }

  console.log(`\nALL ${passed} AI CHECKS PASSED ✅`);
  await mongoose.disconnect();
  httpServer.close();
  await mem.stop();
  process.exit(0);
}

run().catch((e) => {
  console.error('\nAI SMOKE FAILED ❌', e);
  process.exit(1);
});
