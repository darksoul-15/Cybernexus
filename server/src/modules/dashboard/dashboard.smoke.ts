/**
 * Module 5 (server) smoke test — dashboard aggregation reflects real DB records.
 * Run from /server:  npx tsx src/modules/dashboard/dashboard.smoke.ts
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
  process.env.JWT_SECRET = 'dash-smoke-secret';

  const { createApp } = await import('../../app.js');
  const { createServer } = await import('node:http');
  const httpServer = createServer(createApp());
  await mongoose.connect(process.env.MONGODB_URI);
  await new Promise<void>((r) => httpServer.listen(0, r));
  const base = `http://localhost:${(httpServer.address() as net.AddressInfo).port}`;

  const reg = await (await fetch(`${base}/api/auth/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'd@nexus.io', password: 'password123', name: 'D', role: 'admin' }),
  })).json();
  const authH = { authorization: `Bearer ${reg.tokens.accessToken}`, 'content-type': 'application/json' };

  // Requires auth
  assert((await fetch(`${base}/api/dashboard/summary`)).status === 401, 'dashboard requires auth');

  // Empty state
  let sum = await (await fetch(`${base}/api/dashboard/summary`, { headers: authH })).json();
  assert(sum.threats.total === 0 && sum.assets.total === 0, 'empty dashboard has zeroed counts');

  // Seed real data: an asset + detected threats
  const asset = await (await fetch(`${base}/api/assets`, {
    method: 'POST', headers: authH,
    body: JSON.stringify({ name: 'Web', type: 'host', ipAddress: '127.0.0.1', authorizedForScan: true }),
  })).json();
  const sample = await (await fetch(`${base}/api/threats/ingest/sample`, {
    method: 'POST', headers: authH, body: JSON.stringify({ destIp: '127.0.0.1' }),
  })).json();

  sum = await (await fetch(`${base}/api/dashboard/summary`, { headers: authH })).json();
  assert(sum.assets.total === 1, 'asset counted');
  assert(sum.assets.heatmap.length === 1 && sum.assets.heatmap[0].band !== undefined, 'heatmap has asset + risk band');
  assert(sum.threats.total === sample.threatsDetected, 'threat total matches detections');
  assert(sum.threats.byCategory.length >= 4, 'threats grouped by category');
  assert(sum.threats.bySeverity.reduce((a: number, b: any) => a + b.count, 0) === sum.threats.total, 'severity buckets sum to total');
  assert(sum.threats.recent.length > 0 && sum.threats.recent.length <= 10, 'recent threats capped at 10');
  assert(typeof sum.generatedAt === 'string', 'summary carries generatedAt');

  console.log(`\nALL ${passed} MODULE-5 (server) CHECKS PASSED ✅`);
  await mongoose.disconnect();
  httpServer.close();
  await mem.stop();
  process.exit(0);
}

run().catch((e) => {
  console.error('\nMODULE-5 SERVER SMOKE FAILED ❌', e);
  process.exit(1);
});
