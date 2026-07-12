/**
 * Module 7 smoke test — Blockchain Evidence Vault. Verifies the SHA-256
 * hash-chain, tamper detection, and chain-of-custody logging.
 *
 * Run from /server:  npx tsx src/modules/evidence/evidence.smoke.ts
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
  process.env.JWT_SECRET = 'evidence-smoke-secret';

  // ── 1. Hash-chain primitives (pure) ────────────────────────────────────
  console.log('\n[Hash primitives]');
  const { canonicalize, computeContentHash, GENESIS_PREV_HASH } = await import('./hashChain.service.js');
  assert(canonicalize({ a: 1, b: 2 }) === canonicalize({ b: 2, a: 1 }), 'canonicalize is key-order independent');
  assert(canonicalize({ a: [1, { y: 2, x: 1 }] }).includes('"x":1,"y":2'), 'nested keys sorted deterministically');
  const h = computeContentHash({ foo: 'bar' });
  assert(/^[0-9a-f]{64}$/.test(h), 'content hash is 64-hex SHA-256');
  assert(computeContentHash({ foo: 'bar' }) === h, 'content hash is stable for same payload');
  assert(computeContentHash({ foo: 'baz' }) !== h, 'content hash changes with payload');
  assert(GENESIS_PREV_HASH === '0'.repeat(64), 'genesis previousHash is 64 zeros');

  // ── 2. Append + chain linkage ──────────────────────────────────────────
  console.log('\n[Chain build]');
  await mongoose.connect(process.env.MONGODB_URI);
  const { addEvidence, verify } = await import('./evidence.service.js');
  const { EvidenceRecordModel } = await import('../../models/EvidenceRecord.js');
  const uid = new mongoose.Types.ObjectId().toString();

  const r0 = await addEvidence({ type: 'note', payload: { msg: 'genesis evidence' }, userId: uid });
  const r1 = await addEvidence({ type: 'scan', payload: { ports: [22, 80], host: '127.0.0.1' }, userId: uid });
  const r2 = await addEvidence({ type: 'threat', payload: { ip: '203.0.113.5', category: 'brute-force' }, userId: uid });

  assert(r0.index === 0 && r1.index === 1 && r2.index === 2, 'indices increment from genesis');
  assert(r0.previousHash === GENESIS_PREV_HASH, 'genesis links to zero-hash');
  assert(r1.previousHash === r0.hash, 'record 1 links to record 0 hash');
  assert(r2.previousHash === r1.hash, 'record 2 links to record 1 hash');

  let v = await verify();
  assert(v.valid && v.length === 3, 'fresh chain verifies as valid (length 3)');
  assert(v.headHash === r2.hash, 'head hash is the latest record hash');

  // ── 3. Tamper detection ────────────────────────────────────────────────
  console.log('\n[Tamper detection]');
  // Mutate a stored payload directly, bypassing the service (an attacker edit).
  await EvidenceRecordModel.updateOne({ index: 1 }, { $set: { 'payload.host': '10.0.0.99' } });
  v = await verify();
  assert(!v.valid, 'tampered chain fails verification');
  assert(v.issues.some((i) => i.index === 1 && /tamper|content hash/i.test(i.problem)), 'tamper pinpointed at index 1');

  // Restore, confirm valid again.
  await EvidenceRecordModel.updateOne({ index: 1 }, { $set: { 'payload.host': '127.0.0.1' } });
  v = await verify();
  assert(v.valid, 'restoring original payload makes the chain valid again');

  // Mutate a stored hash → record-hash mismatch + broken link for the next record.
  await EvidenceRecordModel.updateOne({ index: 1 }, { $set: { hash: 'deadbeef'.repeat(8) } });
  v = await verify();
  assert(!v.valid && v.issues.length >= 2, 'forging a hash breaks that record AND the next link');
  await EvidenceRecordModel.updateOne({ index: 1 }, { $set: { hash: r1.hash } });
  assert((await verify()).valid, 'chain valid again after restore');

  // ── 4. Chain of custody ────────────────────────────────────────────────
  console.log('\n[Custody]');
  const { getEvidence, exportEvidence } = await import('./evidence.service.js');
  await getEvidence(r0._id.toString(), uid);
  const exported = await exportEvidence(r0._id.toString(), uid);
  const actions = (exported.custody as Array<{ action: string }>).map((c) => c.action);
  assert(actions[0] === 'created', 'custody starts with created');
  assert(actions.includes('accessed') && actions.includes('exported'), 'access + export appended to custody');

  // ── 5. HTTP flow ───────────────────────────────────────────────────────
  console.log('\n[HTTP]');
  const { createApp } = await import('../../app.js');
  const { createServer } = await import('node:http');
  const httpServer = createServer(createApp());
  await new Promise<void>((r) => httpServer.listen(0, r));
  const base = `http://localhost:${(httpServer.address() as net.AddressInfo).port}`;
  const reg = await (await fetch(`${base}/api/auth/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'ev@nexus.io', password: 'password123', name: 'Ev', role: 'admin' }),
  })).json();
  const authH = { authorization: `Bearer ${reg.tokens.accessToken}`, 'content-type': 'application/json' };

  assert((await fetch(`${base}/api/evidence`)).status === 401, 'evidence requires auth');

  const added = await (await fetch(`${base}/api/evidence`, {
    method: 'POST', headers: authH, body: JSON.stringify({ type: 'note', payload: { case: 'demo', n: 1 } }),
  })).json();
  assert(/^[0-9a-f]{64}$/.test(added.evidence.hash), 'POST evidence returns a hashed record');

  const listed = await (await fetch(`${base}/api/evidence`, { headers: authH })).json();
  assert(Array.isArray(listed.evidence) && listed.evidence[0].payload === undefined, 'list omits payloads (metadata only)');

  const verifyRes = await (await fetch(`${base}/api/evidence/verify`, { headers: authH })).json();
  assert(verifyRes.valid === true && verifyRes.length >= 4, 'GET /verify reports a valid chain');

  const exportRes = await (await fetch(`${base}/api/evidence/${added.evidence._id}/export`, { headers: authH })).json();
  assert(exportRes.evidence.custody.some((c: { action: string }) => c.action === 'exported'), 'export logs custody over HTTP');

  console.log(`\nALL ${passed} MODULE-7 CHECKS PASSED ✅`);
  await mongoose.disconnect();
  httpServer.close();
  await mem.stop();
  process.exit(0);
}

run().catch((e) => {
  console.error('\nMODULE-7 SMOKE FAILED ❌', e);
  process.exit(1);
});
