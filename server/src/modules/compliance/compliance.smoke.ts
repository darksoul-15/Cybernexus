/**
 * Module 8 smoke test — Compliance Module. Seeds a real audit trail + incidents
 * + evidence, then verifies report aggregation, the PDF generator (real bytes),
 * and admin-only access.
 *
 * Run from /server:  npx tsx src/modules/compliance/compliance.smoke.ts
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
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function run(): Promise<void> {
  const mem = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mem.getUri();
  process.env.JWT_SECRET = 'compliance-smoke-secret';

  const { createApp } = await import('../../app.js');
  const { createServer } = await import('node:http');
  const httpServer = createServer(createApp());
  await mongoose.connect(process.env.MONGODB_URI);
  await new Promise<void>((r) => httpServer.listen(0, r));
  const base = `http://localhost:${(httpServer.address() as net.AddressInfo).port}`;

  const reg = await (await fetch(`${base}/api/auth/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'co@nexus.io', password: 'password123', name: 'CO', role: 'admin' }),
  })).json();
  const authH = { authorization: `Bearer ${reg.tokens.accessToken}`, 'content-type': 'application/json' };

  // Seed auditable activity across modules.
  await fetch(`${base}/api/evidence`, { method: 'POST', headers: authH, body: JSON.stringify({ type: 'note', payload: { case: 'demo' } }) });
  await fetch(`${base}/api/threats/ingest/sample`, { method: 'POST', headers: authH, body: '{}' });
  await fetch(`${base}/api/incidents/auto-respond`, { method: 'POST', headers: authH, body: '{}' });

  // Audit writes are fire-and-forget on response 'finish'; wait for them to land.
  const { AuditLogModel } = await import('../../models/AuditLog.js');
  for (let i = 0; i < 40 && (await AuditLogModel.countDocuments({})) < 4; i++) await wait(50);

  // ── 1. Report aggregation ──────────────────────────────────────────────
  console.log('\n[Report aggregation]');
  const { buildReport } = await import('./compliance.service.js');
  const report = await buildReport({ generatedBy: { id: reg.user._id, email: reg.user.email } });
  assert(report.audit.total >= 4, `audit trail has the seeded actions (got ${report.audit.total})`);
  assert(report.audit.uniqueActors >= 1, 'at least one distinct actor recorded');
  assert(report.audit.byAction.some((b) => b.key === 'evidence.add'), 'evidence.add action captured in audit trail');
  assert(report.incidents.total >= 1, 'incidents reflected in report');
  assert(report.evidence.chainValid === true && report.evidence.length >= 1, 'evidence chain attested valid');
  assert(report.generatedBy?.email === 'co@nexus.io', 'report attributes the generating admin');

  // ── 2. PDF generation (real bytes) ─────────────────────────────────────
  console.log('\n[PDF generation]');
  const { generateReportPdf } = await import('./pdf.service.js');
  const pdf = await generateReportPdf(report);
  assert(Buffer.isBuffer(pdf) && pdf.length > 1000, `PDF buffer produced (${pdf.length} bytes)`);
  assert(pdf.subarray(0, 5).toString('latin1') === '%PDF-', 'buffer has a valid %PDF- header');
  assert(pdf.subarray(-6).toString('latin1').includes('EOF'), 'PDF ends with EOF marker');

  // ── 3. HTTP endpoints + RBAC ───────────────────────────────────────────
  console.log('\n[HTTP + RBAC]');
  const jsonRes = await (await fetch(`${base}/api/compliance/report`, { headers: authH })).json();
  assert(typeof jsonRes.audit.total === 'number', 'GET /api/compliance/report returns JSON report');

  const pdfRes = await fetch(`${base}/api/compliance/report.pdf`, { headers: authH });
  assert(pdfRes.headers.get('content-type') === 'application/pdf', 'report.pdf served as application/pdf');
  const pdfBytes = Buffer.from(await pdfRes.arrayBuffer());
  assert(pdfBytes.subarray(0, 5).toString('latin1') === '%PDF-', 'streamed PDF has a valid header');

  const auditList = await (await fetch(`${base}/api/compliance/audit?action=evidence.add`, { headers: authH })).json();
  assert(auditList.items.length >= 1 && auditList.items.every((i: { action: string }) => i.action === 'evidence.add'), 'audit list filters by action');

  // Analyst is forbidden from compliance data.
  const an = await (await fetch(`${base}/api/auth/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'analyst2@nexus.io', password: 'password123', name: 'A2' }),
  })).json();
  const anRes = await fetch(`${base}/api/compliance/report`, { headers: { authorization: `Bearer ${an.tokens.accessToken}` } });
  assert(anRes.status === 403, 'analyst is forbidden from compliance (admin-only)');
  assert((await fetch(`${base}/api/compliance/report`)).status === 401, 'compliance requires auth');

  console.log(`\nALL ${passed} MODULE-8 CHECKS PASSED ✅`);
  await mongoose.disconnect();
  httpServer.close();
  await mem.stop();
  process.exit(0);
}

run().catch((e) => {
  console.error('\nMODULE-8 SMOKE FAILED ❌', e);
  process.exit(1);
});
