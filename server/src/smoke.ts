/**
 * Foundation smoke test — boots the Express app against an in-memory MongoDB
 * and exercises the auth vertical slice end-to-end. Not part of the app; run
 * with `npx tsx src/smoke.ts` from /server. Proves register → login → /me works.
 */
import { MongoMemoryServer } from 'mongodb-memory-server';
import mongoose from 'mongoose';

async function run(): Promise<void> {
  const mem = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mem.getUri();
  process.env.JWT_SECRET = 'smoke-test-secret';

  const { createApp } = await import('./app.js');
  const app = createApp();
  const { createServer } = await import('node:http');
  const server = createServer(app);
  await mongoose.connect(process.env.MONGODB_URI);
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as { port: number }).port;
  const base = `http://localhost:${port}`;

  const assert = (cond: boolean, msg: string) => {
    if (!cond) throw new Error('ASSERT FAILED: ' + msg);
    console.log('  ok -', msg);
  };

  // health
  let r = await fetch(`${base}/api/health`);
  assert(r.status === 200, 'health returns 200');

  // register
  r = await fetch(`${base}/api/auth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'analyst@nexus.io', password: 'password123', name: 'Ana Lyst' }),
  });
  let body = await r.json();
  assert(r.status === 201, 'register returns 201');
  assert(body.user.role === 'analyst', 'default role is analyst');
  assert(body.user.passwordHash === undefined, 'passwordHash not leaked');
  assert(typeof body.tokens.accessToken === 'string', 'access token issued');

  // duplicate email rejected
  r = await fetch(`${base}/api/auth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'analyst@nexus.io', password: 'password123', name: 'Dupe' }),
  });
  assert(r.status === 409, 'duplicate email returns 409');

  // weak password rejected
  r = await fetch(`${base}/api/auth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'x@nexus.io', password: 'short', name: 'X' }),
  });
  assert(r.status === 400, 'weak password returns 400');

  // login
  r = await fetch(`${base}/api/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'analyst@nexus.io', password: 'password123' }),
  });
  body = await r.json();
  assert(r.status === 200, 'login returns 200');
  const token = body.tokens.accessToken;

  // wrong password
  r = await fetch(`${base}/api/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'analyst@nexus.io', password: 'wrong' }),
  });
  assert(r.status === 401, 'wrong password returns 401');

  // /me without token
  r = await fetch(`${base}/api/auth/me`);
  assert(r.status === 401, '/me without token returns 401');

  // /me with token
  r = await fetch(`${base}/api/auth/me`, { headers: { authorization: `Bearer ${token}` } });
  body = await r.json();
  assert(r.status === 200, '/me with token returns 200');
  assert(body.user.email === 'analyst@nexus.io', '/me returns correct user');

  // admin registration + role guard payload
  r = await fetch(`${base}/api/auth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'admin@nexus.io', password: 'password123', name: 'Ad Min', role: 'admin' }),
  });
  body = await r.json();
  assert(body.user.role === 'admin', 'admin role assignable at register');

  console.log('\nALL SMOKE CHECKS PASSED ✅');
  await mongoose.disconnect();
  server.close();
  await mem.stop();
  process.exit(0);
}

run().catch((e) => {
  console.error('SMOKE FAILED ❌', e);
  process.exit(1);
});
