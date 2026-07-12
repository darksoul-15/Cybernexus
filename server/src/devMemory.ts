/**
 * Zero-setup dev bootstrap: starts an in-memory MongoDB, then boots the real
 * server against it. Lets you run the whole stack without a MongoDB Atlas URI.
 *   npm run dev:memory   (from /server)
 * NOT for production — data is discarded when the process exits.
 */
import { MongoMemoryServer } from 'mongodb-memory-server';

const mem = await MongoMemoryServer.create();
process.env.MONGODB_URI = mem.getUri();
if (!process.env.JWT_SECRET) process.env.JWT_SECRET = 'dev-only-secret-change-me';
console.log('[dev:memory] in-memory MongoDB ready');

await import('./server.js');
