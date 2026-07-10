import { createServer } from 'node:http';
import { Server as SocketServer } from 'socket.io';
import { createApp } from './app.js';
import { connectDB } from './config/db.js';
import { env } from './config/env.js';

async function main(): Promise<void> {
  await connectDB();

  const app = createApp();
  const httpServer = createServer(app);

  // Socket.io is bootstrapped here now; live channels are wired in Module 5.
  const io = new SocketServer(httpServer, {
    cors: { origin: env.clientOrigin, credentials: true },
  });
  io.on('connection', (socket) => {
    console.log('[socket] client connected', socket.id);
    socket.on('disconnect', () => console.log('[socket] disconnected', socket.id));
  });

  httpServer.listen(env.port, () => {
    console.log(`[server] CYBERNEXUS X listening on http://localhost:${env.port}`);
  });
}

main().catch((err) => {
  console.error('[fatal] failed to start server', err);
  process.exit(1);
});
