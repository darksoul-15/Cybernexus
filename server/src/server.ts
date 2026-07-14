import { createServer } from 'node:http';
import jwt from 'jsonwebtoken';
import { Server as SocketServer } from 'socket.io';
import { createApp } from './app.js';
import { connectDB } from './config/db.js';
import { env } from './config/env.js';
import { setIo } from './realtime/bus.js';

async function main(): Promise<void> {
  await connectDB();

  const app = createApp();
  const httpServer = createServer(app);

  // Socket.io: live dashboard channel. A valid JWT is required to connect.
  const io = new SocketServer(httpServer, {
    cors: { origin: env.serveClient ? true : env.clientOrigin, credentials: true },
  });
  io.use((socket, next) => {
    const token = socket.handshake.auth?.token as string | undefined;
    if (!token) return next(new Error('Authentication required'));
    try {
      jwt.verify(token, env.jwtSecret);
      next();
    } catch {
      next(new Error('Invalid token'));
    }
  });
  io.on('connection', (socket) => {
    console.log('[socket] client connected', socket.id);
    socket.on('disconnect', () => console.log('[socket] disconnected', socket.id));
  });
  setIo(io);

  httpServer.listen(env.port, () => {
    console.log(`[server] CYBERNEXUS X listening on http://localhost:${env.port}`);
  });
}

main().catch((err) => {
  console.error('[fatal] failed to start server', err);
  process.exit(1);
});
