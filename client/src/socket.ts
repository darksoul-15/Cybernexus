import { io, type Socket } from 'socket.io-client';
import { tokenStore } from './api';

let socket: Socket | null = null;

/** Lazily create the authenticated socket connection (JWT in the handshake). */
export function getSocket(): Socket {
  if (!socket) {
    socket = io('/', {
      auth: { token: tokenStore.get() },
      autoConnect: true,
    });
  }
  return socket;
}

export function disconnectSocket(): void {
  socket?.disconnect();
  socket = null;
}
