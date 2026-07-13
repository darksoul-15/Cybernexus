import { io, type Socket } from 'socket.io-client';
import { tokenStore, API_BASE } from './api';

let socket: Socket | null = null;

/** Lazily create the authenticated socket connection (JWT in the handshake). */
export function getSocket(): Socket {
  if (!socket) {
    // In dev, connect same-origin (Vite proxies WS). In prod, connect to the
    // deployed backend origin (VITE_API_URL).
    socket = io(API_BASE || '/', {
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
