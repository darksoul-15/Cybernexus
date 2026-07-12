/**
 * Realtime event bus. Holds the Socket.io server instance and exposes typed
 * emit helpers so any module can push live updates to connected dashboards
 * without importing socket.io directly. Set once at server startup.
 */
import type { Server } from 'socket.io';
import { SOCKET_EVENTS, type ScanCompletedPayload } from '@cybernexus/shared';
import type { ThreatEventDoc } from '../models/ThreatEvent.js';

let io: Server | null = null;

export function setIo(server: Server): void {
  io = server;
}

function emit(event: string, payload: unknown): void {
  io?.emit(event, payload);
  // Any live event also nudges dashboards to refresh their aggregate summary.
  io?.emit(SOCKET_EVENTS.dashboardUpdate, { at: new Date().toISOString(), event });
}

export function emitThreats(threats: ThreatEventDoc[] | unknown[]): void {
  if (!threats.length) return;
  emit(SOCKET_EVENTS.threatNew, { threats });
}

export function emitScanCompleted(payload: ScanCompletedPayload): void {
  emit(SOCKET_EVENTS.scanCompleted, payload);
}

export function emitIncident(incident: unknown): void {
  emit(SOCKET_EVENTS.incidentNew, incident);
}
