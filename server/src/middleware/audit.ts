import type { Request, Response, NextFunction } from 'express';
import { AuditLogModel } from '../models/AuditLog.js';

/**
 * Audit-log middleware. Records sensitive actions to the AuditLog collection
 * after the response finishes. Used by the Compliance module (Module 8) and
 * mounted on sensitive routes as they are built.
 *
 * @param action stable action key, e.g. "auth.login" or "asset.scan.start"
 */
export function audit(action: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    res.on('finish', () => {
      void AuditLogModel.create({
        actor: req.user?.sub,
        actorEmail: req.user?.email,
        action,
        method: req.method,
        path: req.originalUrl,
        statusCode: res.statusCode,
        ip: req.ip ?? req.socket.remoteAddress ?? '',
      }).catch((e) => console.error('[audit] failed to persist', e));
    });
    next();
  };
}
