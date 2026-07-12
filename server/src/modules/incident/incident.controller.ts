import type { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import * as svc from './response.service.js';
import { env } from '../../config/env.js';
import { HttpError } from '../../middleware/error.js';
import { isIpv4 } from '../intel/indicator.util.js';

const autoRespondSchema = z.object({
  minScore: z.number().int().min(0).max(100).optional(),
  autoBlock: z.boolean().optional(),
});

export async function autoRespond(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const parsed = autoRespondSchema.safeParse(req.body ?? {});
    if (!parsed.success) throw new HttpError(400, 'Validation failed', parsed.error.flatten());
    const result = await svc.autoRespond({
      userId: req.user!.sub,
      minScore: parsed.data.minScore ?? env.autoIncidentMinScore,
      autoBlock: parsed.data.autoBlock ?? false,
    });
    res.status(201).json(result);
  } catch (e) {
    next(e);
  }
}

export async function list(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const status = typeof req.query.status === 'string' ? req.query.status : undefined;
    res.json({ incidents: await svc.listIncidents(status) });
  } catch (e) {
    next(e);
  }
}

export async function getOne(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    res.json({ incident: await svc.getIncident(req.params.id) });
  } catch (e) {
    next(e);
  }
}

const patchSchema = z.object({
  status: z.enum(['new', 'investigating', 'contained', 'resolved', 'closed']).optional(),
  assignee: z.string().optional(),
});

export async function update(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const parsed = patchSchema.safeParse(req.body ?? {});
    if (!parsed.success) throw new HttpError(400, 'Validation failed', parsed.error.flatten());
    res.json({ incident: await svc.updateIncident(req.params.id, parsed.data, req.user!.sub) });
  } catch (e) {
    next(e);
  }
}

const blockSchema = z.object({ ip: z.string(), reason: z.string().optional(), incidentId: z.string().optional() });

export async function block(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const parsed = blockSchema.safeParse(req.body ?? {});
    if (!parsed.success) throw new HttpError(400, 'Validation failed', parsed.error.flatten());
    if (!isIpv4(parsed.data.ip)) throw new HttpError(400, 'ip must be a valid IPv4 address');
    const result = await svc.blockIp({
      ip: parsed.data.ip,
      reason: parsed.data.reason ?? 'manual block',
      incidentId: parsed.data.incidentId,
      userId: req.user!.sub,
    });
    res.status(201).json({ block: result });
  } catch (e) {
    next(e);
  }
}

export async function blocklist(_req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    res.json({ blocklist: await svc.listBlocklist(), liveMode: env.responseLiveMode, realFirewall: env.responseAllowRealFirewall });
  } catch (e) {
    next(e);
  }
}
