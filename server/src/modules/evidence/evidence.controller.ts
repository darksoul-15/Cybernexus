import type { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import * as svc from './evidence.service.js';
import { HttpError } from '../../middleware/error.js';

const addSchema = z.object({
  type: z.enum(['log', 'scan', 'threat', 'file', 'note']),
  payload: z.record(z.unknown()),
  incidentId: z.string().optional(),
});

export async function add(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const parsed = addSchema.safeParse(req.body);
    if (!parsed.success) throw new HttpError(400, 'Validation failed', parsed.error.flatten());
    const doc = await svc.addEvidence({ ...parsed.data, userId: req.user!.sub });
    res.status(201).json({ evidence: doc.toJSON() });
  } catch (e) {
    next(e);
  }
}

export async function list(_req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    res.json({ evidence: await svc.listEvidence() });
  } catch (e) {
    next(e);
  }
}

export async function verify(_req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    res.json(await svc.verify());
  } catch (e) {
    next(e);
  }
}

export async function getOne(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    res.json({ evidence: await svc.getEvidence(req.params.id, req.user!.sub) });
  } catch (e) {
    next(e);
  }
}

export async function exportOne(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    res.json({ evidence: await svc.exportEvidence(req.params.id, req.user!.sub) });
  } catch (e) {
    next(e);
  }
}
