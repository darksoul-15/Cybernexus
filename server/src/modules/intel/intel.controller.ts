import type { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import * as intelService from './intel.service.js';
import { HttpError } from '../../middleware/error.js';

export async function lookup(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const indicator = req.params.indicator;
    if (!indicator) throw new HttpError(400, 'Missing indicator');
    const force = req.query.force === 'true';
    res.json({ reputation: await intelService.lookupIndicator(indicator, { force }) });
  } catch (e) {
    next(e);
  }
}

const enrichSchema = z.object({ limit: z.number().int().positive().max(100).optional() });

export async function enrich(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const parsed = enrichSchema.safeParse(req.body ?? {});
    if (!parsed.success) throw new HttpError(400, 'Validation failed', parsed.error.flatten());
    res.json(await intelService.enrichThreatSources(parsed.data.limit));
  } catch (e) {
    next(e);
  }
}
