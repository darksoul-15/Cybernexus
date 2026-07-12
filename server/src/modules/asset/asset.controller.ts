import type { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import * as assetService from './asset.service.js';
import { HttpError } from '../../middleware/error.js';

const createSchema = z.object({
  name: z.string().min(1),
  type: z.enum(['host', 'service', 'container', 'web-app']),
  ipAddress: z.string().min(1),
  hostname: z.string().optional(),
  tags: z.array(z.string()).optional(),
  authorizedForScan: z.boolean().optional(),
});

export async function create(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const parsed = createSchema.safeParse(req.body);
    if (!parsed.success) throw new HttpError(400, 'Validation failed', parsed.error.flatten());
    const asset = await assetService.createAsset(req.user!.sub, parsed.data);
    res.status(201).json({ asset });
  } catch (e) {
    next(e);
  }
}

export async function list(_req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    res.json({ assets: await assetService.listAssets() });
  } catch (e) {
    next(e);
  }
}

export async function getOne(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    res.json({ asset: await assetService.getAsset(req.params.id) });
  } catch (e) {
    next(e);
  }
}

export async function remove(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    await assetService.deleteAsset(req.params.id);
    res.status(204).end();
  } catch (e) {
    next(e);
  }
}
