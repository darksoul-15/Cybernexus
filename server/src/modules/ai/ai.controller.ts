import type { Request, Response, NextFunction } from 'express';
import { analyzeRecentThreats } from './ai.service.js';

export async function analyze(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const limit = req.query.limit ? Number(req.query.limit) : undefined;
    res.json(await analyzeRecentThreats(limit));
  } catch (e) {
    next(e);
  }
}
