import { Router } from 'express';
import type { Request, Response, NextFunction } from 'express';
import { requireAuth } from '../../middleware/auth.js';
import { getSummary } from './dashboard.service.js';

const router = Router();

router.use(requireAuth);

router.get('/summary', async (_req: Request, res: Response, next: NextFunction) => {
  try {
    res.json(await getSummary());
  } catch (e) {
    next(e);
  }
});

export default router;
