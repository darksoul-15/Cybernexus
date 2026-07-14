import { Router } from 'express';
import * as ctrl from './ai.controller.js';
import { requireAuth } from '../../middleware/auth.js';
import { audit } from '../../middleware/audit.js';

const router = Router();

router.use(requireAuth);

router.post('/analyze', audit('ai.analyze'), ctrl.analyze);

export default router;
