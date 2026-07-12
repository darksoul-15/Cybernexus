import { Router } from 'express';
import * as ctrl from './intel.controller.js';
import { requireAuth } from '../../middleware/auth.js';
import { audit } from '../../middleware/audit.js';

const router = Router();

router.use(requireAuth);

router.get('/lookup/:indicator', audit('intel.lookup'), ctrl.lookup);
router.post('/enrich', audit('intel.enrich'), ctrl.enrich);

export default router;
