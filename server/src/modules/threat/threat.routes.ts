import { Router } from 'express';
import * as ctrl from './threat.controller.js';
import { requireAuth } from '../../middleware/auth.js';
import { audit } from '../../middleware/audit.js';

const router = Router();

router.use(requireAuth);

router.post('/ingest', audit('threat.ingest'), ctrl.ingest);
router.post('/ingest/sample', audit('threat.ingest.sample'), ctrl.ingestSample);
router.get('/', ctrl.list);
router.get('/stats', ctrl.stats);
router.patch('/:id/acknowledge', audit('threat.acknowledge'), ctrl.acknowledge);

export default router;
