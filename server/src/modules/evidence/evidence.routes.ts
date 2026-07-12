import { Router } from 'express';
import * as ctrl from './evidence.controller.js';
import { requireAuth } from '../../middleware/auth.js';
import { audit } from '../../middleware/audit.js';

const router = Router();

router.use(requireAuth);

router.get('/', ctrl.list);
router.get('/verify', ctrl.verify);
router.get('/:id', audit('evidence.access'), ctrl.getOne);
router.get('/:id/export', audit('evidence.export'), ctrl.exportOne);
router.post('/', audit('evidence.add'), ctrl.add);

export default router;
