import { Router } from 'express';
import * as ctrl from './incident.controller.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import { audit } from '../../middleware/audit.js';

const router = Router();

router.use(requireAuth);

router.get('/', ctrl.list);
router.get('/blocklist', ctrl.blocklist);
router.get('/:id', ctrl.getOne);
router.post('/auto-respond', audit('incident.auto-respond'), ctrl.autoRespond);
router.patch('/:id', audit('incident.update'), ctrl.update);

// Blocking is a containment action — admin-only, always audited.
router.post('/block', requireRole('admin'), audit('incident.block'), ctrl.block);

export default router;
