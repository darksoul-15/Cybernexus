import { Router } from 'express';
import * as ctrl from './asset.controller.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import { audit } from '../../middleware/audit.js';

const router = Router();

router.use(requireAuth);

router.get('/', ctrl.list);
router.get('/:id', ctrl.getOne);
router.post('/', audit('asset.create'), ctrl.create);
router.delete('/:id', requireRole('admin'), audit('asset.delete'), ctrl.remove);

export default router;
