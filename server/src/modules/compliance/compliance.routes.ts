import { Router } from 'express';
import * as ctrl from './compliance.controller.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import { audit } from '../../middleware/audit.js';

const router = Router();

// Compliance data is sensitive — admin-only, and access is itself audited.
router.use(requireAuth, requireRole('admin'));

router.get('/audit', ctrl.listAudit);
router.get('/audit/stats', ctrl.auditStats);
router.get('/report', audit('compliance.report'), ctrl.report);
router.get('/report.pdf', audit('compliance.report.pdf'), ctrl.reportPdf);

export default router;
