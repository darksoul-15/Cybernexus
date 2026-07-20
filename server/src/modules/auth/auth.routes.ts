import { Router } from 'express';
import * as ctrl from './auth.controller.js';
import { requireAuth } from '../../middleware/auth.js';
import { audit } from '../../middleware/audit.js';

const router = Router();

router.post('/register', audit('auth.register'), ctrl.register);
router.post('/login', audit('auth.login'), ctrl.login);
router.get('/me', requireAuth, ctrl.me);
router.post('/forgot-password', audit('auth.forgot-password'), ctrl.forgotPassword);
router.post('/reset-password', audit('auth.reset-password'), ctrl.resetPassword);

export default router;
