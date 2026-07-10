import { Router } from 'express';
import * as ctrl from './auth.controller.js';
import { requireAuth } from '../../middleware/auth.js';
import { audit } from '../../middleware/audit.js';

const router = Router();

router.post('/register', audit('auth.register'), ctrl.register);
router.post('/login', audit('auth.login'), ctrl.login);
router.get('/me', requireAuth, ctrl.me);

export default router;
