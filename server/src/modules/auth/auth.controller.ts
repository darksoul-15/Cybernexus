import type { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import * as authService from './auth.service.js';
import { HttpError } from '../../middleware/error.js';

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  name: z.string().min(1),
  role: z.enum(['admin', 'analyst']).optional(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

export async function register(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) throw new HttpError(400, 'Validation failed', parsed.error.flatten());
    const result = await authService.register(parsed.data);
    res.status(201).json(result);
  } catch (e) {
    next(e);
  }
}

export async function login(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) throw new HttpError(400, 'Validation failed', parsed.error.flatten());
    const result = await authService.login(parsed.data.email, parsed.data.password);
    res.json(result);
  } catch (e) {
    next(e);
  }
}

export async function me(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    if (!req.user) throw new HttpError(401, 'Not authenticated');
    const user = await authService.getById(req.user.sub);
    res.json({ user });
  } catch (e) {
    next(e);
  }
}
