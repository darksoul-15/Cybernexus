import type { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import * as authService from './auth.service.js';
import { HttpError } from '../../middleware/error.js';
import { env } from '../../config/env.js';

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

const forgotPasswordSchema = z.object({ email: z.string().email() });
const resetPasswordSchema = z.object({
  token: z.string().min(1),
  password: z.string().min(8, 'Password must be at least 8 characters'),
});

/**
 * Resolve the public URL to embed in a password-reset link.
 * - Split deployment (separately hosted client): CLIENT_ORIGIN is explicitly
 *   set — trust it, since the request's own Host header is the API's host,
 *   not the client's.
 * - Single-service deployment (SERVE_CLIENT=true): client and API share one
 *   origin, so the incoming request's own Host header IS the public URL.
 * - Local dev otherwise: falls back to env.clientOrigin's localhost default.
 */
function resolvePublicOrigin(req: Request): string {
  if (process.env.CLIENT_ORIGIN) return process.env.CLIENT_ORIGIN;
  if (env.serveClient) return `${req.protocol}://${req.get('host')}`;
  return env.clientOrigin;
}

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

export async function forgotPassword(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const parsed = forgotPasswordSchema.safeParse(req.body);
    if (!parsed.success) throw new HttpError(400, 'Validation failed', parsed.error.flatten());
    const result = await authService.forgotPassword(parsed.data.email, resolvePublicOrigin(req));
    res.json(result);
  } catch (e) {
    next(e);
  }
}

export async function resetPassword(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const parsed = resetPasswordSchema.safeParse(req.body);
    if (!parsed.success) throw new HttpError(400, 'Validation failed', parsed.error.flatten());
    await authService.resetPassword(parsed.data.token, parsed.data.password);
    res.json({ message: 'Password has been reset. You can now sign in with your new password.' });
  } catch (e) {
    next(e);
  }
}
