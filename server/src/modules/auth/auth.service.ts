import crypto from 'node:crypto';
import { UserModel, hashPassword, type UserDoc } from '../../models/User.js';
import { PasswordResetTokenModel } from './passwordResetToken.model.js';
import { signToken } from '../../middleware/auth.js';
import { HttpError } from '../../middleware/error.js';
import { sendMail, isMailerConfigured } from '../../utils/mailer.js';
import type { AuthResponse, ForgotPasswordResponse, RegisterRequest, UserRole } from '@cybernexus/shared';

const RESET_TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function toAuthResponse(user: UserDoc): AuthResponse {
  const token = signToken({ sub: user._id.toString(), email: user.email, role: user.role });
  return {
    user: user.toJSON() as unknown as AuthResponse['user'],
    tokens: { accessToken: token },
  };
}

export async function register(input: RegisterRequest): Promise<AuthResponse> {
  const existing = await UserModel.findOne({ email: input.email.toLowerCase() });
  if (existing) throw new HttpError(409, 'Email already registered');

  const passwordHash = await hashPassword(input.password);
  const role: UserRole = input.role ?? 'analyst';
  const user = await UserModel.create({
    email: input.email,
    name: input.name,
    role,
    passwordHash,
  });
  return toAuthResponse(user);
}

export async function login(email: string, password: string): Promise<AuthResponse> {
  const user = await UserModel.findOne({ email: email.toLowerCase() });
  if (!user) throw new HttpError(401, 'Invalid credentials');
  const ok = await user.comparePassword(password);
  if (!ok) throw new HttpError(401, 'Invalid credentials');
  return toAuthResponse(user);
}

export async function getById(id: string) {
  const user = await UserModel.findById(id);
  if (!user) throw new HttpError(404, 'User not found');
  return user.toJSON();
}

/**
 * Always returns the same shape regardless of whether the email is registered
 * — the only thing that varies is `emailAvailable`, a server-wide constant
 * (is SMTP configured at all), never per-request delivery status. This keeps
 * the endpoint from ever revealing whether a given account exists.
 */
export async function forgotPassword(email: string, publicOrigin: string): Promise<ForgotPasswordResponse> {
  const emailAvailable = isMailerConfigured();
  const message = emailAvailable
    ? 'If that email is registered, a password reset link has been sent.'
    : 'If that email is registered, a reset link has been generated. Email delivery is not ' +
      'configured on this server — check the server logs for the link.';

  const user = await UserModel.findOne({ email: email.toLowerCase() });
  if (user) {
    const rawToken = crypto.randomBytes(32).toString('hex');
    await PasswordResetTokenModel.create({
      user: user._id,
      tokenHash: hashToken(rawToken),
      expiresAt: new Date(Date.now() + RESET_TOKEN_TTL_MS),
    });
    const resetUrl = `${publicOrigin}/reset-password?token=${rawToken}`;

    if (emailAvailable) {
      await sendMail({
        to: user.email,
        subject: '[CYBERNEXUS X] Password reset request',
        text: `A password reset was requested for your CYBERNEXUS X account.\n\n` +
          `Reset your password: ${resetUrl}\n\n` +
          `This link expires in 1 hour and can only be used once. If you did not request ` +
          `this, you can safely ignore this email.`,
      });
    } else {
      console.warn(`[auth.forgotPassword] SMTP not configured — reset link for ${user.email}: ${resetUrl}`);
    }
  }

  return { message, emailAvailable };
}

export async function resetPassword(token: string, newPassword: string): Promise<void> {
  const tokenHash = hashToken(token);
  const record = await PasswordResetTokenModel.findOne({ tokenHash, used: false });
  if (!record || record.expiresAt.getTime() < Date.now()) {
    throw new HttpError(400, 'This reset link is invalid or has expired.');
  }
  const user = await UserModel.findById(record.user);
  if (!user) throw new HttpError(400, 'This reset link is invalid or has expired.');

  user.passwordHash = await hashPassword(newPassword);
  await user.save();
  record.used = true;
  await record.save();
}
