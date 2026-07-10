import { UserModel, hashPassword, type UserDoc } from '../../models/User.js';
import { signToken } from '../../middleware/auth.js';
import { HttpError } from '../../middleware/error.js';
import type { AuthResponse, RegisterRequest, UserRole } from '@cybernexus/shared';

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
