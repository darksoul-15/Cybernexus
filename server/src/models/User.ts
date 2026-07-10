import { Schema, model, type Document, type Types } from 'mongoose';
import bcrypt from 'bcryptjs';
import type { UserRole } from '@cybernexus/shared';

export interface UserDoc extends Document {
  _id: Types.ObjectId;
  email: string;
  name: string;
  role: UserRole;
  passwordHash: string;
  createdAt: Date;
  updatedAt: Date;
  comparePassword(plain: string): Promise<boolean>;
}

const userSchema = new Schema<UserDoc>(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
    name: { type: String, required: true, trim: true },
    role: { type: String, enum: ['admin', 'analyst'], default: 'analyst', required: true },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true }
);

userSchema.methods.comparePassword = function (plain: string): Promise<boolean> {
  return bcrypt.compare(plain, this.passwordHash);
};

// Never leak the hash when serialized
userSchema.set('toJSON', {
  transform(_doc, ret) {
    const r = ret as unknown as Record<string, unknown>;
    delete r.passwordHash;
    delete r.__v;
    return r;
  },
});

export async function hashPassword(plain: string): Promise<string> {
  return bcrypt.hash(plain, 10);
}

export const UserModel = model<UserDoc>('User', userSchema);
