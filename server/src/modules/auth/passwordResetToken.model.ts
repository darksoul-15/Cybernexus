import { Schema, model, type Types } from 'mongoose';

export interface PasswordResetTokenDoc {
  _id: Types.ObjectId;
  user: Types.ObjectId;
  tokenHash: string; // SHA-256 of the raw token — the raw value is never stored
  expiresAt: Date;
  used: boolean;
  createdAt: Date;
}

const passwordResetTokenSchema = new Schema<PasswordResetTokenDoc>(
  {
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    tokenHash: { type: String, required: true, unique: true, index: true },
    expiresAt: { type: Date, required: true },
    used: { type: Boolean, default: false },
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);

export const PasswordResetTokenModel = model<PasswordResetTokenDoc>('PasswordResetToken', passwordResetTokenSchema);
