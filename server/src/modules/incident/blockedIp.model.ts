import { Schema, model, type Types } from 'mongoose';
import type { BlockMode } from '@cybernexus/shared';

/**
 * Blocked-IP ledger. Records containment actions. `enforced` is true only when a
 * real OS firewall rule was actually applied (live mode + real-firewall opt-in);
 * otherwise the entry is a simulated/logged record. Supporting infrastructure —
 * not one of the 8 core domain entities.
 */
export interface BlockedIpDoc {
  _id: Types.ObjectId;
  ip: string;
  mode: BlockMode;
  enforced: boolean;
  reason: string;
  incident?: Types.ObjectId;
  active: boolean;
  createdBy?: Types.ObjectId;
  createdAt: Date;
}

const blockedIpSchema = new Schema<BlockedIpDoc>(
  {
    ip: { type: String, required: true, index: true },
    mode: { type: String, enum: ['simulated', 'live'], required: true },
    enforced: { type: Boolean, default: false },
    reason: { type: String, default: '' },
    incident: { type: Schema.Types.ObjectId, ref: 'Incident' },
    active: { type: Boolean, default: true },
    createdBy: { type: Schema.Types.ObjectId, ref: 'User' },
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);

export const BlockedIpModel = model<BlockedIpDoc>('BlockedIp', blockedIpSchema);
