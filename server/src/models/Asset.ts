import { Schema, model, type Types } from 'mongoose';
import type { AssetType } from '@cybernexus/shared';

export interface AssetDoc {
  _id: Types.ObjectId;
  name: string;
  type: AssetType;
  ipAddress: string;
  hostname?: string;
  tags: string[];
  owner: Types.ObjectId;
  authorizedForScan: boolean;
  riskScore: number;
  lastScannedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

const assetSchema = new Schema<AssetDoc>(
  {
    name: { type: String, required: true, trim: true },
    type: { type: String, enum: ['host', 'service', 'container', 'web-app'], required: true },
    ipAddress: { type: String, required: true, trim: true },
    hostname: { type: String, trim: true },
    tags: { type: [String], default: [] },
    owner: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    authorizedForScan: { type: Boolean, default: false },
    riskScore: { type: Number, default: 0, min: 0, max: 100 },
    lastScannedAt: { type: Date },
  },
  { timestamps: true }
);

export const AssetModel = model<AssetDoc>('Asset', assetSchema);
