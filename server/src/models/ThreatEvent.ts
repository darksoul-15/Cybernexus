import { Schema, model, type Types } from 'mongoose';
import type { Severity, ThreatCategory } from '@cybernexus/shared';

export interface ThreatEventDoc {
  _id: Types.ObjectId;
  category: ThreatCategory;
  severity: Severity;
  sourceIp?: string;
  targetAsset?: Types.ObjectId;
  detectionMethod: 'statistical' | 'signature' | 'reputation';
  description: string;
  evidence: Record<string, unknown>;
  score: number;
  acknowledged: boolean;
  incident?: Types.ObjectId;
  detectedAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

const threatSchema = new Schema<ThreatEventDoc>(
  {
    category: {
      type: String,
      enum: ['anomaly-rate', 'port-scan', 'brute-force', 'syn-flood', 'signature', 'reputation'],
      required: true,
    },
    severity: {
      type: String,
      enum: ['info', 'low', 'medium', 'high', 'critical'],
      required: true,
      index: true,
    },
    sourceIp: String,
    targetAsset: { type: Schema.Types.ObjectId, ref: 'Asset' },
    detectionMethod: { type: String, enum: ['statistical', 'signature', 'reputation'], required: true },
    description: { type: String, required: true },
    evidence: { type: Schema.Types.Mixed, default: {} },
    score: { type: Number, default: 0, min: 0, max: 100 },
    acknowledged: { type: Boolean, default: false },
    incident: { type: Schema.Types.ObjectId, ref: 'Incident' },
    detectedAt: { type: Date, default: Date.now, index: true },
  },
  { timestamps: true }
);

export const ThreatEventModel = model<ThreatEventDoc>('ThreatEvent', threatSchema);
