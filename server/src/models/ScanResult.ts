import { Schema, model, type Types } from 'mongoose';
import type { PortState } from '@cybernexus/shared';

export interface PortFindingDoc {
  port: number;
  protocol: 'tcp' | 'udp';
  state: PortState;
  service?: string;
  banner?: string;
  product?: string;
  version?: string;
}

export interface ScanResultDoc {
  _id: Types.ObjectId;
  asset: Types.ObjectId;
  initiatedBy: Types.ObjectId;
  target: string;
  portRange: { start: number; end: number };
  status: 'queued' | 'running' | 'completed' | 'failed';
  ports: PortFindingDoc[];
  startedAt: Date;
  completedAt?: Date;
  durationMs?: number;
  error?: string;
  createdAt: Date;
  updatedAt: Date;
}

const portFindingSchema = new Schema<PortFindingDoc>(
  {
    port: { type: Number, required: true },
    protocol: { type: String, enum: ['tcp', 'udp'], default: 'tcp' },
    state: { type: String, enum: ['open', 'closed', 'filtered'], required: true },
    service: String,
    banner: String,
    product: String,
    version: String,
  },
  { _id: false }
);

const scanResultSchema = new Schema<ScanResultDoc>(
  {
    asset: { type: Schema.Types.ObjectId, ref: 'Asset', required: true, index: true },
    initiatedBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    target: { type: String, required: true },
    portRange: {
      start: { type: Number, required: true },
      end: { type: Number, required: true },
    },
    status: {
      type: String,
      enum: ['queued', 'running', 'completed', 'failed'],
      default: 'queued',
    },
    ports: { type: [portFindingSchema], default: [] },
    startedAt: { type: Date, default: Date.now },
    completedAt: Date,
    durationMs: Number,
    error: String,
  },
  { timestamps: true }
);

export const ScanResultModel = model<ScanResultDoc>('ScanResult', scanResultSchema);
