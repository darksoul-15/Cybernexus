import { Schema, model, type Types } from 'mongoose';
import type { IncidentStatus, Severity } from '@cybernexus/shared';

export interface IncidentActionDoc {
  at: Date;
  by: Types.ObjectId;
  action: string;
  live: boolean;
}

export interface IncidentDoc {
  _id: Types.ObjectId;
  title: string;
  status: IncidentStatus;
  severity: Severity;
  assignee?: Types.ObjectId;
  relatedThreats: Types.ObjectId[];
  relatedAsset?: Types.ObjectId;
  summary: string;
  actions: IncidentActionDoc[];
  openedAt: Date;
  resolvedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

const actionSchema = new Schema<IncidentActionDoc>(
  {
    at: { type: Date, default: Date.now },
    by: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    action: { type: String, required: true },
    live: { type: Boolean, default: false },
  },
  { _id: false }
);

const incidentSchema = new Schema<IncidentDoc>(
  {
    title: { type: String, required: true },
    status: {
      type: String,
      enum: ['new', 'investigating', 'contained', 'resolved', 'closed'],
      default: 'new',
      index: true,
    },
    severity: {
      type: String,
      enum: ['info', 'low', 'medium', 'high', 'critical'],
      required: true,
    },
    assignee: { type: Schema.Types.ObjectId, ref: 'User' },
    relatedThreats: [{ type: Schema.Types.ObjectId, ref: 'ThreatEvent' }],
    relatedAsset: { type: Schema.Types.ObjectId, ref: 'Asset' },
    summary: { type: String, default: '' },
    actions: { type: [actionSchema], default: [] },
    openedAt: { type: Date, default: Date.now },
    resolvedAt: Date,
  },
  { timestamps: true }
);

export const IncidentModel = model<IncidentDoc>('Incident', incidentSchema);
