import { Schema, model, type Types } from 'mongoose';

export interface AuditLogDoc {
  _id: Types.ObjectId;
  actor?: Types.ObjectId;
  actorEmail?: string;
  action: string;
  method: string;
  path: string;
  statusCode: number;
  ip: string;
  meta?: Record<string, unknown>;
  createdAt: Date;
}

const auditSchema = new Schema<AuditLogDoc>(
  {
    actor: { type: Schema.Types.ObjectId, ref: 'User', index: true },
    actorEmail: String,
    action: { type: String, required: true, index: true },
    method: { type: String, required: true },
    path: { type: String, required: true },
    statusCode: { type: Number, required: true },
    ip: { type: String, default: '' },
    meta: { type: Schema.Types.Mixed },
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);

export const AuditLogModel = model<AuditLogDoc>('AuditLog', auditSchema);
