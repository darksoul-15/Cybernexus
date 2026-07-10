import { Schema, model, type Types } from 'mongoose';

export interface CustodyEntryDoc {
  at: Date;
  by: Types.ObjectId;
  action: 'created' | 'accessed' | 'exported';
}

export interface EvidenceRecordDoc {
  _id: Types.ObjectId;
  index: number;
  incident?: Types.ObjectId;
  type: 'log' | 'scan' | 'threat' | 'file' | 'note';
  payload: Record<string, unknown>;
  contentHash: string;
  previousHash: string;
  hash: string;
  custody: CustodyEntryDoc[];
  createdBy: Types.ObjectId;
  createdAt: Date;
}

const custodySchema = new Schema<CustodyEntryDoc>(
  {
    at: { type: Date, default: Date.now },
    by: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    action: { type: String, enum: ['created', 'accessed', 'exported'], required: true },
  },
  { _id: false }
);

const evidenceSchema = new Schema<EvidenceRecordDoc>(
  {
    index: { type: Number, required: true, unique: true, index: true },
    incident: { type: Schema.Types.ObjectId, ref: 'Incident' },
    type: { type: String, enum: ['log', 'scan', 'threat', 'file', 'note'], required: true },
    payload: { type: Schema.Types.Mixed, required: true },
    contentHash: { type: String, required: true },
    previousHash: { type: String, required: true },
    hash: { type: String, required: true },
    custody: { type: [custodySchema], default: [] },
    createdBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);

export const EvidenceRecordModel = model<EvidenceRecordDoc>('EvidenceRecord', evidenceSchema);
