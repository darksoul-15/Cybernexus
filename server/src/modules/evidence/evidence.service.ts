/**
 * Evidence Vault orchestration (Module 7). Appends tamper-evident records to the
 * SHA-256 hash-chain, logs chain-of-custody on every access/export, and verifies
 * the whole chain on demand.
 */
import { EvidenceRecordModel, type EvidenceRecordDoc } from '../../models/EvidenceRecord.js';
import { Types, type HydratedDocument } from 'mongoose';
import { HttpError } from '../../middleware/error.js';
import {
  GENESIS_PREV_HASH,
  computeContentHash,
  computeRecordHash,
  verifyChain,
} from './hashChain.service.js';
import type { ChainVerificationResult } from '@cybernexus/shared';

export interface AddEvidenceInput {
  type: 'log' | 'scan' | 'threat' | 'file' | 'note';
  payload: Record<string, unknown>;
  incidentId?: string;
  userId: string;
}

/**
 * Append a record to the chain. Two-step so the linking hash is computed from the
 * persisted createdAt (keeping stored hash and stored timestamp consistent for
 * verification). Retries once on an index collision (concurrent append).
 */
export async function addEvidence(input: AddEvidenceInput, attempt = 0): Promise<HydratedDocument<EvidenceRecordDoc>> {
  const tail = await EvidenceRecordModel.findOne().sort({ index: -1 });
  const index = tail ? tail.index + 1 : 0;
  const previousHash = tail ? tail.hash : GENESIS_PREV_HASH;
  const contentHash = computeContentHash(input.payload);

  try {
    // Step 1: create so Mongoose assigns createdAt.
    const doc = await EvidenceRecordModel.create({
      index,
      incident: input.incidentId ? new Types.ObjectId(input.incidentId) : undefined,
      type: input.type,
      payload: input.payload,
      contentHash,
      previousHash,
      hash: 'pending',
      custody: [{ at: new Date(), by: new Types.ObjectId(input.userId), action: 'created' }],
      createdBy: new Types.ObjectId(input.userId),
    });

    // Step 2: compute the linking hash from the persisted timestamp and save.
    doc.hash = computeRecordHash({
      index,
      contentHash,
      previousHash,
      timestamp: doc.createdAt.toISOString(),
      type: input.type,
    });
    await doc.save();
    return doc;
  } catch (e) {
    // Duplicate index (unique) → a concurrent append won the slot; retry once.
    if ((e as { code?: number }).code === 11000 && attempt < 3) {
      return addEvidence(input, attempt + 1);
    }
    throw e;
  }
}

export async function listEvidence() {
  return EvidenceRecordModel.find().sort({ index: 1 }).select('-payload').lean();
}

/** Fetch a record and append an 'accessed' custody entry. */
export async function getEvidence(id: string, userId: string) {
  const doc = await EvidenceRecordModel.findById(id);
  if (!doc) throw new HttpError(404, 'Evidence record not found');
  doc.custody.push({ at: new Date(), by: new Types.ObjectId(userId), action: 'accessed' });
  await doc.save();
  return doc.toJSON();
}

/** Export a record (full payload + custody) and append an 'exported' custody entry. */
export async function exportEvidence(id: string, userId: string) {
  const doc = await EvidenceRecordModel.findById(id);
  if (!doc) throw new HttpError(404, 'Evidence record not found');
  doc.custody.push({ at: new Date(), by: new Types.ObjectId(userId), action: 'exported' });
  await doc.save();
  return doc.toJSON();
}

export async function verify(): Promise<ChainVerificationResult> {
  const records = await EvidenceRecordModel.find().sort({ index: 1 });
  const { issues, headHash } = verifyChain(records);
  return {
    valid: issues.length === 0,
    length: records.length,
    headHash,
    issues,
    verifiedAt: new Date().toISOString(),
  };
}
