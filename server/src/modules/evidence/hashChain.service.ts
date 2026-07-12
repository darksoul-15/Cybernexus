/**
 * SHA-256 hash-chain primitives (Module 7). Pure functions — no DB.
 *
 * Each record binds: index, a hash of its (canonicalized) payload, the previous
 * record's hash, its timestamp, and its type. Because every record's hash feeds
 * the next record's `previousHash`, altering any past payload invalidates that
 * record AND breaks the link for every record after it — the tamper-evidence
 * property. This is a real hash-chain ledger, not a distributed blockchain
 * (a documented design decision, per project scope).
 */
import { createHash } from 'node:crypto';

export const GENESIS_PREV_HASH = '0'.repeat(64);

function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Deterministic JSON serialization: object keys sorted recursively so the same
 * logical payload always produces the same string (and thus the same hash).
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value) ?? 'null';
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(',')}}`;
}

export function computeContentHash(payload: unknown): string {
  return sha256(canonicalize(payload));
}

export interface RecordHashInput {
  index: number;
  contentHash: string;
  previousHash: string;
  timestamp: string; // ISO string
  type: string;
}

export function computeRecordHash(i: RecordHashInput): string {
  return sha256([i.index, i.contentHash, i.previousHash, i.timestamp, i.type].join('|'));
}

// Minimal shape needed to verify a stored record.
export interface VerifiableRecord {
  _id: { toString(): string };
  index: number;
  type: string;
  payload: unknown;
  contentHash: string;
  previousHash: string;
  hash: string;
  createdAt: Date;
}

export interface ChainIssueLike {
  index: number;
  recordId: string;
  problem: string;
}

/** Re-walk an ordered chain and report every integrity problem found. */
export function verifyChain(records: VerifiableRecord[]): { issues: ChainIssueLike[]; headHash: string | null } {
  const sorted = [...records].sort((a, b) => a.index - b.index);
  const issues: ChainIssueLike[] = [];
  let prevHash = GENESIS_PREV_HASH;
  let expectedIndex = 0;

  for (const rec of sorted) {
    const recordId = rec._id.toString();

    if (rec.index !== expectedIndex) {
      issues.push({ index: rec.index, recordId, problem: `Index gap: expected ${expectedIndex}, found ${rec.index}` });
    }
    const recomputedContent = computeContentHash(rec.payload);
    if (recomputedContent !== rec.contentHash) {
      issues.push({ index: rec.index, recordId, problem: 'Payload tampered: content hash mismatch' });
    }
    if (rec.previousHash !== prevHash) {
      issues.push({ index: rec.index, recordId, problem: 'Broken link: previousHash does not match prior record hash' });
    }
    const recomputedHash = computeRecordHash({
      index: rec.index,
      contentHash: rec.contentHash,
      previousHash: rec.previousHash,
      timestamp: rec.createdAt.toISOString(),
      type: rec.type,
    });
    if (recomputedHash !== rec.hash) {
      issues.push({ index: rec.index, recordId, problem: 'Record hash mismatch: stored hash is inconsistent with record fields' });
    }

    prevHash = rec.hash;
    expectedIndex++;
  }

  return { issues, headHash: sorted.length ? sorted[sorted.length - 1].hash : null };
}
