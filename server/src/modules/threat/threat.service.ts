/**
 * Threat orchestration — the Module 3 vertical slice:
 *   parse logs → run detectors → link target assets → persist ThreatEvents.
 */
import { ThreatEventModel } from '../../models/ThreatEvent.js';
import { AssetModel } from '../../models/Asset.js';
import { parseLogs } from './logParser.service.js';
import { runDetectors, type Detection } from './detection.service.js';
import type {
  IngestSummary,
  LogFormat,
  ThreatCategory,
  ThreatDetectionConfig,
  ThreatEvent,
} from '@cybernexus/shared';

export interface IngestInput {
  data: string | unknown[];
  format: LogFormat;
  config?: Partial<ThreatDetectionConfig>;
}

/** Resolve destIp → Asset._id for detections that carry a target. */
async function resolveAssets(dests: string[]): Promise<Map<string, string>> {
  const unique = [...new Set(dests.filter(Boolean))];
  if (unique.length === 0) return new Map();
  const assets = await AssetModel.find({ ipAddress: { $in: unique } }).select('_id ipAddress').lean();
  const map = new Map<string, string>();
  for (const a of assets) map.set(a.ipAddress, a._id.toString());
  return map;
}

export async function ingestAndDetect(input: IngestInput): Promise<IngestSummary> {
  const { entries, skipped } = parseLogs(input.data, input.format);
  const detections = runDetectors(entries, input.config);

  const assetMap = await resolveAssets(detections.map((d) => d.destIp ?? ''));

  const docs = detections.map((d: Detection) => ({
    category: d.category,
    severity: d.severity,
    sourceIp: d.sourceIp,
    targetAsset: d.destIp ? assetMap.get(d.destIp) : undefined,
    detectionMethod: d.detectionMethod,
    description: d.description,
    evidence: d.evidence,
    score: d.score,
    acknowledged: false,
    detectedAt: new Date(d.detectedAt),
  }));

  const created = docs.length ? await ThreatEventModel.insertMany(docs) : [];

  const byCategory: Partial<Record<ThreatCategory, number>> = {};
  for (const d of detections) byCategory[d.category] = (byCategory[d.category] ?? 0) + 1;

  return {
    entriesParsed: entries.length,
    entriesSkipped: skipped,
    threatsDetected: created.length,
    byCategory,
    threats: created.map((c) => c.toJSON() as unknown as ThreatEvent),
  };
}

export interface ThreatQuery {
  category?: string;
  severity?: string;
  acknowledged?: boolean;
  limit?: number;
}

export async function listThreats(q: ThreatQuery = {}) {
  const filter: Record<string, unknown> = {};
  if (q.category) filter.category = q.category;
  if (q.severity) filter.severity = q.severity;
  if (typeof q.acknowledged === 'boolean') filter.acknowledged = q.acknowledged;
  return ThreatEventModel.find(filter)
    .sort({ detectedAt: -1 })
    .limit(Math.min(q.limit ?? 100, 500))
    .lean();
}

export async function acknowledgeThreat(id: string) {
  const doc = await ThreatEventModel.findByIdAndUpdate(id, { acknowledged: true }, { new: true });
  return doc?.toJSON() ?? null;
}

export async function threatStats() {
  const [byCategory, bySeverity, total, unacked] = await Promise.all([
    ThreatEventModel.aggregate([{ $group: { _id: '$category', count: { $sum: 1 } } }]),
    ThreatEventModel.aggregate([{ $group: { _id: '$severity', count: { $sum: 1 } } }]),
    ThreatEventModel.countDocuments({}),
    ThreatEventModel.countDocuments({ acknowledged: false }),
  ]);
  return { total, unacknowledged: unacked, byCategory, bySeverity };
}
