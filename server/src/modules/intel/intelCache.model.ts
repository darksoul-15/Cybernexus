import { Schema, model, type Types } from 'mongoose';
import type { IntelProvider, IndicatorType, ProviderReputation } from '@cybernexus/shared';

/**
 * Cache for per-provider reputation lookups. Keyed by provider+type+indicator so
 * we respect free-tier rate limits (AbuseIPDB 1000/day, VirusTotal 4/min).
 * Supporting infrastructure — not one of the 8 core domain entities.
 */
export interface IntelCacheDoc {
  _id: Types.ObjectId;
  cacheKey: string; // `${provider}:${type}:${indicator}`
  provider: IntelProvider;
  type: IndicatorType;
  indicator: string;
  result: ProviderReputation; // normalized provider result (available:true only)
  fetchedAt: Date;
}

const intelCacheSchema = new Schema<IntelCacheDoc>({
  cacheKey: { type: String, required: true, unique: true, index: true },
  provider: { type: String, required: true },
  type: { type: String, required: true },
  indicator: { type: String, required: true },
  result: { type: Schema.Types.Mixed, required: true },
  fetchedAt: { type: Date, default: Date.now },
});

export const IntelCacheModel = model<IntelCacheDoc>('IntelCache', intelCacheSchema);
