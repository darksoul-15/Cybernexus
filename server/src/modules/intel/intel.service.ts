/**
 * Threat Intelligence orchestration — Module 4 vertical slice:
 *   validate indicator → per-provider cache lookup → live query on miss →
 *   cache available results → aggregate a combined verdict.
 *
 * Also enriches ThreatEvent source IPs with reputation and raises a
 * 'reputation' ThreatEvent when a source is judged malicious.
 */
import { IntelCacheModel } from './intelCache.model.js';
import { checkIp as abuseCheckIp, normalizeAbuse } from './abuseipdb.service.js';
import { checkIndicator as vtCheck } from './virustotal.service.js';
import { classifyIndicator } from './indicator.util.js';
import { ThreatEventModel } from '../../models/ThreatEvent.js';
import { emitThreats } from '../../realtime/bus.js';
import { HttpError } from '../../middleware/error.js';
import type {
  IndicatorReputation,
  IndicatorType,
  IntelProvider,
  ProviderReputation,
  ReputationVerdict,
} from '@cybernexus/shared';

const CACHE_TTL_MS = 1000 * 60 * 60 * 24; // 24h

const VERDICT_RANK: Record<ReputationVerdict, number> = { unknown: 0, clean: 1, suspicious: 2, malicious: 3 };

/** Pure aggregation: worst verdict + max score across AVAILABLE sources. */
export function aggregate(indicator: string, type: IndicatorType, sources: ProviderReputation[]): IndicatorReputation {
  const available = sources.filter((s) => s.available);
  let verdict: ReputationVerdict = 'unknown';
  let score = 0;
  for (const s of available) {
    if (VERDICT_RANK[s.verdict] > VERDICT_RANK[verdict]) verdict = s.verdict;
    if (s.score > score) score = s.score;
  }
  return { indicator, type, verdict, score, sources, checkedAt: new Date().toISOString() };
}

async function fromCache(provider: IntelProvider, type: IndicatorType, indicator: string): Promise<ProviderReputation | null> {
  const cacheKey = `${provider}:${type}:${indicator}`;
  const hit = await IntelCacheModel.findOne({ cacheKey });
  if (hit && Date.now() - hit.fetchedAt.getTime() < CACHE_TTL_MS) {
    return { ...hit.result, cached: true };
  }
  return null;
}

async function toCache(provider: IntelProvider, type: IndicatorType, indicator: string, result: ProviderReputation): Promise<void> {
  if (!result.available) return; // never cache misses/errors — retry when configured
  const cacheKey = `${provider}:${type}:${indicator}`;
  await IntelCacheModel.findOneAndUpdate(
    { cacheKey },
    { cacheKey, provider, type, indicator, result: { ...result, cached: false }, fetchedAt: new Date() },
    { upsert: true }
  );
}

async function queryProvider(
  provider: IntelProvider,
  type: IndicatorType,
  indicator: string,
  live: () => Promise<ProviderReputation>,
  force: boolean
): Promise<ProviderReputation> {
  if (!force) {
    const cached = await fromCache(provider, type, indicator);
    if (cached) return cached;
  }
  const result = await live();
  await toCache(provider, type, indicator, result);
  return result;
}

export interface LookupOptions {
  force?: boolean; // bypass cache
}

export async function lookupIndicator(raw: string, opts: LookupOptions = {}): Promise<IndicatorReputation> {
  const indicator = raw.trim().toLowerCase();
  const type = classifyIndicator(indicator);
  if (!type) throw new HttpError(400, 'Indicator must be a valid IPv4 address or domain name');

  const force = opts.force ?? false;
  const providers: Promise<ProviderReputation>[] = [
    queryProvider('virustotal', type, indicator, () => vtCheck(indicator, type), force),
  ];
  // AbuseIPDB is IP-only.
  if (type === 'ip') {
    providers.push(queryProvider('abuseipdb', type, indicator, () => abuseCheckIp(indicator), force));
  }

  const sources = await Promise.all(providers);
  return aggregate(indicator, type, sources);
}

/**
 * Enrich recent ThreatEvent source IPs with reputation. When a source is judged
 * malicious, raise a 'reputation' ThreatEvent (deduped per source IP).
 */
export async function enrichThreatSources(limit = 25): Promise<{ checked: number; malicious: number; raised: number }> {
  const threats = await ThreatEventModel.find({ sourceIp: { $exists: true, $ne: null } })
    .sort({ detectedAt: -1 })
    .limit(Math.min(limit, 100))
    .lean();

  const seen = new Set<string>();
  let checked = 0;
  let malicious = 0;
  let raised = 0;

  for (const t of threats) {
    const ip = t.sourceIp!;
    if (seen.has(ip) || classifyIndicator(ip) !== 'ip') continue;
    seen.add(ip);
    checked++;

    const rep = await lookupIndicator(ip);
    if (rep.verdict !== 'malicious') continue;
    malicious++;

    const already = await ThreatEventModel.findOne({ category: 'reputation', sourceIp: ip });
    if (already) continue;

    const doc = await ThreatEventModel.create({
      category: 'reputation',
      severity: rep.score >= 75 ? 'high' : 'medium',
      sourceIp: ip,
      detectionMethod: 'reputation',
      description: `Source IP ${ip} flagged malicious by threat intel (score ${rep.score})`,
      evidence: { verdict: rep.verdict, score: rep.score, sources: rep.sources.map((s) => ({ provider: s.provider, verdict: s.verdict, score: s.score })) },
      score: rep.score,
      acknowledged: false,
      detectedAt: new Date(),
    });
    emitThreats([doc.toJSON()]);
    raised++;
  }

  return { checked, malicious, raised };
}

export { normalizeAbuse };
