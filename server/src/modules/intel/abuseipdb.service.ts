/**
 * AbuseIPDB reputation provider (v2 CHECK endpoint). IP-only.
 * Docs: https://docs.abuseipdb.com/#check-endpoint
 */
import { env } from '../../config/env.js';
import type { ProviderReputation, ReputationVerdict } from '@cybernexus/shared';

const ENDPOINT = 'https://api.abuseipdb.com/api/v2/check';
const TIMEOUT_MS = 8000;

function verdictFromConfidence(score: number): ReputationVerdict {
  if (score >= 50) return 'malicious';
  if (score >= 25) return 'suspicious';
  return 'clean';
}

/** Pure normalizer for an AbuseIPDB check response body. Testable without network. */
export function normalizeAbuse(json: any): ProviderReputation {
  const d = json?.data ?? {};
  const score = typeof d.abuseConfidenceScore === 'number' ? d.abuseConfidenceScore : 0;
  return {
    provider: 'abuseipdb',
    available: true,
    verdict: verdictFromConfidence(score),
    score,
    cached: false,
    detail: {
      abuseConfidenceScore: score,
      totalReports: d.totalReports ?? 0,
      countryCode: d.countryCode ?? null,
      isp: d.isp ?? null,
      domain: d.domain ?? null,
      usageType: d.usageType ?? null,
      lastReportedAt: d.lastReportedAt ?? null,
      isTor: d.isTor ?? null,
    },
  };
}

function unavailable(error: string): ProviderReputation {
  return { provider: 'abuseipdb', available: false, verdict: 'unknown', score: 0, cached: false, detail: {}, error };
}

/** Live lookup. Returns available:false (never fabricates) when key missing or request fails. */
export async function checkIp(ip: string): Promise<ProviderReputation> {
  if (!env.abuseipdbApiKey) return unavailable('ABUSEIPDB_API_KEY not configured');
  const url = new URL(ENDPOINT);
  url.searchParams.set('ipAddress', ip);
  url.searchParams.set('maxAgeInDays', '90');
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Key: env.abuseipdbApiKey, Accept: 'application/json' },
    });
    clearTimeout(timer);
    if (!res.ok) return unavailable(`HTTP ${res.status}`);
    return normalizeAbuse(await res.json());
  } catch (e) {
    return unavailable((e as Error).message);
  }
}
