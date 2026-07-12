/**
 * VirusTotal reputation provider (v3). Supports IPs and domains.
 * Docs: https://docs.virustotal.com/reference/ip-info  /  /reference/domain-info
 */
import { env } from '../../config/env.js';
import type { IndicatorType, ProviderReputation, ReputationVerdict } from '@cybernexus/shared';

const TIMEOUT_MS = 8000;

function verdictFromStats(malicious: number, suspicious: number): ReputationVerdict {
  if (malicious >= 3) return 'malicious';
  if (malicious >= 1 || suspicious >= 2) return 'suspicious';
  return 'clean';
}

/** Pure normalizer for a VirusTotal v3 object response. Testable without network. */
export function normalizeVt(json: any): ProviderReputation {
  const attr = json?.data?.attributes ?? {};
  const stats = attr.last_analysis_stats ?? {};
  const malicious = Number(stats.malicious ?? 0);
  const suspicious = Number(stats.suspicious ?? 0);
  const harmless = Number(stats.harmless ?? 0);
  const undetected = Number(stats.undetected ?? 0);
  const engines = malicious + suspicious + harmless + undetected + Number(stats.timeout ?? 0);
  const score = Math.min(100, malicious * 12 + suspicious * 4);
  return {
    provider: 'virustotal',
    available: true,
    verdict: verdictFromStats(malicious, suspicious),
    score,
    cached: false,
    detail: {
      malicious,
      suspicious,
      harmless,
      undetected,
      engines,
      reputation: typeof attr.reputation === 'number' ? attr.reputation : null,
    },
  };
}

function unavailable(error: string): ProviderReputation {
  return { provider: 'virustotal', available: false, verdict: 'unknown', score: 0, cached: false, detail: {}, error };
}

/** Live lookup for an IP or domain. Returns available:false when key missing or request fails. */
export async function checkIndicator(indicator: string, type: IndicatorType): Promise<ProviderReputation> {
  if (!env.virustotalApiKey) return unavailable('VIRUSTOTAL_API_KEY not configured');
  const path = type === 'ip' ? `ip_addresses/${indicator}` : `domains/${indicator}`;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    const res = await fetch(`https://www.virustotal.com/api/v3/${path}`, {
      signal: controller.signal,
      headers: { 'x-apikey': env.virustotalApiKey, Accept: 'application/json' },
    });
    clearTimeout(timer);
    if (!res.ok) return unavailable(`HTTP ${res.status}`);
    return normalizeVt(await res.json());
  } catch (e) {
    return unavailable((e as Error).message);
  }
}
