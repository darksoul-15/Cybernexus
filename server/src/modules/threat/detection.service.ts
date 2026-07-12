/**
 * Threat detection engine. Runs statistical + signature detectors over a batch
 * of normalized LogEntry objects and returns candidate detections. Pure and
 * side-effect free — persistence/asset-linking happens in threat.service.ts.
 *
 * Detectors:
 *   1. Rate anomaly   — z-score on per-window request counts (statistical)
 *   2. Port scan      — one source IP touching many distinct ports fast (statistical)
 *   3. Brute force    — repeated failed logins from one IP (signature)
 *   4. SYN flood      — burst of bare-SYN packets from one IP (signature)
 */
import type { LogEntry, Severity, ThreatCategory, ThreatDetectionConfig } from '@cybernexus/shared';

export const DEFAULT_CONFIG: ThreatDetectionConfig = {
  rateWindowSec: 60,
  rateZThreshold: 3,
  rateMinCount: 20,
  portScanWindowSec: 10,
  portScanDistinctPorts: 15,
  bruteForceWindowSec: 60,
  bruteForceAttempts: 10,
  synFloodWindowSec: 5,
  synFloodCount: 100,
};

export interface Detection {
  category: ThreatCategory;
  severity: Severity;
  detectionMethod: 'statistical' | 'signature' | 'reputation';
  sourceIp?: string;
  destIp?: string;
  description: string;
  evidence: Record<string, unknown>;
  score: number; // 0–100
  detectedAt: string; // ISO
}

const ts = (e: LogEntry) => new Date(e.timestamp).getTime();

function severityFromRatio(ratio: number): Severity {
  if (ratio >= 4) return 'critical';
  if (ratio >= 2.5) return 'high';
  if (ratio >= 1.5) return 'medium';
  return 'low';
}

// ── 1. Rate anomaly (z-score over fixed windows) ───────────────────────────
function detectRateAnomaly(entries: LogEntry[], cfg: ThreatDetectionConfig): Detection[] {
  if (entries.length === 0) return [];
  const windowMs = cfg.rateWindowSec * 1000;
  const sorted = [...entries].sort((a, b) => ts(a) - ts(b));
  const t0 = ts(sorted[0]);

  const buckets = new Map<number, number>();
  for (const e of sorted) {
    const idx = Math.floor((ts(e) - t0) / windowMs);
    buckets.set(idx, (buckets.get(idx) ?? 0) + 1);
  }
  const counts = [...buckets.values()];
  if (counts.length < 5) return []; // not enough windows for meaningful stats

  // Leave-one-out z-score: each window is scored against the baseline formed by
  // the OTHER windows, so a large spike doesn't inflate the std it's tested
  // against (which would cap its own z near sqrt(k-1)). A std floor avoids
  // blow-ups when the surrounding baseline is near-uniform.
  const n = counts.length;
  const sum = counts.reduce((a, b) => a + b, 0);
  const sumSq = counts.reduce((a, b) => a + b * b, 0);
  const STD_FLOOR = 1;

  const out: Detection[] = [];
  for (const [idx, count] of buckets) {
    const meanOther = (sum - count) / (n - 1);
    const varOther = (sumSq - count * count) / (n - 1) - meanOther * meanOther;
    const stdOther = Math.max(Math.sqrt(Math.max(0, varOther)), STD_FLOOR);
    const z = (count - meanOther) / stdOther;
    if (z >= cfg.rateZThreshold && count >= cfg.rateMinCount) {
      const windowStart = new Date(t0 + idx * windowMs).toISOString();
      out.push({
        category: 'anomaly-rate',
        severity: severityFromRatio(z / cfg.rateZThreshold),
        detectionMethod: 'statistical',
        description: `Request-rate spike: ${count} requests in a ${cfg.rateWindowSec}s window (z=${z.toFixed(2)}, baseline mean=${meanOther.toFixed(1)})`,
        evidence: { windowStart, count, baselineMean: Number(meanOther.toFixed(2)), baselineStd: Number(stdOther.toFixed(2)), zScore: Number(z.toFixed(2)) },
        score: Math.min(100, Math.round((z / cfg.rateZThreshold) * 50)),
        detectedAt: windowStart,
      });
    }
  }
  return out;
}

// Group entries by source IP.
function groupBySource(entries: LogEntry[]): Map<string, LogEntry[]> {
  const m = new Map<string, LogEntry[]>();
  for (const e of entries) {
    const arr = m.get(e.sourceIp) ?? [];
    arr.push(e);
    m.set(e.sourceIp, arr);
  }
  return m;
}

// ── 2. Port scan (distinct ports from one IP within a sliding window) ──────
function detectPortScan(entries: LogEntry[], cfg: ThreatDetectionConfig): Detection[] {
  const windowMs = cfg.portScanWindowSec * 1000;
  const out: Detection[] = [];

  for (const [ip, evsRaw] of groupBySource(entries)) {
    const evs = evsRaw.filter((e) => typeof e.destPort === 'number').sort((a, b) => ts(a) - ts(b));
    if (evs.length < cfg.portScanDistinctPorts) continue;

    let start = 0;
    let best = 0;
    let bestPorts: number[] = [];
    let bestAt = evs[0].timestamp;
    for (let end = 0; end < evs.length; end++) {
      while (ts(evs[end]) - ts(evs[start]) > windowMs) start++;
      const ports = new Set<number>();
      for (let i = start; i <= end; i++) ports.add(evs[i].destPort!);
      if (ports.size > best) {
        best = ports.size;
        bestPorts = [...ports].sort((a, b) => a - b);
        bestAt = evs[start].timestamp;
      }
    }

    if (best >= cfg.portScanDistinctPorts) {
      const ratio = best / cfg.portScanDistinctPorts;
      out.push({
        category: 'port-scan',
        severity: severityFromRatio(ratio),
        detectionMethod: 'statistical',
        sourceIp: ip,
        destIp: evs[0].destIp,
        description: `Port scan: ${ip} probed ${best} distinct ports within ${cfg.portScanWindowSec}s`,
        evidence: { distinctPorts: best, windowSec: cfg.portScanWindowSec, samplePorts: bestPorts.slice(0, 25) },
        score: Math.min(100, Math.round(ratio * 40)),
        detectedAt: bestAt,
      });
    }
  }
  return out;
}

// Generic sliding-window max-count for entries already grouped by IP.
function maxInWindow(evs: LogEntry[], windowMs: number): { count: number; at: string } {
  const sorted = [...evs].sort((a, b) => ts(a) - ts(b));
  let start = 0;
  let best = 0;
  let bestAt = sorted[0]?.timestamp ?? new Date().toISOString();
  for (let end = 0; end < sorted.length; end++) {
    while (ts(sorted[end]) - ts(sorted[start]) > windowMs) start++;
    const count = end - start + 1;
    if (count > best) {
      best = count;
      bestAt = sorted[start].timestamp;
    }
  }
  return { count: best, at: bestAt };
}

// ── 3. Brute force (failed logins from one IP) ─────────────────────────────
function isFailedAuth(e: LogEntry): boolean {
  const authPath = e.path ? /login|signin|auth|session/i.test(e.path) : false;
  return (e.statusCode === 401 || e.statusCode === 403) && (authPath || e.path === undefined);
}

function detectBruteForce(entries: LogEntry[], cfg: ThreatDetectionConfig): Detection[] {
  const windowMs = cfg.bruteForceWindowSec * 1000;
  const out: Detection[] = [];
  for (const [ip, evs] of groupBySource(entries)) {
    const fails = evs.filter(isFailedAuth);
    if (fails.length < cfg.bruteForceAttempts) continue;
    const { count, at } = maxInWindow(fails, windowMs);
    if (count >= cfg.bruteForceAttempts) {
      const ratio = count / cfg.bruteForceAttempts;
      out.push({
        category: 'brute-force',
        severity: severityFromRatio(ratio),
        detectionMethod: 'signature',
        sourceIp: ip,
        destIp: fails[0].destIp,
        description: `Brute-force: ${count} failed auth attempts from ${ip} within ${cfg.bruteForceWindowSec}s`,
        evidence: { failedAttempts: count, windowSec: cfg.bruteForceWindowSec, samplePath: fails[0].path },
        score: Math.min(100, Math.round(ratio * 45 + 20)),
        detectedAt: at,
      });
    }
  }
  return out;
}

// ── 4. SYN flood (burst of bare SYNs from one IP) ──────────────────────────
function detectSynFlood(entries: LogEntry[], cfg: ThreatDetectionConfig): Detection[] {
  const windowMs = cfg.synFloodWindowSec * 1000;
  const out: Detection[] = [];
  for (const [ip, evs] of groupBySource(entries)) {
    const syns = evs.filter((e) => e.flags?.toUpperCase() === 'S');
    if (syns.length < cfg.synFloodCount) continue;
    const { count, at } = maxInWindow(syns, windowMs);
    if (count >= cfg.synFloodCount) {
      const ratio = count / cfg.synFloodCount;
      out.push({
        category: 'syn-flood',
        severity: severityFromRatio(ratio),
        detectionMethod: 'signature',
        sourceIp: ip,
        destIp: syns[0].destIp,
        description: `SYN flood: ${count} bare-SYN packets from ${ip} within ${cfg.synFloodWindowSec}s`,
        evidence: { synCount: count, windowSec: cfg.synFloodWindowSec, targetPort: syns[0].destPort },
        score: Math.min(100, Math.round(ratio * 50 + 30)),
        detectedAt: at,
      });
    }
  }
  return out;
}

/** Run all detectors and return the combined list of candidate detections. */
export function runDetectors(entries: LogEntry[], config?: Partial<ThreatDetectionConfig>): Detection[] {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  return [
    ...detectRateAnomaly(entries, cfg),
    ...detectPortScan(entries, cfg),
    ...detectBruteForce(entries, cfg),
    ...detectSynFlood(entries, cfg),
  ];
}
