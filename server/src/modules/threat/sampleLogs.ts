/**
 * Synthetic sample-log generator. Produces normalized LogEntry batches with a
 * benign baseline plus optionally-embedded attack patterns, so the detection
 * engine can be exercised without real traffic.
 *
 * IMPORTANT: this is synthetic INPUT data the user controls (explicitly allowed
 * by the project rules) — it is NOT fabricated threat output. Detected threats
 * are always the real result of running the detectors over these logs.
 */
import type { LogEntry } from '@cybernexus/shared';

export interface SampleOptions {
  baseIp?: string;
  destIp?: string;
  minutes?: number; // span of benign baseline
  ratePerMin?: number; // baseline request rate
  includeRateSpike?: boolean;
  includePortScan?: boolean;
  includeBruteForce?: boolean;
  includeSynFlood?: boolean;
  seed?: number;
}

// Small deterministic PRNG so samples are reproducible in tests.
function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function generateSampleLogs(opts: SampleOptions = {}): LogEntry[] {
  const baseIp = opts.baseIp ?? '192.168.1.10';
  const destIp = opts.destIp ?? '127.0.0.1';
  const minutes = opts.minutes ?? 10;
  const ratePerMin = opts.ratePerMin ?? 12;
  const rnd = mulberry32(opts.seed ?? 1337);
  const start = Date.UTC(2026, 0, 1, 0, 0, 0);
  const entries: LogEntry[] = [];

  const paths = ['/', '/index.html', '/api/status', '/assets/app.js', '/favicon.ico'];

  // Benign baseline: spread requests across the window with mild jitter.
  for (let m = 0; m < minutes; m++) {
    for (let i = 0; i < ratePerMin; i++) {
      const jitter = Math.floor(rnd() * 60000);
      entries.push({
        timestamp: new Date(start + m * 60000 + jitter).toISOString(),
        sourceIp: `192.168.1.${20 + Math.floor(rnd() * 50)}`,
        destIp,
        destPort: 80,
        method: 'GET',
        path: paths[Math.floor(rnd() * paths.length)],
        statusCode: 200,
        bytes: 200 + Math.floor(rnd() * 4000),
        protocol: 'tcp',
      });
    }
  }

  // Rate spike: a flood of requests inside a single window.
  if (opts.includeRateSpike) {
    const spikeStart = start + Math.floor(minutes / 2) * 60000;
    for (let i = 0; i < 300; i++) {
      entries.push({
        timestamp: new Date(spikeStart + Math.floor(rnd() * 30000)).toISOString(),
        sourceIp: '203.0.113.7',
        destIp,
        destPort: 80,
        method: 'GET',
        path: '/',
        statusCode: 200,
        bytes: 500,
        protocol: 'tcp',
      });
    }
  }

  // Port scan: one IP hits many distinct ports within a few seconds.
  if (opts.includePortScan) {
    const scanStart = start + 60000;
    for (let p = 1; p <= 40; p++) {
      entries.push({
        timestamp: new Date(scanStart + p * 100).toISOString(),
        sourceIp: '198.51.100.23',
        destIp,
        destPort: p,
        protocol: 'tcp',
        flags: 'S',
      });
    }
  }

  // Brute force: repeated 401s against a login path from one IP.
  if (opts.includeBruteForce) {
    const bfStart = start + 120000;
    for (let i = 0; i < 25; i++) {
      entries.push({
        timestamp: new Date(bfStart + i * 1500).toISOString(),
        sourceIp: '203.0.113.66',
        destIp,
        destPort: 443,
        method: 'POST',
        path: '/api/auth/login',
        statusCode: 401,
        bytes: 0,
        protocol: 'tcp',
      });
    }
  }

  // SYN flood: a burst of bare SYNs from one IP within a couple of seconds.
  if (opts.includeSynFlood) {
    const synStart = start + 180000;
    for (let i = 0; i < 250; i++) {
      entries.push({
        timestamp: new Date(synStart + Math.floor(rnd() * 2000)).toISOString(),
        sourceIp: '203.0.113.99',
        destIp,
        destPort: 80,
        protocol: 'tcp',
        flags: 'S',
      });
    }
  }

  return entries.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
}
