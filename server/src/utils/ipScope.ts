/**
 * Network-scope authorization. Enforces the project rule that scanning is only
 * ever allowed against localhost / explicitly whitelisted private ranges.
 * Targets outside AUTHORIZED_SCAN_RANGES are rejected before any socket opens.
 *
 * IPv4 only (sufficient for localhost/private-range scanning). IPv6 targets are
 * rejected as out-of-scope rather than silently allowed.
 */
import { env } from '../config/env.js';

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let acc = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n < 0 || n > 255) return null;
    acc = (acc << 8) | n;
  }
  return acc >>> 0;
}

interface Cidr {
  base: number;
  mask: number;
}

function parseCidr(cidr: string): Cidr | null {
  const [ip, bitsRaw] = cidr.split('/');
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  const base = ipv4ToInt(ip);
  if (base === null) return null;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { base: (base & mask) >>> 0, mask };
}

/** Normalize a target: resolve the "localhost" alias to 127.0.0.1. */
export function normalizeTarget(target: string): string {
  const t = target.trim().toLowerCase();
  if (t === 'localhost') return '127.0.0.1';
  return target.trim();
}

export interface ScopeCheck {
  allowed: boolean;
  reason?: string;
  normalized: string;
}

/** True only if `target` falls inside one of the configured authorized CIDRs. */
export function isTargetAuthorized(target: string): ScopeCheck {
  const normalized = normalizeTarget(target);
  const ipInt = ipv4ToInt(normalized);
  if (ipInt === null) {
    return { allowed: false, normalized, reason: 'Target is not a valid IPv4 address (IPv6/hostnames are out of scope)' };
  }
  for (const cidr of env.authorizedScanRanges) {
    const parsed = parseCidr(cidr);
    if (!parsed) continue;
    if (((ipInt & parsed.mask) >>> 0) === parsed.base) {
      return { allowed: true, normalized };
    }
  }
  return {
    allowed: false,
    normalized,
    reason: `Target ${normalized} is outside authorized scan ranges (${env.authorizedScanRanges.join(', ')})`,
  };
}
