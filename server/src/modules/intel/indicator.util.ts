/** Indicator validation + classification for reputation lookups. */
import type { IndicatorType } from '@cybernexus/shared';

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
// FQDN: one or more labels, then an alphabetic TLD (>=2 letters). The alphabetic
// TLD requirement is what prevents dotted-numeric strings (e.g. an out-of-range
// "999.1.1.1") from being misclassified as a domain.
const DOMAIN_RE =
  /^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$/;

export function isIpv4(s: string): boolean {
  const m = s.match(IPV4_RE);
  if (!m) return false;
  return m.slice(1).every((o) => Number(o) >= 0 && Number(o) <= 255);
}

export function isDomain(s: string): boolean {
  return DOMAIN_RE.test(s);
}

/** Classify an indicator as ip/domain, or null if it is neither. */
export function classifyIndicator(raw: string): IndicatorType | null {
  const s = raw.trim().toLowerCase();
  if (isIpv4(s)) return 'ip';
  if (isDomain(s)) return 'domain';
  return null;
}
