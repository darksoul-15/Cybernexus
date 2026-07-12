/**
 * Log parsing. Converts raw access-log text (Apache/Nginx common & combined
 * formats) or JSON arrays into normalized LogEntry objects for the detector.
 * Lines that don't parse are counted as skipped — never fabricated.
 */
import type { LogEntry, LogFormat } from '@cybernexus/shared';

// Combined:  ip - - [date] "METHOD path proto" status bytes "ref" "ua"
// Common:    ip - - [date] "METHOD path proto" status bytes
const ACCESS_RE =
  /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)[^"]*"\s+(\d{3})\s+(\S+)/;

const MONTHS: Record<string, number> = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

/** Parse "10/Oct/2000:13:55:36 -0700" → ISO string, or null. */
export function parseClfDate(raw: string): string | null {
  const m = raw.match(/^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?$/);
  if (!m) return null;
  const [, dd, mon, yyyy, hh, mm, ss, tz] = m;
  const month = MONTHS[mon];
  if (month === undefined) return null;
  let offsetMs = 0;
  if (tz) {
    const sign = tz[0] === '-' ? -1 : 1;
    offsetMs = sign * (Number(tz.slice(1, 3)) * 60 + Number(tz.slice(3, 5))) * 60000;
  }
  const utc = Date.UTC(Number(yyyy), month, Number(dd), Number(hh), Number(mm), Number(ss)) - offsetMs;
  return new Date(utc).toISOString();
}

export interface ParseResult {
  entries: LogEntry[];
  skipped: number;
}

function parseAccessLog(text: string): ParseResult {
  const entries: LogEntry[] = [];
  let skipped = 0;
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const m = trimmed.match(ACCESS_RE);
    if (!m) {
      skipped++;
      continue;
    }
    const [, ip, dateRaw, method, path, status, bytesRaw] = m;
    const iso = parseClfDate(dateRaw);
    if (!iso) {
      skipped++;
      continue;
    }
    entries.push({
      timestamp: iso,
      sourceIp: ip,
      method,
      path,
      statusCode: Number(status),
      bytes: bytesRaw === '-' ? 0 : Number(bytesRaw),
      protocol: 'tcp',
    });
  }
  return { entries, skipped };
}

function coerceEntry(raw: any): LogEntry | null {
  if (!raw || typeof raw !== 'object') return null;
  if (typeof raw.sourceIp !== 'string') return null;
  const ts = raw.timestamp ? new Date(raw.timestamp) : null;
  if (!ts || Number.isNaN(ts.getTime())) return null;
  return {
    timestamp: ts.toISOString(),
    sourceIp: raw.sourceIp,
    destIp: typeof raw.destIp === 'string' ? raw.destIp : undefined,
    destPort: typeof raw.destPort === 'number' ? raw.destPort : undefined,
    method: typeof raw.method === 'string' ? raw.method : undefined,
    path: typeof raw.path === 'string' ? raw.path : undefined,
    statusCode: typeof raw.statusCode === 'number' ? raw.statusCode : undefined,
    bytes: typeof raw.bytes === 'number' ? raw.bytes : undefined,
    protocol: raw.protocol === 'udp' ? 'udp' : 'tcp',
    flags: typeof raw.flags === 'string' ? raw.flags : undefined,
  };
}

/** Parse ingest input into normalized entries. `data` is text (access logs) or an array (json). */
export function parseLogs(data: string | unknown[], format: LogFormat): ParseResult {
  if (format === 'json') {
    const arr = Array.isArray(data) ? data : [];
    const entries: LogEntry[] = [];
    let skipped = 0;
    for (const raw of arr) {
      const e = coerceEntry(raw);
      if (e) entries.push(e);
      else skipped++;
    }
    return { entries, skipped };
  }
  return parseAccessLog(typeof data === 'string' ? data : '');
}
