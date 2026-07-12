import dotenv from 'dotenv';
dotenv.config();

function required(name: string, fallback?: string): string {
  const v = process.env[name] ?? fallback;
  if (v === undefined) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return v;
}

export const env = {
  mongoUri: required('MONGODB_URI'),
  jwtSecret: required('JWT_SECRET'),
  jwtExpiresIn: process.env.JWT_EXPIRES_IN ?? '1d',
  port: Number(process.env.PORT ?? 4000),
  clientOrigin: process.env.CLIENT_ORIGIN ?? 'http://localhost:5173',
  authorizedScanRanges: (process.env.AUTHORIZED_SCAN_RANGES ?? '127.0.0.1/32')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
  // Module 4 — Threat Intelligence free-tier API keys (optional; lookups degrade
  // gracefully to "unknown" when a key is absent rather than fabricating data).
  abuseipdbApiKey: process.env.ABUSEIPDB_API_KEY ?? '',
  virustotalApiKey: process.env.VIRUSTOTAL_API_KEY ?? '',
  isProd: process.env.NODE_ENV === 'production',
} as const;
