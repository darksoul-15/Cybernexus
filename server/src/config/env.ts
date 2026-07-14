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
  // AI Threat Analyst (Anthropic). Optional — the feature reports unavailable
  // (never fabricates) when the key is absent.
  anthropicApiKey: process.env.ANTHROPIC_API_KEY ?? '',
  aiModel: process.env.AI_MODEL ?? 'claude-sonnet-5',
  // Module 6 — Automated Incident Response.
  // Threats at/above this score auto-generate an incident.
  autoIncidentMinScore: Number(process.env.AUTO_INCIDENT_MIN_SCORE ?? 70),
  // Live mode records a 'live' block action instead of a simulated one.
  responseLiveMode: process.env.RESPONSE_LIVE_MODE === 'true',
  // Second, separate opt-in required to actually execute an OS firewall command.
  // Kept off by default so no disruptive action runs without explicit intent.
  responseAllowRealFirewall: process.env.RESPONSE_ALLOW_REAL_FIREWALL === 'true',
  // When true, the server also serves the built React client (single-service
  // deploy). Left false in local dev, where Vite serves the frontend.
  serveClient: process.env.SERVE_CLIENT === 'true',
  smtp: {
    host: process.env.SMTP_HOST ?? '',
    port: Number(process.env.SMTP_PORT ?? 587),
    user: process.env.SMTP_USER ?? '',
    pass: process.env.SMTP_PASS ?? '',
    from: process.env.ALERT_FROM ?? 'cybernexus-x@localhost',
    to: process.env.ALERT_TO ?? '',
  },
  isProd: process.env.NODE_ENV === 'production',
} as const;
