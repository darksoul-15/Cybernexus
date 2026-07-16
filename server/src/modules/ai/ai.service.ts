/**
 * AI Threat Analyst. Sends recently detected ThreatEvents to Claude and returns
 * a schema-validated assessment (severity, attack narrative, recommended
 * actions). The deterministic detectors remain the source of truth — this layer
 * reasons over their real output. Degrades gracefully (available:false) when no
 * ANTHROPIC_API_KEY is set; never fabricates threats.
 */
import Anthropic from '@anthropic-ai/sdk';
import { env } from '../../config/env.js';
import { ThreatEventModel } from '../../models/ThreatEvent.js';
import type { AiAnalysisResponse, AiThreatAssessment } from '@cybernexus/shared';

// JSON Schema the model must fill. Structured outputs guarantee the response
// validates against it (all objects need additionalProperties:false + required).
const ASSESSMENT_SCHEMA = {
  type: 'object',
  properties: {
    severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
    headline: { type: 'string' },
    attackNarrative: { type: 'string' },
    correlatedIps: { type: 'array', items: { type: 'string' } },
    recommendedActions: { type: 'array', items: { type: 'string' } },
    confidence: { type: 'number' },
  },
  required: ['severity', 'headline', 'attackNarrative', 'correlatedIps', 'recommendedActions', 'confidence'],
  additionalProperties: false,
} as const;

const SYSTEM_PROMPT = `You are a senior Security Operations Center (SOC) analyst.
You are given a list of security threats that were already detected by automated
statistical and signature-based systems. Produce a concise, actionable assessment.
Rules:
- Base your analysis strictly on the provided detections. Do not invent threats,
  IPs, or events that are not in the data.
- attackNarrative: explain in 2-4 sentences what the attacker appears to be doing.
- recommendedActions: 3-6 concrete, prioritized response steps.
- confidence: 0-100, reflecting how strongly the data supports your assessment.`;

let client: Anthropic | null = null;
function getClient(): Anthropic | null {
  if (!env.anthropicApiKey) return null;
  if (!client) client = new Anthropic({ apiKey: env.anthropicApiKey, timeout: 30000 });
  return client;
}

/**
 * Map an Anthropic SDK exception to an actionable, non-technical message.
 * The full error is always logged server-side; only a clean summary reaches the client.
 */
function friendlyAiError(e: unknown): string {
  console.error('[ai.analyze] Anthropic API error:', e);

  if (e instanceof Anthropic.AuthenticationError) {
    return 'AI service authentication failed — check that ANTHROPIC_API_KEY is set correctly on the server.';
  }
  if (e instanceof Anthropic.PermissionDeniedError) {
    return 'AI service permission denied — this API key does not have access to the configured model.';
  }
  if (e instanceof Anthropic.RateLimitError) {
    return 'AI service is rate-limited right now — try again in a moment.';
  }
  if (e instanceof Anthropic.BadRequestError) {
    if (/credit balance/i.test(e.message)) {
      return 'AI service unavailable — the connected Anthropic account has no API credit. Add billing at console.anthropic.com to enable AI analysis.';
    }
    return 'AI service rejected the request — the account or model configuration may need attention.';
  }
  if (e instanceof Anthropic.APIConnectionError) {
    return 'Could not reach the AI service — network error contacting Anthropic.';
  }
  if (e instanceof Anthropic.APIError) {
    return `AI service error (HTTP ${e.status ?? '?'}) — see server logs for details.`;
  }
  return 'AI analysis failed unexpectedly — see server logs for details.';
}

/** Compact, deterministic text summary of the threats for the prompt. */
export function buildThreatSummary(
  threats: Array<{ category: string; severity: string; sourceIp?: string | null; score: number; description: string; detectedAt?: Date }>
): string {
  const lines = threats.map((t, i) => {
    const when = t.detectedAt ? new Date(t.detectedAt).toISOString() : 'n/a';
    return `${i + 1}. [${t.severity}] ${t.category} from ${t.sourceIp ?? 'unknown'} (score ${t.score}, ${when}): ${t.description}`;
  });
  return `Detected threats (${threats.length}):\n${lines.join('\n')}`;
}

export async function analyzeRecentThreats(limit = 25): Promise<AiAnalysisResponse> {
  const anthropic = getClient();
  if (!anthropic) {
    return { available: false, error: 'ANTHROPIC_API_KEY not configured' };
  }

  const threats = await ThreatEventModel.find()
    .sort({ detectedAt: -1 })
    .limit(Math.min(limit, 100))
    .select('category severity sourceIp score description detectedAt')
    .lean();

  if (threats.length === 0) {
    return { available: true, model: env.aiModel, analyzedThreats: 0, error: 'No detected threats to analyze yet.' };
  }

  const summary = buildThreatSummary(threats as never);

  try {
    const res = await anthropic.messages.create({
      model: env.aiModel,
      max_tokens: 2048,
      thinking: { type: 'disabled' }, // structured extraction — keep it fast/cheap
      output_config: { format: { type: 'json_schema', schema: ASSESSMENT_SCHEMA } },
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: summary }],
    });

    if (res.stop_reason === 'refusal') {
      return { available: true, model: env.aiModel, analyzedThreats: threats.length, error: 'Model declined to analyze this input' };
    }
    const textBlock = res.content.find((b): b is Anthropic.TextBlock => b.type === 'text');
    const parsed = textBlock ? (JSON.parse(textBlock.text) as AiThreatAssessment) : null;
    if (!parsed) {
      return { available: true, model: env.aiModel, analyzedThreats: threats.length, error: 'Model did not return a valid assessment' };
    }
    return { available: true, model: env.aiModel, analyzedThreats: threats.length, assessment: parsed };
  } catch (e) {
    return { available: true, model: env.aiModel, analyzedThreats: threats.length, error: friendlyAiError(e) };
  }
}
