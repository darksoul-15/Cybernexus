/**
 * Automated Incident Response orchestration — Module 6 vertical slice:
 *   qualifying ThreatEvents → correlate into Incidents → alert → (gated) block.
 *
 * Correlation: threats sharing a source IP fold into one incident; threats with
 * no source IP become individual incidents. Incident severity = worst threat.
 */
import { Types, type HydratedDocument } from 'mongoose';
import { IncidentModel, type IncidentDoc } from '../../models/Incident.js';
import { ThreatEventModel } from '../../models/ThreatEvent.js';
import { BlockedIpModel } from './blockedIp.model.js';
import { sendIncidentAlert } from './alert.service.js';
import { applyBlock } from './firewall.service.js';
import { emitIncident } from '../../realtime/bus.js';
import { HttpError } from '../../middleware/error.js';
import type { AutoRespondResult, BlockResult, Severity } from '@cybernexus/shared';

const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function worstSeverity(sevs: Severity[]): Severity {
  return sevs.reduce((a, b) => (SEVERITY_RANK[b] > SEVERITY_RANK[a] ? b : a), 'info');
}

export interface AutoRespondOptions {
  userId: string;
  minScore?: number;
  autoBlock?: boolean; // block correlated source IPs (mode gated by env)
}

export async function autoRespond(opts: AutoRespondOptions & { minScore: number }): Promise<AutoRespondResult> {
  // Qualifying: unacknowledged, not yet linked to an incident, and either
  // high/critical severity or score at/above the configured threshold.
  const qualifying = await ThreatEventModel.find({
    acknowledged: false,
    incident: { $exists: false },
    $or: [{ severity: { $in: ['high', 'critical'] } }, { score: { $gte: opts.minScore } }],
  })
    .sort({ detectedAt: -1 })
    .lean();

  // Correlate: group by sourceIp; threats without a source IP stand alone.
  const groups = new Map<string, typeof qualifying>();
  for (const t of qualifying) {
    const key = t.sourceIp ?? `solo:${t._id.toString()}`;
    const arr = groups.get(key) ?? [];
    arr.push(t);
    groups.set(key, arr);
  }

  const incidents: HydratedDocument<IncidentDoc>[] = [];
  const blocks: BlockResult[] = [];
  let alertsSent = 0;

  for (const [key, threats] of groups) {
    const severity = worstSeverity(threats.map((t) => t.severity as Severity));
    const sourceIp = key.startsWith('solo:') ? undefined : key;
    const categories = [...new Set(threats.map((t) => t.category))];
    const relatedAsset = threats.find((t) => t.targetAsset)?.targetAsset;

    const incident = await IncidentModel.create({
      title: sourceIp
        ? `Correlated activity from ${sourceIp} (${categories.join(', ')})`
        : `${categories.join(', ')} threat`,
      status: 'new',
      severity,
      relatedThreats: threats.map((t) => t._id),
      relatedAsset,
      summary: `Auto-generated from ${threats.length} threat event(s): ${categories.join(', ')}.` +
        (sourceIp ? ` Source IP ${sourceIp}.` : ''),
      actions: [{ at: new Date(), by: new Types.ObjectId(opts.userId), action: `Auto-generated from ${threats.length} threat event(s)`, live: false }],
      openedAt: new Date(),
    });

    await ThreatEventModel.updateMany(
      { _id: { $in: threats.map((t) => t._id) } },
      { incident: incident._id }
    );

    const alert = await sendIncidentAlert(incident);
    if (alert.inApp || alert.email) alertsSent++;

    if (opts.autoBlock && sourceIp) {
      const result = await blockIp({ ip: sourceIp, reason: `Auto-response for incident ${incident._id.toString()}`, incidentId: incident._id.toString(), userId: opts.userId });
      blocks.push(result);
      incident.actions.push({ at: new Date(), by: new Types.ObjectId(opts.userId), action: `IP block (${result.mode}): ${sourceIp}`, live: result.enforced });
      await incident.save();
    }

    incidents.push(incident);
  }

  return {
    qualifyingThreats: qualifying.length,
    incidentsCreated: incidents.length,
    incidents: incidents.map((i) => i.toJSON() as unknown as AutoRespondResult['incidents'][number]),
    alertsSent,
    blocks,
  };
}

export interface BlockIpInput {
  ip: string;
  reason: string;
  incidentId?: string;
  userId: string;
}

export async function blockIp(input: BlockIpInput): Promise<BlockResult> {
  const result = await applyBlock(input.ip);
  await BlockedIpModel.findOneAndUpdate(
    { ip: input.ip, active: true },
    {
      ip: input.ip,
      mode: result.mode,
      enforced: result.enforced,
      reason: input.reason,
      incident: input.incidentId ? new Types.ObjectId(input.incidentId) : undefined,
      active: true,
      createdBy: new Types.ObjectId(input.userId),
    },
    { upsert: true }
  );
  return result;
}

export async function listIncidents(status?: string) {
  const filter = status ? { status } : {};
  return IncidentModel.find(filter).sort({ openedAt: -1 }).lean();
}

export async function getIncident(id: string) {
  const inc = await IncidentModel.findById(id).lean();
  if (!inc) throw new HttpError(404, 'Incident not found');
  return inc;
}

export async function updateIncident(id: string, patch: { status?: string; assignee?: string }, userId: string) {
  const inc = await IncidentModel.findById(id);
  if (!inc) throw new HttpError(404, 'Incident not found');
  if (patch.status) {
    inc.status = patch.status as IncidentDoc['status'];
    inc.actions.push({ at: new Date(), by: new Types.ObjectId(userId), action: `Status → ${patch.status}`, live: false });
    if (patch.status === 'resolved' || patch.status === 'closed') inc.resolvedAt = new Date();
  }
  if (patch.assignee) inc.assignee = new Types.ObjectId(patch.assignee);
  await inc.save();
  emitIncident({ _id: inc._id.toString(), title: inc.title, severity: inc.severity, status: inc.status, openedAt: inc.openedAt });
  return inc.toJSON();
}

export async function listBlocklist() {
  return BlockedIpModel.find({ active: true }).sort({ createdAt: -1 }).lean();
}
