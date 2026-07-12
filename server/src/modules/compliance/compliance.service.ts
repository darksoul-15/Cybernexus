/**
 * Compliance aggregation (Module 8). Surfaces the audit trail written by the
 * audit() middleware and assembles a compliance report from real AuditLog +
 * Incident + evidence-chain data (no fabricated numbers).
 */
import { AuditLogModel } from '../../models/AuditLog.js';
import { IncidentModel } from '../../models/Incident.js';
import { verify as verifyEvidenceChain } from '../evidence/evidence.service.js';
import type { AuditLog, ComplianceReport, CountBucket } from '@cybernexus/shared';

function toBuckets(rows: Array<{ _id: string; count: number }>): CountBucket[] {
  return rows.filter((r) => r._id != null).map((r) => ({ key: r._id, count: r.count }));
}

export interface AuditQuery {
  actor?: string;
  action?: string;
  from?: string;
  to?: string;
  limit?: number;
  skip?: number;
}

function buildFilter(q: AuditQuery): Record<string, unknown> {
  const filter: Record<string, unknown> = {};
  if (q.actor) filter.actor = q.actor;
  if (q.action) filter.action = q.action;
  if (q.from || q.to) {
    const range: Record<string, Date> = {};
    if (q.from) range.$gte = new Date(q.from);
    if (q.to) range.$lte = new Date(q.to);
    filter.createdAt = range;
  }
  return filter;
}

export async function listAudit(q: AuditQuery = {}) {
  const filter = buildFilter(q);
  const [items, total] = await Promise.all([
    AuditLogModel.find(filter)
      .sort({ createdAt: -1 })
      .skip(q.skip ?? 0)
      .limit(Math.min(q.limit ?? 100, 500))
      .lean(),
    AuditLogModel.countDocuments(filter),
  ]);
  return { items, total };
}

export async function auditStats() {
  const [byAction, uniqueActors, total] = await Promise.all([
    AuditLogModel.aggregate([{ $group: { _id: '$action', count: { $sum: 1 } } }, { $sort: { count: -1 } }]),
    AuditLogModel.distinct('actor'),
    AuditLogModel.countDocuments({}),
  ]);
  return { total, uniqueActors: uniqueActors.filter(Boolean).length, byAction: toBuckets(byAction) };
}

export interface ReportOptions {
  from?: string;
  to?: string;
  generatedBy: { id: string; email: string } | null;
}

export async function buildReport(opts: ReportOptions): Promise<ComplianceReport> {
  const filter = buildFilter({ from: opts.from, to: opts.to });

  const [auditTotal, byAction, actors, recent, incidentTotal, byStatus, bySeverity, chain] = await Promise.all([
    AuditLogModel.countDocuments(filter),
    AuditLogModel.aggregate([{ $match: filter }, { $group: { _id: '$action', count: { $sum: 1 } } }, { $sort: { count: -1 } }]),
    AuditLogModel.distinct('actor', filter),
    AuditLogModel.find(filter).sort({ createdAt: -1 }).limit(25).lean(),
    IncidentModel.countDocuments({}),
    IncidentModel.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }]),
    IncidentModel.aggregate([{ $group: { _id: '$severity', count: { $sum: 1 } } }]),
    verifyEvidenceChain(),
  ]);

  return {
    generatedAt: new Date().toISOString(),
    generatedBy: opts.generatedBy,
    period: { from: opts.from, to: opts.to },
    audit: {
      total: auditTotal,
      uniqueActors: actors.filter(Boolean).length,
      byAction: toBuckets(byAction),
      recent: recent.map((r) => ({ ...r, _id: r._id.toString() }) as unknown as AuditLog),
    },
    incidents: {
      total: incidentTotal,
      byStatus: toBuckets(byStatus),
      bySeverity: toBuckets(bySeverity),
    },
    evidence: {
      chainValid: chain.valid,
      length: chain.length,
      headHash: chain.headHash,
    },
  };
}
