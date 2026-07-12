/**
 * Dashboard aggregation — Module 5. Builds the DashboardSummary entirely from
 * real DB records via Mongo aggregations (no fabricated numbers).
 */
import { AssetModel } from '../../models/Asset.js';
import { VulnerabilityModel } from '../../models/Vulnerability.js';
import { ThreatEventModel } from '../../models/ThreatEvent.js';
import { IncidentModel } from '../../models/Incident.js';
import { riskBand } from '../vulnerability/risk.service.js';
import type { CountBucket, DashboardSummary, ThreatEvent } from '@cybernexus/shared';

function toBuckets(rows: Array<{ _id: string; count: number }>): CountBucket[] {
  return rows.filter((r) => r._id != null).map((r) => ({ key: r._id, count: r.count }));
}

export async function getSummary(): Promise<DashboardSummary> {
  const [
    assetTotal,
    scannable,
    heatmapRaw,
    vulnTotal,
    vulnOpen,
    vulnBySeverity,
    threatTotal,
    threatUnacked,
    threatByCategory,
    threatBySeverity,
    recentThreats,
    incidentTotal,
    incidentByStatus,
  ] = await Promise.all([
    AssetModel.countDocuments({}),
    AssetModel.countDocuments({ authorizedForScan: true }),
    AssetModel.find({}).sort({ riskScore: -1 }).limit(12).select('name ipAddress riskScore').lean(),
    VulnerabilityModel.countDocuments({}),
    VulnerabilityModel.countDocuments({ status: 'open' }),
    VulnerabilityModel.aggregate([{ $group: { _id: '$cvss.baseSeverity', count: { $sum: 1 } } }]),
    ThreatEventModel.countDocuments({}),
    ThreatEventModel.countDocuments({ acknowledged: false }),
    ThreatEventModel.aggregate([{ $group: { _id: '$category', count: { $sum: 1 } } }]),
    ThreatEventModel.aggregate([{ $group: { _id: '$severity', count: { $sum: 1 } } }]),
    ThreatEventModel.find({}).sort({ detectedAt: -1 }).limit(10).lean(),
    IncidentModel.countDocuments({}),
    IncidentModel.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }]),
  ]);

  return {
    assets: {
      total: assetTotal,
      scannable,
      heatmap: heatmapRaw.map((a) => ({
        _id: a._id.toString(),
        name: a.name,
        ipAddress: a.ipAddress,
        riskScore: a.riskScore,
        band: riskBand(a.riskScore),
      })),
    },
    vulnerabilities: {
      total: vulnTotal,
      open: vulnOpen,
      bySeverity: toBuckets(vulnBySeverity),
    },
    threats: {
      total: threatTotal,
      unacknowledged: threatUnacked,
      byCategory: toBuckets(threatByCategory),
      bySeverity: toBuckets(threatBySeverity),
      recent: recentThreats.map((t) => ({ ...t, _id: t._id.toString() }) as unknown as ThreatEvent),
    },
    incidents: {
      total: incidentTotal,
      byStatus: toBuckets(incidentByStatus),
    },
    generatedAt: new Date().toISOString(),
  };
}
