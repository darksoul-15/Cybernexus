import type { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import * as threatService from './threat.service.js';
import { generateSampleLogs } from './sampleLogs.js';
import { HttpError } from '../../middleware/error.js';

const configSchema = z
  .object({
    rateWindowSec: z.number().positive().optional(),
    rateZThreshold: z.number().positive().optional(),
    rateMinCount: z.number().positive().optional(),
    portScanWindowSec: z.number().positive().optional(),
    portScanDistinctPorts: z.number().positive().optional(),
    bruteForceWindowSec: z.number().positive().optional(),
    bruteForceAttempts: z.number().positive().optional(),
    synFloodWindowSec: z.number().positive().optional(),
    synFloodCount: z.number().positive().optional(),
  })
  .optional();

const ingestSchema = z.object({
  format: z.enum(['combined', 'common', 'json']),
  data: z.union([z.string(), z.array(z.unknown())]),
  config: configSchema,
});

export async function ingest(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const parsed = ingestSchema.safeParse(req.body);
    if (!parsed.success) throw new HttpError(400, 'Validation failed', parsed.error.flatten());
    const summary = await threatService.ingestAndDetect(parsed.data);
    res.status(201).json(summary);
  } catch (e) {
    next(e);
  }
}

// Demo helper: generate synthetic logs with embedded attacks, then detect.
const sampleSchema = z.object({
  includeRateSpike: z.boolean().optional(),
  includePortScan: z.boolean().optional(),
  includeBruteForce: z.boolean().optional(),
  includeSynFlood: z.boolean().optional(),
  destIp: z.string().optional(),
  seed: z.number().optional(),
});

export async function ingestSample(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const parsed = sampleSchema.safeParse(req.body ?? {});
    if (!parsed.success) throw new HttpError(400, 'Validation failed', parsed.error.flatten());
    const opts = {
      includeRateSpike: true,
      includePortScan: true,
      includeBruteForce: true,
      includeSynFlood: true,
      ...parsed.data,
    };
    const logs = generateSampleLogs(opts);
    const summary = await threatService.ingestAndDetect({ data: logs, format: 'json' });
    res.status(201).json({ ...summary, sampleEntries: logs.length });
  } catch (e) {
    next(e);
  }
}

export async function list(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const ack = req.query.acknowledged;
    res.json({
      threats: await threatService.listThreats({
        category: typeof req.query.category === 'string' ? req.query.category : undefined,
        severity: typeof req.query.severity === 'string' ? req.query.severity : undefined,
        acknowledged: ack === 'true' ? true : ack === 'false' ? false : undefined,
        limit: req.query.limit ? Number(req.query.limit) : undefined,
      }),
    });
  } catch (e) {
    next(e);
  }
}

export async function acknowledge(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const updated = await threatService.acknowledgeThreat(req.params.id);
    if (!updated) throw new HttpError(404, 'ThreatEvent not found');
    res.json({ threat: updated });
  } catch (e) {
    next(e);
  }
}

export async function stats(_req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    res.json(await threatService.threatStats());
  } catch (e) {
    next(e);
  }
}
