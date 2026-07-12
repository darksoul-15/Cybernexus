import type { Request, Response, NextFunction } from 'express';
import * as svc from './compliance.service.js';
import { generateReportPdf } from './pdf.service.js';

function str(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

export async function listAudit(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const result = await svc.listAudit({
      actor: str(req.query.actor),
      action: str(req.query.action),
      from: str(req.query.from),
      to: str(req.query.to),
      limit: req.query.limit ? Number(req.query.limit) : undefined,
      skip: req.query.skip ? Number(req.query.skip) : undefined,
    });
    res.json(result);
  } catch (e) {
    next(e);
  }
}

export async function auditStats(_req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    res.json(await svc.auditStats());
  } catch (e) {
    next(e);
  }
}

function reportOptions(req: Request) {
  return {
    from: str(req.query.from),
    to: str(req.query.to),
    generatedBy: req.user ? { id: req.user.sub, email: req.user.email } : null,
  };
}

export async function report(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    res.json(await svc.buildReport(reportOptions(req)));
  } catch (e) {
    next(e);
  }
}

export async function reportPdf(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const data = await svc.buildReport(reportOptions(req));
    const pdf = await generateReportPdf(data);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="cybernexus-compliance-${Date.now()}.pdf"`);
    res.send(pdf);
  } catch (e) {
    next(e);
  }
}
