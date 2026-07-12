/**
 * PDF compliance report generator (Module 8). Renders a ComplianceReport into a
 * PDF using pdfkit (built-in Helvetica, no font files needed). Returns a Buffer
 * so it is equally usable for HTTP streaming and for tests.
 */
import PDFDocument from 'pdfkit';
import type { ComplianceReport, CountBucket } from '@cybernexus/shared';

const INK = '#1a2230';
const ACCENT = '#0b7a6e';
const MUTED = '#666666';

export function generateReportPdf(report: ComplianceReport): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50, size: 'A4' });
    const chunks: Buffer[] = [];
    doc.on('data', (c: Buffer) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    // Header
    doc.fillColor(ACCENT).fontSize(22).font('Helvetica-Bold').text('CYBERNEXUS X');
    doc.fillColor(INK).fontSize(15).text('Security Compliance Report');
    doc.moveDown(0.3);
    doc.fillColor(MUTED).fontSize(9).font('Helvetica')
      .text(`Generated: ${new Date(report.generatedAt).toUTCString()}`)
      .text(`By: ${report.generatedBy?.email ?? 'system'}`);
    if (report.period.from || report.period.to) {
      doc.text(`Period: ${report.period.from ?? 'beginning'} → ${report.period.to ?? 'now'}`);
    }
    divider(doc);

    // Evidence integrity attestation — the headline compliance statement.
    section(doc, 'Evidence Integrity Attestation');
    doc.fontSize(10).font('Helvetica').fillColor(INK);
    doc.fillColor(report.evidence.chainValid ? '#0a7d33' : '#c0271e').font('Helvetica-Bold')
      .text(report.evidence.chainValid ? '● CHAIN VERIFIED — no tampering detected' : '● CHAIN INVALID — tampering detected');
    doc.fillColor(MUTED).font('Helvetica').fontSize(9)
      .text(`Records: ${report.evidence.length}   Head hash: ${report.evidence.headHash ?? '(empty chain)'}`);
    doc.moveDown(0.5);

    // Audit summary
    section(doc, 'Audit Trail Summary');
    doc.fontSize(10).font('Helvetica').fillColor(INK)
      .text(`Total audited actions: ${report.audit.total}`)
      .text(`Distinct actors: ${report.audit.uniqueActors}`);
    doc.moveDown(0.3);
    kvTable(doc, 'Actions by type', report.audit.byAction);

    // Incidents
    section(doc, 'Incident Summary');
    doc.fontSize(10).font('Helvetica').fillColor(INK).text(`Total incidents: ${report.incidents.total}`);
    doc.moveDown(0.2);
    kvTable(doc, 'By status', report.incidents.byStatus);
    kvTable(doc, 'By severity', report.incidents.bySeverity);

    // Recent audit events table
    section(doc, 'Recent Audited Events');
    doc.fontSize(8).fillColor(MUTED).font('Helvetica-Bold')
      .text('When'.padEnd(26) + 'Actor'.padEnd(26) + 'Action'.padEnd(22) + 'Status');
    doc.font('Helvetica').fillColor(INK);
    for (const e of report.audit.recent.slice(0, 20)) {
      const when = new Date(e.createdAt).toISOString().replace('T', ' ').slice(0, 19);
      const actor = (e.actorEmail ?? 'anonymous').slice(0, 24);
      const action = e.action.slice(0, 20);
      doc.text(when.padEnd(26) + actor.padEnd(26) + action.padEnd(22) + String(e.statusCode));
    }

    doc.moveDown(1);
    doc.fontSize(8).fillColor(MUTED).font('Helvetica')
      .text('This report is generated from immutable audit records and a SHA-256 hash-chained evidence ledger. All figures trace to real database records.', { align: 'center' });

    doc.end();
  });
}

function divider(doc: PDFKit.PDFDocument): void {
  doc.moveDown(0.5);
  doc.strokeColor('#cccccc').lineWidth(1).moveTo(50, doc.y).lineTo(545, doc.y).stroke();
  doc.moveDown(0.5);
}

function section(doc: PDFKit.PDFDocument, title: string): void {
  doc.moveDown(0.6);
  doc.fillColor(ACCENT).fontSize(12).font('Helvetica-Bold').text(title);
  doc.moveDown(0.2);
}

function kvTable(doc: PDFKit.PDFDocument, label: string, rows: CountBucket[]): void {
  doc.fontSize(9).fillColor(MUTED).font('Helvetica-Oblique').text(label);
  doc.font('Helvetica').fillColor(INK).fontSize(9);
  if (rows.length === 0) {
    doc.text('  (none)');
    return;
  }
  for (const r of rows) {
    doc.text(`  ${r.key.padEnd(28, '.')} ${r.count}`);
  }
  doc.moveDown(0.2);
}
