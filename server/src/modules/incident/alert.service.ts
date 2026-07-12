/**
 * Alerting. Sends an email via nodemailer when SMTP is configured, and always
 * raises an in-app notification over Socket.io. Degrades gracefully: with no
 * SMTP config, only the in-app alert fires (no error, no fabricated delivery).
 */
import nodemailer, { type Transporter } from 'nodemailer';
import { env } from '../../config/env.js';
import { emitIncident } from '../../realtime/bus.js';
import type { IncidentDoc } from '../../models/Incident.js';

let transporter: Transporter | null = null;
let transporterTried = false;

function getTransporter(): Transporter | null {
  if (transporterTried) return transporter;
  transporterTried = true;
  if (!env.smtp.host) return null;
  transporter = nodemailer.createTransport({
    host: env.smtp.host,
    port: env.smtp.port,
    secure: env.smtp.port === 465,
    auth: env.smtp.user ? { user: env.smtp.user, pass: env.smtp.pass } : undefined,
  });
  return transporter;
}

export interface AlertResult {
  inApp: boolean;
  email: boolean;
  detail: string;
}

export async function sendIncidentAlert(incident: IncidentDoc): Promise<AlertResult> {
  // In-app notification (always) — pushed live to connected dashboards.
  emitIncident({
    _id: incident._id.toString(),
    title: incident.title,
    severity: incident.severity,
    status: incident.status,
    openedAt: incident.openedAt,
  });

  const t = getTransporter();
  if (!t || !env.smtp.to) {
    return { inApp: true, email: false, detail: 'in-app only (SMTP not configured)' };
  }

  try {
    await t.sendMail({
      from: env.smtp.from,
      to: env.smtp.to,
      subject: `[CYBERNEXUS X] ${incident.severity.toUpperCase()} incident: ${incident.title}`,
      text: `${incident.summary}\n\nStatus: ${incident.status}\nOpened: ${incident.openedAt.toISOString()}`,
    });
    return { inApp: true, email: true, detail: `emailed ${env.smtp.to}` };
  } catch (e) {
    return { inApp: true, email: false, detail: `email failed: ${(e as Error).message}` };
  }
}
