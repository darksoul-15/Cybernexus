/**
 * Minimal SMTP mailer, mirroring incident/alert.service.ts's transporter
 * pattern. Degrades gracefully: with no SMTP config, isMailerConfigured()
 * reports false and sendMail() is a no-op returning false — callers must
 * never claim delivery that did not happen.
 */
import nodemailer, { type Transporter } from 'nodemailer';
import { env } from '../config/env.js';

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

export function isMailerConfigured(): boolean {
  return getTransporter() !== null;
}

export interface SendMailInput {
  to: string;
  subject: string;
  text: string;
}

/** Sends via SMTP. Returns false (never throws) when unconfigured or on failure. */
export async function sendMail(input: SendMailInput): Promise<boolean> {
  const t = getTransporter();
  if (!t) return false;
  try {
    await t.sendMail({ from: env.smtp.from, to: input.to, subject: input.subject, text: input.text });
    return true;
  } catch (e) {
    console.error('[mailer] send failed:', e);
    return false;
  }
}
