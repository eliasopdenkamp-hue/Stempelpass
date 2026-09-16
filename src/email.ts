import nodemailer, { type Transporter } from 'nodemailer';
import { createHmac } from 'node:crypto';
import { esc } from './staff-ui.js';

export type EmailConfiguration = {
  host: string;
  port: number;
  user: string;
  password: string;
  from: string;
};

export type EmailTransport = {
  sendMail(message: { from: string; to: string; subject: string; text?: string; html?: string }): Promise<unknown>;
};

/** Reads SMTP settings from environment. No defaults or credentials are invented. */
export function smtpConfiguration(env: NodeJS.ProcessEnv = process.env): EmailConfiguration | null {
  const host = env.EMAIL_SMTP_HOST?.trim();
  const user = env.EMAIL_SMTP_USER?.trim();
  const password = env.EMAIL_SMTP_PASSWORD;
  const from = env.EMAIL_FROM?.trim();
  const port = Number(env.EMAIL_SMTP_PORT || '');
  if (!host || !user || !password || !from || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host, port, user, password, from };
}

export type EmailSendResult = { status: 'not_configured' | 'sent' | 'failed'; failureCode?: string };

/** Provider-neutral SMTP implementation. The transport can be injected for tests. */
export class SmtpEmailAdapter {
  readonly configured: boolean;
  private readonly config: EmailConfiguration | null;
  private readonly transport: EmailTransport;
  private readonly env: NodeJS.ProcessEnv;

  constructor(env: NodeJS.ProcessEnv = process.env, transport?: EmailTransport) {
    this.env = env;
    this.config = smtpConfiguration(env);
    this.configured = Boolean(this.config);
    this.transport = transport ?? (this.config ? nodemailer.createTransport({
      host: this.config.host, port: this.config.port, secure: this.config.port === 465,
      auth: { user: this.config.user, pass: this.config.password },
    }) as unknown as Transporter : { sendMail: async () => undefined });
  }

  recipientHash(email: string): string | null {
    return recipientHash(email, this.env);
  }

  async send(input: { to: string; subject: string; text?: string; html?: string }): Promise<EmailSendResult> {
    if (!this.config) return { status: 'not_configured', failureCode: 'PROVIDER_NOT_CONFIGURED' };
    try {
      await this.transport.sendMail({ from: this.config.from, to: input.to, subject: input.subject, text: input.text, html: input.html });
      return { status: 'sent' };
    } catch {
      // Deliberately do not include provider errors: they may contain addresses or message data.
      return { status: 'failed', failureCode: 'PROVIDER_SEND_FAILED' };
    }
  }
}

/** The only accepted secret for recipient pseudonymisation. Never use a public hash. */
export function communicationHashSecret(env: NodeJS.ProcessEnv = process.env): string | null {
  const secret = env.COMMUNICATION_HASH_SECRET;
  return secret && secret.length >= 32 ? secret : null;
}

/** Returns a keyed, non-reversible recipient pseudonym, or null when not configured. */
export function recipientHash(email: string, env: NodeJS.ProcessEnv = process.env): string | null {
  const secret = communicationHashSecret(env);
  if (!secret) return null;
  return createHmac('sha256', secret).update(email.trim().toLowerCase()).digest('hex');
}

/**
 * Self-service password-reset mail (plain text). The reset link embeds the RAW
 * one-time token (43-char base64url); it reaches only the account owner's
 * mailbox and is treated as a Bearer secret by GET /reset/:token and
 * POST /api/auth/reset/confirm.
 */
export function passwordResetEmailText(resetLink: string): string {
  return 'Passwort zurücksetzen\n\n'
    + 'Sie haben ein Zurücksetzen Ihres Passworts angefordert. Der Link ist 60 Minuten gültig:\n'
    + resetLink
    + '\n\nFalls Sie das nicht angefordert haben, ignorieren Sie diese E-Mail. Ihr Passwort bleibt unverändert.\n';
}

/** Self-service password-reset mail (HTML). Every dynamic value is HTML-escaped. */
export function passwordResetEmailHtml(resetLink: string): string {
  const safe = esc(resetLink);
  return '<!doctype html><html lang="de"><body style="font:16px system-ui,sans-serif;color:#172033;background:#f8fafc;padding:2rem">'
    + '<div style="max-width:32rem;margin:auto;background:#fff;padding:2rem;border-radius:1rem;border-top:.5rem solid #155e75">'
    + '<h1 style="font-size:1.25rem;margin:0 0 .5rem">Passwort zurücksetzen</h1>'
    + '<p>Sie haben ein Zurücksetzen Ihres Passworts angefordert. Der Link ist <strong>60 Minuten</strong> gültig.</p>'
    + '<p><a href="' + safe + '" style="display:inline-block;background:#155e75;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:.65rem;font-weight:600">Passwort zurücksetzen</a></p>'
    + '<p>Falls Sie das nicht angefordert haben, ignorieren Sie diese E-Mail. Ihr Passwort bleibt unverändert.</p>'
    + '<p style="font-size:.8rem;color:#475569">StempelPass Deutschland</p>'
    + '</div></body></html>';
}
