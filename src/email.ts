import nodemailer, { type Transporter } from 'nodemailer';
import { createHmac } from 'node:crypto';

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
