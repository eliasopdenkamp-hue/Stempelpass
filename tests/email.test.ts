import { describe, expect, test } from 'bun:test';
import { SmtpEmailAdapter, smtpConfiguration } from '../src/email';
import { CommunicationService, type CommunicationRepository } from '../src/communication';

const env = { EMAIL_SMTP_HOST: 'smtp.example.eu', EMAIL_SMTP_PORT: '587', EMAIL_SMTP_USER: 'user', EMAIL_SMTP_PASSWORD: 'secret', EMAIL_FROM: 'StempelPass <noreply@example.eu>', COMMUNICATION_HASH_SECRET: 'test-secret-that-is-at-least-32-chars' };
function repo(preference: any): CommunicationRepository {
  return { preference: async () => preference, log: async (_t: string, _c: string|null, _p: any, _m: string, _h: string, status: any) => ({ id: 'log', status }), setMarketingOptIn: async () => {}, withdrawMarketing: async () => {} } as unknown as CommunicationRepository;
}

describe('SMTP adapter and gated email delivery', () => {
  test('missing credentials remains not_configured', async () => {
    expect(smtpConfiguration({ EMAIL_SMTP_HOST: 'smtp.example', EMAIL_SMTP_PORT: '587' })).toBeNull();
    expect(await new SmtpEmailAdapter({}).send({ to: 'a@example.test', subject: 'x' })).toEqual({ status: 'not_configured', failureCode: 'PROVIDER_NOT_CONFIGURED' });
  });
  test('valid policy sends through injected transport, never network', async () => {
    let sent: any;
    const adapter = new SmtpEmailAdapter(env, { sendMail: async (message) => { sent = message; } });
    const result = await new CommunicationService(repo({ optedIn: true, withdrawnAt: null }), true).sendEmail({ tenantId: 't', customerId: 'c', purpose: 'marketing', messageType: 'campaign', to: 'a@example.test', subject: 'Hello', text: 'Body' }, adapter);
    expect(result.status).toBe('sent');
    expect(sent.from).toContain('noreply@example.eu');
  });
  test('marketing without opt-in is blocked and transport is untouched', async () => {
    let calls = 0;
    const adapter = new SmtpEmailAdapter(env, { sendMail: async () => { calls++; } });
    const result = await new CommunicationService(repo(null), true).sendEmail({ tenantId: 't', customerId: 'c', purpose: 'marketing', messageType: 'campaign', to: 'a@example.test', subject: 'x' }, adapter);
    expect(result.status).toBe('blocked'); expect(calls).toBe(0);
  });
  test('withdrawal blocks marketing', async () => {
    const adapter = new SmtpEmailAdapter(env, { sendMail: async () => { throw new Error('must not send'); } });
    const result = await new CommunicationService(repo({ optedIn: false, withdrawnAt: 'now' }), true).sendEmail({ tenantId: 't', customerId: 'c', purpose: 'marketing', messageType: 'campaign', to: 'a@example.test', subject: 'x' }, adapter);
    expect(result.status).toBe('blocked'); expect(result.reason).toBe('marketing_withdrawn');
  });
});
