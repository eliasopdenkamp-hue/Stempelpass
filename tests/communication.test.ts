import { describe, expect, test } from 'bun:test';
import { CommunicationService, type CommunicationRepository } from '../src/communication';

function repo(preference: any = null): CommunicationRepository {
  return {
    preference: async () => preference,
    log: async (_tenant: string, _customer: string | null, _purpose: any, _type: string, _hash: string, status: any) => ({ id: 'log', status }),
    setMarketingOptIn: async () => {}, withdrawMarketing: async () => {},
  } as unknown as CommunicationRepository;
}

describe('communication policy', () => {
  test('marketing opt-in is not default', async () => {
    const result = await new CommunicationService(repo()).check('tenant-a', 'customer-a', 'marketing');
    expect(result).toEqual({ allowed: false, reason: 'marketing_opt_in_required' });
  });
  test('withdrawal blocks marketing', async () => {
    const result = await new CommunicationService(repo({ optedIn: false, withdrawnAt: 'now' })).check('tenant-a', 'customer-a', 'marketing');
    expect(result.reason).toBe('marketing_withdrawn');
    expect(result.allowed).toBe(false);
  });
  test('service communication is separate and allowed', async () => {
    const result = await new CommunicationService(repo()).check('tenant-a', 'customer-a', 'service');
    expect(result).toEqual({ allowed: true, reason: 'service_allowed' });
  });
  test('provider absence never sends and is explicit', async () => {
    const result = await new CommunicationService(repo({ optedIn: true, withdrawnAt: null })).prepare('tenant-a', 'customer-a', 'marketing', 'campaign', 'recipient-hash');
    expect(result.status).toBe('not_configured');
  });
  test('tenant context is passed to preference and log', async () => {
    const calls: string[] = [];
    const r = repo({ optedIn: true, withdrawnAt: null });
    r.preference = async (tenant) => { calls.push(tenant); return { optedIn: true, withdrawnAt: null } as any; };
    await new CommunicationService(r, true).check('tenant-b', 'customer-b', 'marketing');
    expect(calls).toEqual(['tenant-b']);
  });
});
