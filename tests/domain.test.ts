import { test, expect } from 'bun:test';
import { assertTenant, capacity, canStamp, PLAN_LIMITS } from '../src/domain';
test('plan limits are explicit',()=>expect(PLAN_LIMITS).toEqual({up_to_500:500,up_to_1000:1000}));
test('capacity never becomes negative',()=>expect(capacity({id:'t',slug:'t',planCode:'up_to_500',customerLimit:500},501).remaining).toBe(0));
test('tenant context rejects cross-tenant request',()=>expect(()=>assertTenant('a','b')).toThrow('TENANT_CONTEXT_REQUIRED'));
test('only operational roles stamp',()=>{expect(canStamp('staff')).toBe(true);expect(canStamp('viewer')).toBe(false)});
