import { test, expect } from 'bun:test';
import { DemoStore } from './store';
test('demo flow enforces reward threshold',()=>{const s=new DemoStore();const {card,token}=s.createCard('demo-tenant','customer-1');expect(s.publicCard(token)?.tenantId).toBe('demo-tenant');for(let i=0;i<9;i++)s.stamp('demo-tenant',card.id,1,String(i));expect(s.rewards.size).toBe(0);s.stamp('demo-tenant',card.id,1,'last');expect(s.rewards.size).toBe(1)});
test('foreign tenant cannot stamp card',()=>{const s=new DemoStore();const {card}=s.createCard('demo-tenant','customer-1');expect(()=>s.stamp('other',card.id,1,'x')).toThrow('CARD_NOT_FOUND')});
