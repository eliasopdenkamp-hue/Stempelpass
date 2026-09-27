-- 021: visible card code on every card (owner wish 2026-09-24).
--
-- Every card gets a short, human-readable, tenant-unique code used purely as
-- an identification aid at the register and on the customer-visible surfaces
-- (webcard, Google Wallet pass, staff dashboard). It encodes NO data and grants
-- NO permission: stamping still requires an authenticated staff session; the
-- staff code search resolves only inside the caller's tenant RLS transaction.
--
-- Format: 6 characters from a confusion-safe alphabet (0/O/1/I excluded),
-- displayed with the K- prefix (e.g. K-7F3D2A). The DATABASE stores only the
-- bare 6-char code; the prefix is a display concern (src/card-code.ts).
-- Uniqueness is enforced per tenant by cards_tenant_card_code_key.

alter table cards add column card_code text;

-- Backfill EVERY existing card (active, archived and soft-deleted rows alike —
-- the unique index covers all of them) with a tenant-unique code. The DO block
-- runs as the migration role (table owner → RLS bypassed, no FORCE ROW LEVEL
-- SECURITY anywhere), exactly like the other data migrations. Collisions are
-- retried per candidate; the 32^6 namespace makes the retry loop exit quasi-
-- always on the first candidate.
do $$
declare
  r record;
  candidate text;
  alphabet constant text := '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  chars constant integer := 6;
begin
  for r in select id, tenant_id from cards where card_code is null loop
    loop
      candidate := '';
      for i in 1..chars loop
        candidate := candidate || substr(alphabet, 1 + (random() * length(alphabet))::integer, 1);
      end loop;
      exit when not exists (select 1 from cards where tenant_id = r.tenant_id and card_code = candidate);
    end loop;
    update cards set card_code = candidate where id = r.id;
  end loop;
end
$$;

alter table cards alter column card_code set not null;
alter table cards add constraint cards_tenant_card_code_key unique (tenant_id, card_code);
comment on column cards.card_code is 'Tenant-unique visible card code (6 chars, confusion-safe alphabet, stored without the K- display prefix); identification only, never a permission.';