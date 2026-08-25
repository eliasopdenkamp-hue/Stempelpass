# RLS/Auth-P1 Produktionsprüfung

## Teil A: Tenant-Kontext
`auth()` öffnet vor der Membership-Abfrage eine Transaktion, setzt `set_config('app.tenant_id', $1, true)` mit dem geprüften Tenant-Parameter und führt bei Erfolg `commit`, bei Fehler `rollback` und in jedem Fall `release` aus. Die bestehende Session-, Membership-, MFA-, CSRF- und Tenant-Prüfung bleibt bestehen.

## Teil B: MFA-Bootstrap (B1 — seit Migration 010 gelöst)

**Befund (vor 010):** Die tenantlose Login-MFA-Abfrage aggregierte direkt über
`tenant_memberships` (`bool_or` über Owner-/Admin-Memberships). Unter aktivem
RLS liefert ein SELECT ohne `app.tenant_id` auf der tenant-isolierten Tabelle
keine Zeilen → `bool_or` → NULL → der fail-closed-Guard
(`MFA_BOOTSTRAP_UNVERIFIED`) blockierte **jeden** Login.

**Lösung (Migration `010_membership_mfa_resolver.sql`):** Der Login nutzt für
den MFA-Bootstrap ausschließlich die minimalprivilegierte SECURITY-DEFINER-
Funktion `public.membership_mfa_required(p_user_id uuid) returns boolean`
(`select public.membership_mfa_required($1) as required`); die direkte
Tabellen-/Aggregat-Abfrage wurde entfernt. Sicherheitseigenschaften und
Verträge: Teil F.

**Fail-closed bleibt vollständig erhalten:**
- Funktion fehlt / DB-Fehler → Login schlägt fehl (INTERNAL_ERROR-Pfad).
- Ergebniszeile fehlt oder `required` ist nicht boolean (z. B. NULL von einer
  nicht-konformen Quelle) → `MFA_BOOTSTRAP_UNVERIFIED` → einheitlich
  `INVALID_CREDENTIALS` (400); es wird **nie** stillschweigend `required=false`.
- Die Funktion selbst liefert nie NULL (`EXISTS` ergibt true/false für jede
  Eingabe); ein Nutzer ohne aktive Owner-/Admin-Membership erhält bewusst
  `false` ("keine MFA-Pflicht") — nur ein tatsächlich fehlendes
  Funktion/Ergebnis wird fail-closed behandelt.

## Vor Produktivfreigabe zwingend prüfen (ohne Credentials)
Mit der tatsächlich verwendeten App-Rolle und einer separaten Admin-/Owner-Prüfung verifizieren:

- `rolbypassrls = false` in `pg_roles` für die App-Rolle.
- Die App-Rolle ist **kein** Owner der betroffenen Tabellen (insbesondere `users`, `tenant_memberships`, `sessions`), da Tabellenowner RLS umgehen kann.
- Explizite, minimale Grants sind vorhanden: erforderliche DML-/SELECT-Rechte für normale Transaktionen sowie `EXECUTE` nur auf ausdrücklich freigegebene Funktionen. Keine Superuser-, Bypass-RLS- oder unbeschränkten Tabellenrechte.
- RLS ist aktiv und erzwungen (`relrowsecurity`, bei Bedarf `relforcerowsecurity`) auf tenant-sensitiven Tabellen.
- MFA-Login muss mit einer nicht privilegierten Produktions-App-Rolle und Testdaten mit aktiviertem MFA tatsächlich Ende-zu-Ende geprüft werden; ein RLS-gefiltertes Ergebnis muss nicht als `false` akzeptiert werden.

Keine echten Secrets oder Wallet-Credentials gehören in diese Prüfung oder in das Repository.

## Runtime-Rolle und manuelle DB-Schritte nach Migration 014

Migration `014_app_role_grants.sql` ist bewusst nur ein **additiver Grant-Schritt**:
Wenn `app_role` bereits existiert, erhält sie `USAGE` auf `public`,
`SELECT/INSERT/UPDATE` auf `public.card_creation_idempotency` und `EXECUTE` auf
die drei Resolver-Funktionen. Fehlt die Rolle, wird nichts angelegt und nichts
geändert. Die Migration führt ausdrücklich **keine** Rollen-Downgrades,
Ownership-Änderungen oder Entzüge geerbter Rechte aus und kann sicher erneut
ausgeführt werden.

Vor dem Runtime-Deploy sind deshalb manuell, über eine getrennte Admin-/Owner-
Verbindung, alle folgenden Schritte nachzuweisen:

1. Eine dedizierte Runtime-Rolle provisionieren (oder `app_role` nur dann
   verwenden, wenn sie nachweislich dediziert und nicht privilegiert ist):
   `LOGIN`, kein `SUPERUSER`, `BYPASSRLS`, `CREATEROLE`, `CREATEDB` oder
   `REPLICATION`, keine unkontrollierten Rollenmitgliedschaften und kein Owner
   der App-Tabellen. Eine aktuell privilegierte/Owner-artige `app_role` darf
   **nicht** als Runtime-Rolle verwendet werden; gegebenenfalls ist eine neue
   Rolle anzulegen und die Grants für diesen Namen separat nachzuziehen.
2. Die Rolle als Tabellen-/Funktions- und Schema-Berechtigungsinhaber prüfen.
   Falls sie Tabellen besitzt, Ownership mit der Admin-Verbindung auf eine
   dedizierte Migrations-/Owner-Rolle übertragen. Die Sicherheitsprüfung darf
   dabei nicht durch automatische Änderungen in einer Anwendungsmigration
   ersetzt werden.
3. `014_app_role_grants.sql` mit der Migrationsrolle ausführen, sobald
   `app_role` vorhanden ist. Bei einer anders benannten Runtime-Rolle die
   entsprechenden fünf additiven Grants manuell für diese Rolle ausführen
   (Schema-`USAGE`, Idempotency-DML sowie die drei Resolver-`EXECUTE`-Grants).
4. Erst danach muss `DATABASE_URL` im Runtime-Environment auf die dedizierte,
   nicht privilegierte Runtime-Rolle zeigen — niemals auf die Admin-/Owner-
   Verbindung, die Migrationen oder Seeds ausführt. Mit `RLS_VERIFY_DATABASE_URL`
   (as-role und zusätzlich named-role) `rolbypassrls`, Owner-Risiko, RLS,
   Tabellen-DML und alle drei `EXECUTE`-Grants prüfen; ein privilegierter
   Verbindungs-String ist kein gültiger Ersatztest.

Beispiel für die manuelle, ausdrücklich zu prüfende Reihenfolge (nur mit einer
Admin-/Owner-Verbindung; Platzhalter nie unverändert ausführen):

```sql
-- 1) Ist-Zustand prüfen, bevor eine Rolle verändert wird.
select rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication
  from pg_roles where rolname = 'app_role';

-- 2) Nur nach expliziter Freigabe und Prüfung der Ownership/Memberships:
-- alter role app_role nosuperuser nobypassrls nocreaterole nocreatedb
--   noreplication noinherit;
-- revoke <breite_oder_unerwünschte_mitgliedschaft> from app_role;

-- 3) Additive Grants für eine bereits geprüfte app_role (014 macht dies
--    bedingt automatisch; bei einer neu benannten Runtime-Rolle manuell):
grant usage on schema public to app_role;
grant select, insert, update on table public.card_creation_idempotency to app_role;
grant execute on function public.resolve_entry_point(text) to app_role;
grant execute on function public.resolve_session_user(text) to app_role;
grant execute on function public.membership_mfa_required(uuid) to app_role;
```

Bei einer neuen, anders benannten Rolle müssen die fünf Grant-Anweisungen auf
diesen Namen angepasst werden; Migration 014 erteilt sie absichtlich nur an
den Namen `app_role`. Danach Ownership, Mitgliedschaften und die effektiven
Rechte nochmals mit `rls-verify` prüfen, bevor `DATABASE_URL` umgestellt wird.

Die konkreten Rollennamen, Passwörter, Ownership-Änderungen und Provider-
Environment-Einträge bleiben bewusste Owner-/DB-Operator-Schritte; keine
Secrets werden dokumentiert oder committet.

## Teil C: Produktionsrollen-/RLS-Diagnose (opt-in, read-only, anonymisiert)

`src/rls-verify.ts` prüft gegen eine **explizit bereitgestellte** DB-Verbindung
nur anonymisierte Rollenmerkmale. Aufruf (Script `rls-verify` in
`package.json`):

```sh
# Variante A — as-role: mit der Verbindung DER APP-ROLLE selbst
RLS_VERIFY_DATABASE_URL='postgresql://app_role:...@host/db?sslmode=require' \
  bun run rls-verify

# Variante B — named-role: Admin-/Owner-Verbindung, prüft eine benannte Rolle
# (row_security_active ist hier nicht prüfbar und wird als null berichtet)
RLS_VERIFY_DATABASE_URL='postgresql://admin:...@host/db?sslmode=require' \
  RLS_VERIFY_ROLE='app_role' bun run rls-verify
```

Optional `RLS_VERIFY_SCHEMA` (Default `public`). Exit-Codes: `0` = alle
kritischen Checks bestanden, `1` = Prüfung fehlgeschlagen (oder Verbindung
fehlgeschlagen), `2` = nicht ausgeführt (Opt-in-Umgebungsvariable fehlt).

**Sicherheitsvertrag (nicht abschwächen):**
- Opt-in ist `RLS_VERIFY_DATABASE_URL`; es gibt **keinen** Fallback auf
  `DATABASE_URL`, ohne die Variable bricht das Tool mit Exit 2 ab.
- Read-only: eigene kurzlebige Verbindung (max 1), Transaktion läuft als
  **explizites** `BEGIN READ ONLY` (plain SQL, bewusst **nicht** der
  `sql.begin('read only', …)`-Helfer des Treibers — postgres.js führt nach dem
  Callback selbst COMMIT aus; ein fehlgeschlagener Check-Query ließ die
  Transaktion serverseitig abgebrochen zurück, der Treiber-COMMIT schlug dann
  mit 25P02 fehl und alles wurde fälschlich als `connect` gemeldet, obwohl die
  Rolle sich direkt anmelden konnte — genau der Neon-Befund). Zusätzlich wird
  `default_transaction_read_only=on` auf Session-Ebene gepinnt und
  `connect_timeout=30` (Neon-Autosuspend-Cold-Starts). Jede Anweisung ist ein
  reines SELECT auf Katalogsichten (`pg_roles`, `pg_class`, `pg_namespace`,
  `has_table_privilege`/`has_schema_privilege`/`row_security_active`). Keine
  Datentabelle wird gelesen, nichts wird geschrieben, kein DDL; bei
  Check-Fehlern wird explizit ROLLBACK ausgeführt, die Verbindung wird immer
  geschlossen.
- Anonymisiert: ausgegeben werden nur Booleans und klassifizierte Werte.
  `current_user` wird nie ausgegeben, Rollennamen nur als Bind-Parameter,
  die Verbindungs-URL (ggf. mit Passwort) wird nie geloggt oder zurückgegeben;
  Treiberfehler werden zu kurzen Codes (`connect`, `query:<schritt>`) reduziert.
- Kein Workaround: Gibt es (noch) keine separate Nicht-Owner-App-Rolle, liefert
  das Tool `ok:false` / `roleClass:"unverified"` und Exit ≠ 0 — es wird kein
  unsicherer Ersatz (Owner-Check, Rollen-Fabrication) implementiert.

**Geprüfte Merkmale** (Report-Felder): `roleBypassRls`, `roleSuperuser`,
`roleCanCreateRole/Db/Replication` (müssen false sein), `ownsAnyTable` +
`ownedTables` (Owner-Risiko), `rlsEnabledOnAllTenantTables` + `rlsMissing`
(`relrowsecurity` je Tenant-Tabelle), `rlsForcedOnAllTenantTables` +
`rlsInactiveForRole` (informational bzw. as-role; Migrationen setzen kein
FORCE ROW SECURITY), `grantsComplete` + `missingGrants` (gegen
`REQUIRED_GRANTS` sowie die drei erforderlichen Resolver-`EXECUTE`-Grants,
abgeleitet aus repository/server-Codepfaden), `missingFunctionGrants` für
die Resolver im Detail, `schemaUsage`/`schemaCreate` (CREATE nur
informational — nötig, solange die App-Rolle Start-Migrationen ausführt; für
Least Privilege Migrationen später auf eine separate Admin-Rolle verlagern),
`tablesMissing` (Schema unvollständig → Fail).

**Blocker (Stand dieser Revision):** Für eine echte Ende-zu-Ende-Verifikation
ist eine separate Nicht-Owner-/Nicht-BYPASSRLS-App-Rolle samt Verbindungsdaten
nötig, die in diesem Workspace **nicht** vorhanden ist (TEST_DATABASE_URL ist
die Neon-Verwaltungsverbindung, keine App-Rolle). Deshalb wurde bewusst **kein**
unsicherer Workaround implementiert; Tool und Unit-Tests
(`tests/rls-verify.test.ts`, 32 Nicht-DB-Tests) sind fertig und der
produktive Lauf ist der erste Schritt des Pilot-/Deployment-Prozesses, sobald
die App-Rolle angelegt ist (siehe `PILOT_ONBOARDING.md`/`TESTING.md`).

## Teil D: Öffentlicher Entry-Point-Resolver (`GET /join/:publicKey`)

`tenant_entry_points` ist seit Migration 006 per Tenant-Isolation-RLS
geschützt. Der unauthentifizierte `/join`-Einstieg hat **keinen** Tenant-Kontext
und darf `app.tenant_id` nicht setzen — ein direkter Tabellen-SELECT unter RLS
würde deshalb jede Zeile verstecken (Befund: gültige Public Keys wurden
unsichtbar). Lösung (Migration `008_entry_point_resolver.sql`): eine einzelne
minimalprivilegierte **SECURITY DEFINER**-Funktion

```sql
public.resolve_entry_point(p_public_key text) → table (tenant_id uuid, join_path text)
```

- **Sicherheitseigenschaften:** fester `search_path = pg_catalog`,
  vollqualifizierte Tabelle `public.tenant_entry_points` (kein
  search_path-abhängiges Auflösen), statisches SELECT ohne dynamisches SQL,
  Format-Guard (`^[a-f0-9]{32}`) als Defense in depth, `REVOKE ALL ... FROM
  PUBLIC` und expliziter `GRANT EXECUTE ... TO app_role` (bedingt via
  `DO`-Block, solange die Rolle fehlen kann; nach Rollenanlage ggf. einmalig
  ausführen: `grant execute on function public.resolve_entry_point(text) to
  app_role;`).
- **Minimalprinzip:** Die App-Rolle braucht **kein** Tabellen-SELECT auf
  `tenant_entry_points` — nur EXECUTE auf genau diese eine Funktion, die
  ausschließlich `tenant_id`/`join_path` für exakt den übergebenen Public Key
  liefert. `CardRepository.resolveEntryPoint` ruft ausschließlich
  `select tenant_id,join_path from public.resolve_entry_point($1)` auf und
  validiert das Format vor jedem DB-Zugriff.
- **DB-freie Verträge:** `tests/entry-point-rls.test.ts` (Repository-SQL,
  Format-Guard, Spaltenminimierung, Migrations-DDL) und
  `tests/migrations.test.ts` (008-Eigenschaften) pinnen die Sicherheits- und
  Migrations-Verträge ohne Datenbank. Route-Level-Verträge in
  `tests/http-contract.test.ts` (200-Kontrakt, 404, kein DB-Zugriff bei
  malformed key, INTERNAL_ERROR ohne Leak).
- **Blocker (unverändert, kein Workaround):** Die fehlende Produktions-App-Rolle
  macht den Ende-zu-Ende-Lauf gegen eine Live-DB in diesem Workspace unmöglich.
  Erster Schritt des Pilots nach Rollenanlage: `GRANT EXECUTE` verifizieren
  (Migration nachziehen oder einmalig ausführen), dann `bun run rls-verify`
  (Teil C) und ein echter `/join/:publicKey`-Abruf mit der App-Rolle.

## Teil E: Sessions-RLS (B2), Audit-Policy-Split (B3) und Owner-/FORCE-Entscheidung

Migration `009_sessions_rls_and_audit_split.sql` schließt die beiden
bestätigten Restlücken des Restaudits.

**B2 — Sessions ohne RLS:** `sessions` trägt pro-User-Credentials
(`token_hash`, `csrf_token_hash`). Seit 009 ist RLS aktiv mit einer
**user-scoped** Policy:

```sql
create policy sessions_user_isolation on sessions
  using (user_id = nullif(current_setting('app.user_id', true), '')::uuid)
  with check (user_id = nullif(current_setting('app.user_id', true), '')::uuid);
```

- Eine Session-Zeile ist nur im Kontext des **eigenen** `app.user_id`
  sichtbar/beschreibbar. Die Tenant-Grenze ist bewusst **nicht** Teil der
  Policy: Sessions gehören dem User; die Tenant-Zuordnung erzwingt der
  Membership-Join in `auth()` (server.ts) zusammen mit der Tenant-RLS von
  `tenant_memberships`. Ergebnis: keine Cross-User- und keine
  Cross-Tenant-Sichtbarkeit.
- **Transaktionslokaler User-Kontext** (kein RLS-Bypass): `auth()` setzt
  `app.user_id` nach der Identitätsauflösung, `login` vor
  Revoke/Insert, `rotate` und `revoke` (Logout) laufen über
  `CardRepository.userTransaction` (begin → `set_config('app.user_id', …, true)`
  → DML → commit). Ohne `app.user_id` liefert die Policy keine Zeilen
  (fail-closed), ein fremder User-Kontext kann keine fremden Zeilen treffen.
- **Identitäts-Bootstrap `resolve_session_user(p_token_hash)`:** `auth()` muss
  die `user_id` aus dem Session-Token kennen, **bevor** es `app.user_id`
  setzen kann (Henne-Ei). Analog zu `resolve_entry_point` (008) ist dies der
  einzige minimalprivilegierte Ausweg: SECURITY DEFINER, fester
  `search_path = pg_catalog`, vollqualifiziertes `public.sessions`, statisches
  SELECT ohne dynamisches SQL, Format-Guard (`^[a-f0-9]{64}`, sha256-Hex),
  `REVOKE ALL ... FROM PUBLIC` + bedingter `GRANT EXECUTE ... TO app_role`.
  Die Funktion liefert **ausschließlich** `user_id` für exakten
  Token-Hash-Match — niemals `csrf_token_hash`, `expires_at`, `revoked_at`
  oder andere Session-Spalten; der sensitive Session-Read in `auth()`
  läuft anschließend unter voller RLS mit gesetztem `app.user_id`. Besitz des
  Token-Hashs ist der Authentisierungsfaktor; die Funktion verrät kein
  Geheimnis, das der Aufrufer nicht bereits besitzt, und ist kein RLS-Bypass
  im Sinne von „Daten außerhalb des Berechtigungskontexts lesbar".

**B3 — Audit-Policy-Split:** Migration 006 nutzte eine einzelne Policy
`tenant_id is null or tenant_id = app.tenant_id`; dadurch waren globale Zeilen
in **jedem** Tenant-Kontext sichtbar und ohne Kontext alle Zeilen. 009 ersetzt
sie durch zwei OR-verknüpfte Policies:

```sql
create policy audit_log_tenant_isolation on audit_log
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  with check (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
create policy audit_log_global_isolation on audit_log
  using (tenant_id is null and nullif(current_setting('app.tenant_id', true), '') is null)
  with check (tenant_id is null and nullif(current_setting('app.tenant_id', true), '') is null);
```

- Tenant-Zeilen (`tenant_id NOT NULL`) nur im passenden `app.tenant_id`-Kontext;
- globale Zeilen (`tenant_id IS NULL`) nur **ohne** Tenant-Kontext;
- normale `appendAudit`-Aufrufe (`configurePilot`, `setStaff`) laufen innerhalb
  von `repository.transaction(tenantId, …)` mit gesetztem `app.tenant_id` und
  funktionieren unverändert (per Test gepinnt).

**Owner-/FORCE-Entscheidung (dokumentiert, keine pauschale FORCE-Aktivierung):**
Weder 009 noch eine andere Migration setzt `FORCE ROW LEVEL SECURITY` (gepinnt
durch `tests/migrations.test.ts`). Begründung: Die SECURITY-DEFINER-Resolver
(`resolve_entry_point` für `/join` aus 008, `resolve_session_user` aus 009)
laufen als Tabellenowner (Migrationsrolle) und stützen sich auf den
Owner-Bypass, der nur ohne FORCE existiert. Die App-Rolle ist in beiden Fällen
**kein** Owner und unterliegt RLS unabhängig von FORCE; `relforcerowsecurity`
ist für die Produktionsprüfung daher informational (Teil C) und kein
Freigabekriterium. Sollte später ein anderer Tabellenowner als die
Migrationsrolle existieren, wäre die Owner-/FORCE-Frage neu zu bewerten.

**DB-freie Verträge:** `tests/migrations.test.ts` (009-Policy-Exaktheit,
Resolver-Eigenschaften, kein FORCE, kein Eingriff in `tenant_entry_points`),
`tests/sessions-rls.test.ts` (`userTransaction`/`revokeSession`/
`revokeSessions`-Query-Reihenfolge und -Parameter, `appendAudit`-Insert
unverändert) und `tests/http-contract.test.ts` (Resolver-Query exakt
`select user_id from public.resolve_session_user($1)`, User-Kontext vor jedem
Session-Read, Login-/Logout-/Rotate-Kontext). `src/rls-verify.ts` prüft
`sessions` seit 009 in `TENANT_SENSITIVE_TABLES` mit.

**Blocker (unverändert):** Die Ende-zu-Ende-Verifikation von Sessions- und
Audit-RLS gegen eine Live-DB erfordert weiterhin die separate Nicht-Owner-App-
Rolle (Teil C); ohne sie kann in diesem Workspace nur der Owner-Pfad getestet
werden. B1 (Login-MFA-Bootstrap) ist seit Migration 010 über den eigenen
Definer-/Bootstrap-Mechanismus gelöst (Teile B/F); die Ende-zu-Ende-Verifikation
bleibt Teil des Pilotprozesses.


## Teil F: Login-MFA-Resolver (Migration 010)

`tenant_memberships` ist seit 001 per Tenant-Isolation-RLS geschützt. Der
unauthentifizierte Login hat **keinen** Tenant-Kontext und darf
`app.tenant_id` nicht setzen — ein direkter SELECT unter RLS verbirgt alle
Zeilen (Befund: NULL → `MFA_BOOTSTRAP_UNVERIFIED` → jeder Login blockiert).
Lösung (Migration `010_membership_mfa_resolver.sql`), analog zu
`resolve_entry_point` (008) und `resolve_session_user` (009): eine einzelne
minimalprivilegierte **SECURITY DEFINER**-Funktion

```sql
public.membership_mfa_required(p_user_id uuid) → boolean
```

- **Semantik:** `EXISTS` einer aktiven (`m.status='active'`) Owner-/Admin-
  Membership (`m.role in ('owner','admin')`) des Nutzers mit MFA-Pflicht auf
  Membership- **oder** User-Ebene (`m.mfa_required or u.mfa_required`) — exakt
  das bisherige Inline-Aggregat, aber als nie-NULL-Boolean.
- **Sicherheitseigenschaften:** fester `search_path = pg_catalog`,
  vollqualifizierte Tabellen `public.tenant_memberships` / `public.users`
  (kein search_path-abhängiges Auflösen), statisches `SELECT EXISTS` ohne
  dynamisches SQL, `REVOKE ALL ... FROM PUBLIC` und bedingter
  `GRANT EXECUTE ... TO app_role` (DO-Block, solange die Rolle fehlen kann;
  nach Rollenanlage ggf. einmalig ausführen:
  `grant execute on function public.membership_mfa_required(uuid) to app_role;`).
- **Minimalprinzip:** Die App-Rolle braucht für den Login **kein**
  Tabellen-SELECT auf `tenant_memberships`/`users` — nur EXECUTE auf genau
  diese eine Funktion, die ausschließlich den MFA-Boolean liefert (liest nur
  `m.role`, `m.status`, `m.mfa_required`, `u.mfa_required`; niemals
  `password_hash`, `mfa_secret_ciphertext`, E-Mail o. Ä.). Der `uuid`-Typ des
  Parameters weist Fehleingaben bereits auf Typ-Ebene ab (kein Regex-Guard
  nötig).
- **Keine FORCE-RLS-Änderung, keine breiten Grants:** 010 ändert weder Tabellen
  noch Policies und setzt kein `FORCE ROW LEVEL SECURITY` (der Owner-Bypass
  der SECURITY-DEFINER-Resolver bleibt erhalten; die App-Rolle ist kein Owner
  und unterliegt RLS unabhängig von FORCE).
- **DB-freie Verträge:** `tests/migrations.test.ts` (010-DDL: Signatur,
  SECURITY DEFINER, fester search_path, statisches SQL, REVOKE/GRANT, keine
  Tabellen-/Policy-/FORCE-Änderungen, nur `tenant_memberships`+`users`
  gelesen) und `tests/http-contract.test.ts` (Login-Abfrage exakt
  `select public.membership_mfa_required($1) as required`, niemals
  `from tenant_memberships`/`bool_or`; Fail-closed bei fehlender Zeile und bei
  NULL; `required=true` durchläuft das MFA-Gate ohne Session-Anlage).
- **Blocker (unverändert, kein Workaround):** Der Ende-zu-Ende-Lauf gegen eine
  Live-DB erfordert weiterhin die separate Nicht-Owner-App-Rolle (Teil C).
  Erster Schritt des Pilots nach Rollenanlage: `GRANT EXECUTE` verifizieren
  (Migration nachziehen oder einmalig ausführen), dann `bun run rls-verify`
  und ein echter Login mit MFA-aktivem Owner-/Admin-Konto unter der App-Rolle.
