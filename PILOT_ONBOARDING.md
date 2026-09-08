# Pilot-Onboarding (Backend)

## Authentifizierter Ablauf

Owner/Admin sendet mit aktiver Session und `x-csrf-token`:

`PUT /api/tenants/{tenantId}/pilot`

Body: `planCode` (`up_to_500` oder `up_to_1000`), `cardTitle`, `cardText`, `primaryColor`, `secondaryColor` (jeweils `#RRGGBB`), optionale `iconAssetId`/`logoAssetId`, `stampsRequired` (1–100), `rewardTitle`, `rewardDescription`.

Das Backend setzt den Tarif unveränderlich auf 500/1000 Kundenlimit, speichert Branding und eine aktive Stamp Rule, erzeugt einen zufälligen öffentlichen Join-Key und schreibt Audit. Ein Wechsel unter die aktuelle Nutzung wird abgelehnt.

Staff: `PUT /api/tenants/{tenantId}/staff` mit `{userId, role: "admin"|"staff"|"viewer", active: true|false}`. Nur Owner/Admin, CSRF und tenant-scoped Session; Aktivierung legt eine Mitgliedschaft an, Deaktivierung setzt `inactive` und wird auditiert.

Entry-Point: `GET /api/tenants/{tenantId}/entry-point` (Session erforderlich). Der Rückgabewert enthält `joinPath` und `publicKey`; der Key ist keine Berechtigung und enthält keine Secrets.

## QR/NFC

QR-Code oder NFC-Tag verweist auf `/join/{publicKey}`. Der öffentliche Endpunkt liefert ausschließlich die Tenant-Referenz und weist aus, dass Kunden weder Login noch E-Mail benötigen. Karten-Token und Stempelberechtigung sind davon getrennt: Stempeln bleibt ausschließlich über authentifiziertes Personal möglich. Keine Admin-URL in QR/NFC einbetten. Der QR-Key ist ein zufälliger Identifier ohne Berechtigung.

Kunden werden weiterhin ohne Konto, Pflichtname, Telefonnummer oder E-Mail angelegt; Kommunikationsmodule bleiben optional.

## Einmaliger Pilot-Seed (CLI, nur lokal/Operator)

Der Seed legt idempotent Pilot-Tenant, Owner-User, owner-Membership und – nur bei gesetzter Variable – einen Testkunden an. Er liest **ausschließlich** Umgebungsvariablen, hasht das Passwort mit der bestehenden `hashPassword`-Logik (scrypt, `$scrypt$N=32768,r=8,p=1$…`) und gibt nur anonymisierte IDs/Status aus. Er läuft **niemals** im Vercel-Requestpfad: reines CLI (`import.meta.main`), zusätzlich harte Sperre bei `VERCEL=1` (`SEED_NOT_ALLOWED_ON_VERCEL`).

Voraussetzung: Migrationen sind angewendet (`bun run db:migrate`, Exit 0). Verbindung über `DATABASE_URL` mit der Operator-/Owner-Rolle (RLS wird als Tabellenowner umgangen — dieselbe Annahme wie `db:migrate`).

```sh
DATABASE_URL='postgresql://.../db?sslmode=require' \
PILOT_TENANT_SLUG='stempelpass' \
PILOT_TENANT_LEGAL_NAME='Stempelpass GmbH' \
PILOT_OWNER_EMAIL='owner@example.com' \
PILOT_OWNER_PASSWORD='<starkes Passwort, min. 12 Zeichen>' \
bun run db:seed-pilot
```

Optionaler Testkunde (`unique(tenant_id, external_ref)`):

```sh
PILOT_CUSTOMER_REF='test-kunde-1' bun run db:seed-pilot   # zusätzlich zu den Variablen oben
```

Verhalten und Sicherheitsvertrag:

- **Kein Klartextpasswort** wird gespeichert, geloggt, committet oder ausgegeben; das Passwort wird vor jeder SQL-Anweisung gehasht. Es gibt **kein Default-Passwort** und keine hartkodierten Ownerdaten (Runbook-Platzhalter sind Beispiele, keine Daten).
- **Ein Transaktion + Advisory-Lock** (`pg_advisory_xact_lock`, Schlüssel `742002`, getrennt vom Migrations-Lock `742001`) serialisiert parallele Seeds; `app.tenant_id` wird transaktionslokal gesetzt (Konsistenz mit den App-Transaktionen).
- **Idempotent**: existierende Tenant/User/Membership/Kunde bleiben unverändert; ein vorhandenes Passwort-Hash wird **nie** überschrieben (nur wenn der User noch keins hat, wird es gesetzt).
- **Anonymisierte Ausgabe** (Beispiel): `pilot_seed_ok`, `tenant id=3f9a1c2e… status=created`, `owner id=… status=created`, `membership id=… status=created role=owner membership_status=active`, `customer status=skipped` (bzw. `customer id=… status=created`). Slug, Rechtsname, E-Mail, Kunden-Ref und Passwort erscheinen nie. Exit-Codes: `0` = Erfolg, `1` = Fehler (stabiler Fehlercode auf stderr, z. B. `pilot_seed_failed PILOT_TENANT_SLUG_REQUIRED`).
- Der Tenant wird mit dem freigegebenen Pilot-Tarif `up_to_500`/500 angelegt; Tarifwechsel, Branding und Stamp Rule setzt der authentifizierte Ablauf `PUT /api/tenants/{tenantId}/pilot` (siehe oben). Karten/Tokens sind bewusst **nicht** Teil des Seeds.
- `PILOT_CUSTOMER_REF` optional: leer/fehlend = kein Kunde.

Erst ausführen, nachdem die Migrations- und Rollenprüfung (RLS_AUTH_P1.md Teil C) abgeschlossen ist und bevor `PILOT_READY=1` gesetzt wird (Reihenfolge: `db:migrate` → `db:seed-pilot` → App-Rolle/`rls-verify` → `PILOT_READY=1`).

## Neuer Mandant (`db:create-tenant`)

Für einen neuen Betrieb wird das vollständige Onboarding mit einem einzigen
operator-only CLI-Lauf angelegt: Tenant, Owner-User, Owner-Mitgliedschaft,
Branding, eine aktive Stempelregel, öffentlicher Entry-Point und optional ein
Testkunde. Voraussetzung ist, dass die Migrationen bereits erfolgreich
angewendet wurden (`bun run db:migrate`). Karten und Karten-Tokens werden
bewusst **nicht** angelegt; die Kartenerstellung erfolgt später über den
authentifizierten Flow bzw. einen separaten Schritt.

### Env-Vertrag

`DATABASE_URL` und alle folgenden Variablen sind erforderlich, sofern nicht als
optional markiert. Leere oder nur aus Whitespace bestehende Werte sind ungültig.
Es gibt keine Credential-Defaults und keine Pilotdaten im Code.

- `TENANT_SLUG`: Kleinbuchstaben, Ziffern und Bindestriche, 1–63 Zeichen.
- `TENANT_LEGAL_NAME`: Rechts-/Firmenname, maximal 200 Zeichen.
- `TENANT_PLAN_CODE`: ausschließlich `up_to_500` (Limit 500) oder `up_to_1000` (Limit 1000).
- `OWNER_EMAIL`: Login-E-Mail; der Abgleich erfolgt case-insensitiv über `lower(email)`.
- `OWNER_PASSWORD`: mindestens 12 Zeichen; wird niemals als Klartext gespeichert oder ausgegeben.
- `CARD_TITLE`, `CARD_TEXT`: Kartentitel und Kartentext.
- `PRIMARY_COLOR`, `SECONDARY_COLOR`: jeweils exakt `#RRGGBB`.
- `STAMPS_REQUIRED`: ganzzahlig `1` bis `100`.
- `REWARD_TITLE`, `REWARD_DESCRIPTION`: Prämientitel und Beschreibung.
- `ICON_ASSET_ID`, `LOGO_ASSET_ID`: optional; falls gesetzt UUIDs.
- `CUSTOMER_REF`: optionaler externer Schlüssel für genau einen Testkunden (`unique(tenant_id, external_ref)`).

Beispiel mit Platzhaltern (keine echten Zugangsdaten oder Pilotdaten in
Runbooks/Dateien schreiben):

```sh
export DATABASE_URL='postgresql://<operator>:<password>@<host>/<db>?sslmode=require'
export TENANT_SLUG='<tenant-slug>'
export TENANT_LEGAL_NAME='<legal-name>'
export TENANT_PLAN_CODE='up_to_500'
export OWNER_EMAIL='<owner-email>'
read -r -s OWNER_PASSWORD
export OWNER_PASSWORD
export CARD_TITLE='<card-title>'
export CARD_TEXT='<card-text>'
export PRIMARY_COLOR='#123456'
export SECONDARY_COLOR='#ffffff'
export STAMPS_REQUIRED='10'
export REWARD_TITLE='<reward-title>'
export REWARD_DESCRIPTION='<reward-description>'
# Optional: export CUSTOMER_REF='<test-customer-ref>'
# Optional: export ICON_ASSET_ID='<uuid>' / export LOGO_ASSET_ID='<uuid>'
bun run db:create-tenant
unset OWNER_PASSWORD
```

### Sicherheitsvertrag und Ablauf

- `OWNER_PASSWORD` wird mit der bestehenden scrypt-`hashPassword`-Funktion
  gehasht, **bevor** der CLI eine Datenbankverbindung bzw. SQL-Anweisung
  ausführt. Das Klartextpasswort wird niemals geloggt, gespeichert,
  committet oder ausgegeben.
- Der Lauf ist idempotent: Ein vorhandener Tenant wird exakt beibehalten
  (insbesondere kein Plan-Downgrade oder sonstige Tenant-Änderung), User und
  Membership werden nicht dupliziert, ein bestehender Passwort-Hash nie
  überschrieben, Branding/aktive Regel werden aktualisiert und der vorhandene
  Entry-Point-Key bleibt bei Wiederholung erhalten.
- Alle DML laufen in **einer Transaktion** unter der Operator-/Owner-
  Datenbankverbindung (dieselbe RLS-Bypass-Annahme wie `db:migrate` und
  `db:seed-pilot`). Die Transaktion hält den neuen
  `pg_advisory_xact_lock`-Schlüssel **742003** und setzt `app.tenant_id`
  transaktionslokal. Der Schlüssel ist nicht mit 742001 (Migration) oder
  742002 (Pilot-Seed) geteilt.
- Der CLI ist durch `import.meta.main` auf reine CLI-Ausführung begrenzt und
  verweigert bei `VERCEL=1` mit stabilem Fehlercode den Lauf.
- Stdout ist anonymisiert: nur maskierte interne IDs, Statuswerte und der
  öffentliche `join_path` (kein Secret) erscheinen. Slug, Rechtsname,
  E-Mail, `CUSTOMER_REF` und Credentials erscheinen nie. Fehler gehen als
  stabile Codes mit Exit 1 nach stderr; Erfolg endet mit Exit 0.
- Audit wird append-only als `tenant.configured` mit minimalen Metadaten
  geschrieben. Die Ausgabe enthält keine Audit-/PII-Daten.

Auszuführen ist der Ablauf nach `db:migrate` und vor dem produktiven Pilot-
Betrieb. Die öffentliche Join-URL kann danach für QR/NFC verwendet werden;
Stempeln bleibt ausschließlich dem authentifizierten Personal vorbehalten.

## Owner-Passwort setzen/rotieren (CLI, nur Operator)

Für einen **bereits vorhandenen** Owner gibt es ausschließlich den operator-only CLI-Pfad `bun run db:rotate-owner-password`. Er läuft nie bei `VERCEL=1`, prüft vor jeder DML die Operator-/Tabellenowner-Rolle und sucht ausschließlich den bestehenden aktiven Owner über Tenant-Slug plus exakte Owner-E-Mail. Es werden keine User oder Memberships angelegt.

```sh
export DATABASE_URL='postgresql://.../db?sslmode=require'
export OWNER_PASSWORD_ROTATION_TENANT_SLUG='stempelpass'
export OWNER_PASSWORD_ROTATION_OWNER_EMAIL='owner@example.com'
export OWNER_PASSWORD_ROTATION_ID="owner-rotation-$(date -u +%Y%m%dT%H%M%SZ)"
read -r -s OWNER_PASSWORD_ROTATION_PASSWORD
export OWNER_PASSWORD_ROTATION_PASSWORD
bun run db:rotate-owner-password
unset OWNER_PASSWORD_ROTATION_PASSWORD
```

Das Ersatzpasswort wird mit derselben scrypt-`hashPassword`-Logik gehasht, bevor `users.password_hash` geschrieben wird. Danach werden alle bestehenden Sessions des Users widerrufen und genau ein append-only Audit-Ereignis (`operator.owner_password_rotated`) geschrieben. Ausgabe enthält nur `status=rotated` bzw. `status=already_applied`; Passwort, E-Mail, Tenant- und interne IDs werden nie ausgegeben. Bei einem Retry dieselbe `OWNER_PASSWORD_ROTATION_ID` wiederverwenden; eine bereits erfolgreich angewendete Operation ändert weder Passwort noch Sessions erneut. Alternativ kann das Passwort über stdin gepiped werden. Das Passwort niemals als CLI-Argument verwenden oder in Dateien/Notizen schreiben.

## Migration und Tests

Migration `006_pilot_onboarding.sql` ergänzt Entry-Points und Audit-Log, jeweils mit Tenant-RLS. Vor Pilotbetrieb Migrationen ausführen sowie Backups/Löschprozesse und Secrets produktiv konfigurieren. Keine echten Pilotdaten in Tests erzeugen.
