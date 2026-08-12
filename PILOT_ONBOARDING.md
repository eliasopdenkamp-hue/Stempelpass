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

## Migration und Tests

Migration `006_pilot_onboarding.sql` ergänzt Entry-Points und Audit-Log, jeweils mit Tenant-RLS. Vor Pilotbetrieb Migrationen ausführen sowie Backups/Löschprozesse und Secrets produktiv konfigurieren. Keine echten Pilotdaten in Tests erzeugen.
