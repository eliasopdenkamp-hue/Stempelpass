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

## Migration und Tests

Migration `006_pilot_onboarding.sql` ergänzt Entry-Points und Audit-Log, jeweils mit Tenant-RLS. Vor Pilotbetrieb Migrationen ausführen sowie Backups/Löschprozesse und Secrets produktiv konfigurieren. Keine echten Pilotdaten in Tests erzeugen.
