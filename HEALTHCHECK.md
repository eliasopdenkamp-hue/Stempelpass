# Fehlerüberwachung: `/health`-Check per GitHub Actions

Leichtgewichtige Produktionsüberwachung ohne Monitoring-SaaS und ohne
zusätzliche Kosten (Stand 2026-11-03, Owner-Anforderung vor dem Pilot).

## Was läuft

| Punkt | Wert |
| --- | --- |
| Workflow | `.github/workflows/health-check.yml` |
| Intervall | alle 15 Minuten (`cron: */15 * * * *`, UTC) + manuell per `workflow_dispatch` |
| Ziel | `GET https://project-ywbp8.vercel.app/health` (überschreibbar über die Repo-Variable `HEALTH_URL`: Settings → Secrets and variables → Actions → Variables) |
| Erfolg | HTTP 200 **und** Body `{"status":"ready"}` |
| Fehler | alles andere (HTTP ≠ 200, `not_ready`, kein/unlesbares JSON, Timeout) — nach 3 Versuchen im Abstand von 15 s |
| Benachrichtigung | GitHub mailt fehlgeschlagene (Scheduled-)Workflow-Läufe an den Repo-Inhaber bzw. an die Person, die diese Workflow-Datei zuletzt geändert hat |

Kostenrahmen: ~96 Läufe/Tag à 10–20 s, also deutlich unter 100
Actions-Minuten pro Monat.

## Was `/health` aussagt — und was nicht

`GET /health` antwortet **immer** mit HTTP 200, solange die Function läuft
(Liveness). Der eigentliche Zustand steht ausschließlich im Feld `status`:

- `ready` — Konfiguration vollständig, kein Initialisierungsfehler, DB-Pool
  bereit und `PILOT_READY=1` gesetzt.
- `not_ready` — eine dieser Bedingungen fehlt (z. B. fehlende/ungültige
  Umgebungsvariable, fehlgeschlagene Opt-in-Migration, `PILOT_READY` nicht
  gesetzt).

Der Endpoint **fragt die Datenbank nicht ab** (bewusst: keine blockierende
Query im Health-Pfad, siehe `src/health.ts`). Ein `ready` bedeutet daher
„Deployment ist konfiguriert und als pilotbereit markiert", nicht „jede
Route und jede Query funktioniert". Ein Fehler in einzelnen Fachrouten
(Stempeln, Einlösen, Wallet-Refresh) löst diesen Alarm **nicht** aus.

## Alarmfall — was zu tun ist

1. **Bestätigen (1 Minute).** `curl -sS https://project-ywbp8.vercel.app/health`
   von Hand aufrufen. Kommt `{"status":"ready"}`, war es ein Netz-Hiccup beim
   Runner: Run im Actions-Tab erneut starten (`Run workflow`) und im
   Betriebslog vermerken.
2. **Deployment prüfen.** Im Vercel-Projekt den letzten Deploy ansehen: Ist
   der Alarm kurz nach einem Deploy aufgetreten, zuerst auf die vorherige
   funktionierende Version zurückrollen (Instant Rollback) und danach in Ruhe
   debuggen.
3. **Umgebungsvariablen prüfen** (häufigste Ursache für `not_ready`):
   `PILOT_READY`, `DATABASE_URL`, `SESSION_SECRET`, `FRONTEND_ORIGIN`.
   Wurde eine Variable gelöscht oder geändert? Die Live-Umgebung startet nach
   dem Speichern einer Variable innerhalb von Sekunden neu — danach den
   Workflow erneut starten.
4. **Datenbank erreichbar?** Bei Verdacht auf Neon (z. B. gleichzeitig
   Fehler bei Stempeln/Einlösen): `bun run rls-verify` mit
   `RLS_VERIFY_DATABASE_URL=<Production-URL> RLS_VERIFY_ROLE=stempelpass_runtime`
   laufen lassen. Exit 0 = Rolle/RLS/Grants in Ordnung; `connect` im Report =
   Datenbank nicht erreichbar.
5. **Nach der Behebung:** Workflow manuell starten, grünen Lauf abwarten,
   Vorfall mit Zeitpunkt, Ursache und Maßnahme im Betriebslog festhalten
   (DSGVO-Ordner, außerhalb des Repos).

## Grenzen und Wartungshinweise

- GitHub deaktiviert **geplante** Workflows nach 60 Tagen ohne
  Repository-Aktivität. Kommt längere Zeit kein Commit, im Actions-Tab
  prüfen, ob der Schedule noch aktiv ist (und ihn ggf. per
  `Run workflow`/Commit reaktivieren).
- Scheduled Runs können bei GitHub-Last um einige Minuten verzögern; das
  Intervall ist bewusst kein SLA.
- Der Check braucht keine Secrets: `/health` ist öffentlich und liefert nur
  ein Statusfeld.
- Wächst der Bedarf (z. B. Prüfung von Stempel-/Einlöse-Pfaden oder
  Wallet-Refresh-Fehlern), ist das ein eigener Ausbauschritt — nicht Teil
  dieses minimalen Checks.
