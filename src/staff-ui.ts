/**
 * Server-rendered staff web UI (no client framework, no new dependencies).
 *
 * Pure render helpers: they take plain view data and return HTML strings.
 * No database access, no secrets, no request handling — the routes in
 * server.ts do auth and data loading, then call these builders. Every dynamic
 * value is HTML-escaped (esc), colors are sanitized via safeCardColor, and the
 * only values that ever reach HTML attributes/JS state (tenant id, csrf hash)
 * are strict formats (UUID / 64-hex). The embedded script is static and uses
 * event delegation on `document`, so swapping #sp-app content keeps the page
 * interactive without re-binding listeners.
 */
import type { StaffDashboardCard, StaffDashboardEvent } from './repository.js';
import { DEFAULT_PRIMARY_CARD_COLOR, DEFAULT_SECONDARY_CARD_COLOR, safeCardColor } from './public-card.js';

/** HTML-escape a dynamic value (same character set as the public webcard). */
export function esc(v: unknown): string {
  return String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

/** Short, deterministic timestamp for tables (UTC-agnostic display). */
function fmtTs(v: string | null): string {
  if (!v) return '—';
  const s = String(v).slice(0, 16).replace('T', ' ');
  return s.length === 16 ? `${s} Uhr` : '—';
}

const BASE_CSS = `
body{font:16px system-ui,sans-serif;margin:0;padding:2rem;background:#f8fafc;color:#172033}
.card{max-width:40rem;margin:auto;padding:2rem;border-radius:1.5rem;background:#fff;border-top:.6rem solid #155e75;box-shadow:0 8px 30px #0002}
h1{margin:0 0 .25rem;font-size:1.5rem}h2{margin:1.75rem 0 .5rem;font-size:1.1rem;color:#334155}
p{margin:.4rem 0;color:#334155;line-height:1.45}
label{display:block;margin:.8rem 0 .25rem;font-weight:600;font-size:.9rem;color:#334155}
input,select{width:100%;box-sizing:border-box;padding:.7rem .8rem;border:1px solid #cbd5e1;border-radius:.6rem;font:inherit}
button{background:#155e75;color:#fff;border:0;padding:.7rem 1.1rem;border-radius:.65rem;font-weight:600;cursor:pointer;margin-top:1rem}
button:disabled{opacity:.55;cursor:default}
button.secondary{background:#0f766e}
button.ghost{background:#fff;color:#155e75;border:1px solid #155e75;margin-top:0;padding:.4rem .8rem;font-size:.85rem}
table{width:100%;border-collapse:collapse;margin-top:.5rem;font-size:.9rem}
th,td{text-align:left;padding:.5rem .4rem;border-bottom:1px solid #e2e8f0;vertical-align:middle}
th{color:#64748b;font-size:.8rem;text-transform:uppercase;letter-spacing:.03em}
code{font-size:.8rem;background:#f1f5f9;padding:.1rem .35rem;border-radius:.3rem;color:#334155}
.badge{display:inline-block;font-size:.75rem;font-weight:700;padding:.15rem .5rem;border-radius:999px}
.badge.issued{background:#dcfce7;color:#166534}.badge.redeemed{background:#e2e8f0;color:#475569}
.flash{padding:.8rem 1rem;border-radius:.7rem;margin:0 0 1rem;font-weight:600}
.flash.ok{background:#dcfce7;color:#166534}.flash.error{background:#fee2e2;color:#991b1b}
.meta{color:#475569;font-size:.85rem}
.error{color:#991b1b;font-weight:600}
.hint{font-size:.85rem;color:#64748b;margin-top:.35rem}
.row{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center}
.spacer{flex:1}
@media(max-width:640px){body{padding:1rem}.card{padding:1.2rem;border-radius:1rem}}
`.trim();

/** Colors are additionally sanitized before interpolation into CSS. */
const safeColor = (v: unknown, fallback: string) => safeCardColor(v, fallback);

/** Full HTML document shell shared by all staff pages. */
function page(title: string, bodyHtml: string, extraHead = ''): string {
  return `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>${BASE_CSS}</style>${extraHead}</head><body>${bodyHtml}</body></html>`;
}

/**
 * Deterministic staff script (static — carries NO server state; the current
 * CSRF hash is delivered in a <meta name="sp-csrf"> tag in <head>). Mutating
 * actions run through fetch with the x-csrf-token header (the CSRF contract of
 * the JSON API); every mutating response rotates the session and therefore
 * carries a fresh x-csrf-token RESPONSE header, which is adopted here.
 * After a successful action the server re-renders the full #sp-app dashboard
 * (fresh CSRF embedded), which this script swaps in; document-level delegated
 * listeners make the swapped-in content interactive without re-binding.
 */
const STAFF_SCRIPT = `
<script>
(function () {
  var csrf = null;
  function refreshCsrf(doc) {
    var m = doc && doc.querySelector('meta[name="sp-csrf"]');
    if (m) csrf = m.getAttribute('content');
  }
  refreshCsrf(document);
  function showError(text) {
    var box = document.getElementById('sp-errbox');
    if (box) { box.textContent = text; box.style.display = 'block'; }
    else window.alert(text);
  }
  function hideError() {
    var box = document.getElementById('sp-errbox');
    if (box) { box.textContent = ''; box.style.display = 'none'; }
  }
  function dataBody(el) {
    var out = {};
    var card = el.getAttribute('data-card');
    var qty = el.getAttribute('data-quantity');
    var reward = el.getAttribute('data-reward');
    if (card) out.cardId = card;
    if (qty) out.quantity = qty;
    if (reward) out.rewardId = reward;
    return out;
  }
  function post(url, data) {
    hideError();
    var body = new URLSearchParams(data || {});
    return fetch(url, { method: 'POST', headers: { 'x-csrf-token': csrf || '' }, body: body }).then(function (res) {
      var next = res.headers.get('x-csrf-token');
      if (next && /^[0-9a-f]{64}$/.test(next)) csrf = next;
      return res.text().then(function (html) {
        var doc = new DOMParser().parseFromString(html, 'text/html');
        if (!res.ok) {
          var err = doc.getElementById('sp-error');
          showError(err ? err.textContent : 'Aktion fehlgeschlagen. Bitte erneut versuchen.');
          return;
        }
        refreshCsrf(doc);
        var app = doc.getElementById('sp-app');
        var current = document.getElementById('sp-app');
        if (app && current) current.outerHTML = app.outerHTML;
      });
    }).catch(function () {
      showError('Dienst ist kurz nicht erreichbar. Bitte erneut versuchen.');
    });
  }
  document.addEventListener('click', function (ev) {
    var el = ev.target && ev.target.closest ? ev.target.closest('[data-action]') : null;
    if (!el) return;
    ev.preventDefault();
    var action = el.getAttribute('data-action');
    var url = el.getAttribute('data-url');
    if (!url) return;
    el.disabled = true;
    var done = post(url, dataBody(el));
    done.then(function () { el.disabled = false; });
    if (action === 'logout') done.then(function () { window.location.href = '/login'; });
  });
  document.addEventListener('submit', function (ev) {
    var form = ev.target;
    if (!form || !form.getAttribute || !form.getAttribute('data-staff-form')) return;
    ev.preventDefault();
    var action = form.getAttribute('action');
    var btn = form.querySelector('button[type="submit"]');
    if (btn) btn.disabled = true;
    post(action, new FormData(form)).then(function () { if (btn) btn.disabled = false; });
  });
})();
</script>`;

/** German-friendly text for a given error code (never internal details). */
export function staffErrorMessage(code: string): string {
  switch (code) {
    case 'UNAUTHENTICATED': return 'Diese Seite erfordert eine Anmeldung.';
    case 'CSRF_INVALID': return 'Sitzung abgelaufen. Bitte neu anmelden.';
    case 'FORBIDDEN': return 'Keine Berechtigung für diese Aktion.';
    case 'CARD_NOT_FOUND': return 'Karte nicht gefunden.';
    case 'CARD_FIELDS_REQUIRED': return 'Bitte eine Karten-ID oder einen Karten-Token angeben.';
    case 'INVALID_STAMP_QUANTITY': return 'Ungültige Stempelanzahl (1–10).';
    case 'RATE_LIMITED': return 'Zu viele Anfragen. Bitte kurz warten.';
    case 'REWARD_NOT_FOUND': return 'Keine einlösbare Prämie für diese Karte.';
    case 'REWARD_ALREADY_REDEEMED': return 'Diese Prämie wurde bereits eingelöst.';
    case 'TENANT_NOT_FOUND': return 'Unternehmen nicht gefunden oder deaktiviert.';
    case 'DATABASE_UNAVAILABLE': return 'Dienst ist kurz nicht erreichbar. Bitte erneut versuchen.';
    case 'MFA_REQUIRED': return 'Diese Sitzung erfordert eine MFA-Bestätigung. Bitte neu anmelden.';
    default: return 'Ein unerwarteter Fehler ist aufgetreten. Bitte erneut versuchen.';
  }
}

/** Full-page error (status + friendly text; request id only for INTERNAL_ERROR). */
export function staffErrorPage(status: number, code: string, requestId?: string): string {
  const detail = code === 'INTERNAL_ERROR' && requestId
    ? `<p class="hint">Fehlerkennung: ${esc(requestId)}</p>` : '';
  return page('Fehler – StempelPass', `<main class="card"><h1>Fehler</h1><p class="error" id="sp-error">${esc(staffErrorMessage(code))}</p>${detail}<p><a href="/staff">Zurück zur Übersicht</a></p></main>`);
}

/** GET /login — staff login form (email + password + optional MFA code). */
export function loginPage(): string {
  return page('Anmelden – StempelPass', `<main class="card"><h1>StempelPass</h1><p class="meta">Personal-Anmeldung</p>
<form id="login-form">
<label for="f-email">E-Mail</label><input id="f-email" name="email" type="email" required autocomplete="username" autofocus>
<label for="f-password">Passwort</label><input id="f-password" name="password" type="password" required autocomplete="current-password">
<label for="f-mfa">MFA-Code <span class="hint">(nur falls aktiviert)</span></label><input id="f-mfa" name="mfaCode" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="6-stelliger Code">
<p id="login-msg" class="error" style="min-height:1.2em"></p>
<button type="submit">Anmelden</button>
</form></main>
<script>
(function () {
  var form = document.getElementById('login-form');
  var msg = document.getElementById('login-msg');
  var texts = {
    INVALID_CREDENTIALS: 'E-Mail, Passwort oder MFA-Code ist falsch.',
    CREDENTIALS_REQUIRED: 'Bitte E-Mail und Passwort eingeben.',
    RATE_LIMITED: 'Zu viele Versuche. Bitte kurz warten.',
    DATABASE_UNAVAILABLE: 'Dienst ist kurz nicht erreichbar. Bitte erneut versuchen.'
  };
  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var btn = form.querySelector('button');
    btn.disabled = true; msg.textContent = '';
    var payload = { email: form.email.value, password: form.password.value };
    if (form.mfaCode && form.mfaCode.value) payload.mfaCode = form.mfaCode.value;
    fetch('/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) })
      .then(function (res) {
        if (res.ok) { window.location.href = '/staff'; return; }
        return res.json().catch(function () { return {}; }).then(function (body) {
          var code = body && body.data && body.data.error;
          msg.textContent = texts[code] || 'Anmeldung fehlgeschlagen. Bitte erneut versuchen.';
        });
      })
      .catch(function () { msg.textContent = texts.DATABASE_UNAVAILABLE; })
      .then(function () { btn.disabled = false; });
  });
})();
</script>`);
}

/** GET /staff with >1 active tenant — chooser page. */
export function tenantChooserPage(tenants: Array<{ tenantId: string; role: string; legalName: string | null }>): string {
  const links = tenants.map(t =>
    `<p><a href="/staff/${esc(t.tenantId)}"><strong>${esc(t.legalName ?? t.tenantId)}</strong></a> <span class="meta">(${esc(t.role)})</span></p>`).join('');
  return page('Unternehmen wählen – StempelPass', `<main class="card"><h1>Unternehmen wählen</h1><p class="meta">Ihr Konto ist mehreren Unternehmen zugeordnet.</p>${links}<p><a href="/login">Abmelden</a></p></main>`);
}

/** GET /staff with an authenticated user that has no active tenant. */
export function noTenantPage(): string {
  return page('Kein Zugang – StempelPass', `<main class="card"><h1>Kein aktiver Zugang</h1><p>Dieses Konto ist keinem aktiven Unternehmen zugeordnet. Bitte wenden Sie sich an Ihren Anbieter.</p><p><a href="/login">Zur Anmeldung</a></p></main>`);
}

export interface DashboardView {
  tenantId: string;
  legalName: string | null;
  planCode: string;
  customerLimit: number;
  usedCards: number;
  role: string;
  canStamp: boolean;
  cardTitle: string;
  cardText: string;
  primaryColor: string;
  ruleName: string | null;
  stampsRequired: number | null;
  rewardTitle: string | null;
  rewardDescription: string | null;
  joinPath: string | null;
  csrf: string;
  cards: StaffDashboardCard[];
  events: StaffDashboardEvent[];
}

const PLAN_LABEL: Record<string, string> = { up_to_500: 'Bis 500 Kunden', up_to_1000: 'Bis 1.000 Kunden' };

/** GET /staff/:tenantId — dashboard. `csrf` must be the current session's
 *  stored CSRF hash (the exact value the client submits in x-csrf-token). */
export function dashboardPage(v: DashboardView, flash?: { kind: 'ok' | 'error'; text: string }): string {
  const primary = safeColor(v.primaryColor, DEFAULT_PRIMARY_CARD_COLOR);
  const title = v.cardTitle || 'StempelPass';
  const tenantName = v.legalName || v.cardTitle || 'Unternehmen';
  const flashHtml = flash ? `<div class="flash ${esc(flash.kind)}" id="sp-flash">${esc(flash.text)}</div>` : '';
  const rewardHtml = v.rewardTitle
    ? `<p><strong>Prämie:</strong> ${esc(v.rewardTitle)}${v.rewardDescription ? ` — ${esc(v.rewardDescription)}` : ''} (${esc(v.ruleName ?? 'Regel')}: ${esc(v.stampsRequired ?? '?')} Stempel)</p>`
    : '<p class="meta">Noch keine Stempelregel eingerichtet.</p>';
  const joinHtml = v.joinPath
    ? `<p><a href="${esc(v.joinPath)}">Kunden-Join-Link öffnen</a> <span class="hint">(${esc(v.joinPath)})</span></p>`
    : '<p class="meta">Noch kein Join-Link eingerichtet.</p>';
  const cardRows = v.cards.length
    ? v.cards.map(c => {
        const progress = Math.min(100, Math.round((c.stampCount / Math.max(1, Number(v.stampsRequired ?? 1))) * 100));
        const statusBadge = c.rewardStatus === 'issued'
          ? '<span class="badge issued">Prämie einlösbar</span>'
          : c.rewardStatus === 'redeemed' ? '<span class="badge redeemed">Prämie eingelöst</span>' : '';
        const actions: string[] = [];
        if (v.canStamp) {
          actions.push(`<button type="button" class="ghost" data-action="stamp" data-url="/staff/${esc(v.tenantId)}/stamp" data-card="${esc(c.id)}" data-quantity="1">+1 Stempel</button>`);
          if (c.rewardStatus === 'issued' && c.rewardId) {
            actions.push(`<button type="button" class="ghost" data-action="redeem" data-url="/staff/${esc(v.tenantId)}/redeem" data-reward="${esc(c.rewardId)}">Prämie einlösen</button>`);
          }
        }
        return `<tr><td><code>${esc(c.id.slice(0, 8))}</code> <span class="meta">${esc(c.customerRef ?? '—')}</span></td><td>${esc(c.stampCount)} / ${esc(v.stampsRequired ?? '?')}</td><td><progress max="100" value="${progress}" style="width:5rem;accent-color:${esc(primary)}"></progress></td><td>${statusBadge || '<span class="meta">—</span>'}</td><td class="row">${actions.join('')}</td></tr>`;
      }).join('')
    : '<tr><td colspan="5"><span class="meta">Noch keine Karten.</span></td></tr>';
  const eventRows = v.events.length
    ? v.events.map(e => `<tr><td><code>${esc(e.cardId.slice(0, 8))}</code></td><td>${esc(e.customerRef ?? '—')}</td><td>+${esc(e.quantity)}</td><td>${esc(fmtTs(e.createdAt))}</td></tr>`).join('')
    : '<tr><td colspan="4"><span class="meta">Noch keine Stempel-Ereignisse.</span></td></tr>';
  const stampForm = v.canStamp
    ? `<form data-staff-form action="/staff/${esc(v.tenantId)}/stamp" method="post" class="row" style="gap:.5rem;margin-top:.5rem">
        <input name="cardId" placeholder="Karten-ID oder Karten-Token" required style="flex:1;margin:0">
        <input name="quantity" type="number" min="1" max="10" value="1" style="width:5.5rem;margin:0">
        <button type="submit" class="secondary" style="margin:0">Stempel vergeben</button>
      </form><p class="hint">Karten-ID aus der Liste kopieren oder den Token vom Kunden-Gerät/QR eingeben.</p>`
    : '<p class="meta">Diese Rolle kann keine Stempel vergeben oder Prämien einlösen.</p>';
  return page(`${title} – Personal-Bereich`,
    `<main class="card" id="sp-app" style="border-top-color:${esc(primary)}">
${flashHtml}<p id="sp-errbox" class="flash error" style="display:none" role="alert"></p>
<div class="row"><h1 style="margin:0">${esc(tenantName)}</h1><span class="spacer"></span><button type="button" class="ghost" data-action="logout" data-url="/staff/${esc(v.tenantId)}/logout">Abmelden</button></div>${v.cardText ? `<p class="meta">${esc(v.cardText)}</p>` : ""}
<p class="meta">Tarif: ${esc(PLAN_LABEL[v.planCode] ?? v.planCode)} · ${esc(v.usedCards)} von ${esc(v.customerLimit)} Kunden belegt · Rolle: ${esc(v.role)}</p>
<h2>Stempelregel &amp; Prämie</h2>${rewardHtml}
<h2>Links für die Demo</h2>${joinHtml}<p class="hint">Kunden-Webkarte: <code>/card/${esc(v.tenantId)}/{Karten-Token}</code> — der Karten-Token wird bei der Kartenerstellung einmalig ausgegeben und ist nur dem Kunden/Personal bekannt.</p>
<h2>Karten</h2>
<table><thead><tr><th>Karte / Kunde</th><th>Stempel</th><th>Fortschritt</th><th>Prämie</th><th>Aktion</th></tr></thead><tbody>${cardRows}</tbody></table>${stampForm}
<h2>Letzte Stempel-Ereignisse</h2>
<table><thead><tr><th>Karte</th><th>Kunde</th><th>Stempel</th><th>Zeitpunkt</th></tr></thead><tbody>${eventRows}</tbody></table>
</main>`,
    `<meta name="sp-csrf" content="${esc(v.csrf)}">${STAFF_SCRIPT}`);
}