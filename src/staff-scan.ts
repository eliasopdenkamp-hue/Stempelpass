/**
 * Staff camera scan ("Karte scannen") — decision note APP_NFC_RECHERCHE_2026-
 * 10-17: the 0-€ path for the register is scanning the code on the customer's
 * phone camera, not NFC (Smart Tap needs certified terminals, phone-to-phone
 * is not supported). Everything runs 100 % client-side: the camera images are
 * decoded in the browser and NEVER uploaded; there are no new data endpoints,
 * no new DB fields and no new secrets. The recognized value is fed through the
 * EXISTING staff search/resolver (GET /staff/:tenantId/search-code →
 * resolveStampTarget), so scanning accepts exactly what typing accepts:
 * card code K-XXXXXX (prefix optional, case-insensitive), card UUID or
 * customer token — plus, as a convenience, a webcard URL QR (its final path
 * segment IS the customer token).
 *
 * Decoders (two paths, one UX):
 *  - Native `BarcodeDetector` where the browser ships it (Chrome/Android,
 *    formats code_128 + qr_code) — zero download.
 *  - The vendored @zxing/library UMD (served via GET /vendor/zxing.min.js,
 *    lazy-loaded ONLY on cameras that lack BarcodeDetector: iOS Safari,
 *    Firefox, desktop Chrome) — `ZXing.BrowserMultiFormatReader`.
 *  - <input type="file"> as a manual fallback inside the modal for devices
 *    where getUserMedia fails (permission denied, no camera); the picked
 *    image is decoded with the same zxing reader, client-side.
 */

/**
 * Normalize a raw scanned value to what the staff search/stamp resolver
 * accepts. Deliberately conservative: whitespace trimmed; a webcard URL QR
 * (containing /card/) is reduced to its final path segment (the customer
 * token); everything else is passed through unchanged so the server-side
 * resolveStampTarget (cardCode | cardId | token, case-insensitive) stays the
 * single authority.
 *
 * Written in ES5-compatible style on purpose: this exact function source is
 * embedded into the staff page via Function.prototype.toString (see
 * staffScanScript below), so it must survive transpilation and run in the
 * browser as-is.
 */
export function normalizeScannedTarget(raw: unknown): string {
  var v = String(raw == null ? '' : raw).trim();
  if (v.length === 0) return '';
  if (/^https?:\/\//i.test(v)) {
    // Webcard QR (https://…/card/{tenantId}/{token} or /card/{token}): the
    // customer token is the LAST path segment and IS a valid stamp/search
    // target. Any /card/ URL is reduced to that segment; the server-side
    // resolveStampTarget stays the single authority for everything else.
    var path = v.split(/[?#]/)[0];
    if (/\/card\//i.test(path)) {
      var segs = path.split('/');
      var last = segs[segs.length - 1];
      if (last) return last;
    }
  }
  return v;
}

/**
 * Scan field fragment: wraps an existing input (stamp form cardId / code
 * search input) plus a ≥44px camera button in a flex row. One shared button
 * class (.sp-scan-btn) so the delegated click handler in the scan script
 * survives dashboard swaps. `inputHtml` is server-controlled markup, so
 * escaping it here is belt-and-braces.
 */
export function scanFieldHtml(inputHtml: string): string {
  return `<span class="sp-scan-field" style="flex:1;min-width:0">
${inputHtml}
<button type="button" class="ghost sp-scan-btn" aria-label="Kartencode per Kamera scannen" title="Kartencode per Kamera scannen">📷</button>
</span>`;
}

/**
 * Inline scan modal (sibling of #sp-app, never swapped on dashboard re-render,
 * so the event listeners bound once at boot keep working). The camera preview,
 * the status line and the file fallback all live here; the privacy note states
 * the on-device-only processing guarantee (DSGVO-friendly, matches the brief).
 */
export function scanModalHtml(): string {
  return `<div id="sp-scan-modal" class="scan-modal" hidden>
<div class="scan-modal-box" role="dialog" aria-modal="true" aria-label="Karte scannen">
<div class="scan-modal-head"><strong>Karte scannen</strong><button type="button" class="ghost" id="sp-scan-close" style="margin:0">Schließen</button></div>
<video id="sp-scan-video" playsinline autoplay muted></video>
<p id="sp-scan-status" class="scan-status">Kartencode auf dem Kundenhandy anvisieren …</p>
<div class="scan-modal-actions"><label class="scan-file-label">Foto verwenden<input type="file" id="sp-scan-file" accept="image/*"></label></div>
<p class="hint" style="text-align:center">Alle Bilder werden ausschließlich auf diesem Gerät verarbeitet und nicht hochgeladen.</p>
</div>
</div>`;
}

/**
 * The inline scan script (delivered at the end of <body> like STAFF_SCRIPT —
 * never in <head>, see the live-verified 2026-09-23 position bug). ES5-style,
 * no template literals, no `</script>` inside string literals. Uses document-
 * level delegation for the scan buttons (survives #sp-app swaps) and triggers
 * the EXISTING search form submit once a value is recognized, so the found
 * card appears with its +1 Stempel button exactly like manual entry.
 *
 * The embedded normalizeScannedTarget source is shipped via toString() — the
 * unit test pins both the TS export and the exact embedded copy.
 */
export function staffScanScript(): string {
  return `<script>
(function () {
  var scan = { modal: null, video: null, status: null, file: null, stream: null, reader: null, timer: null, open: false, done: false };
  ${normalizeScannedTarget.toString()}
  function byId(id) { return document.getElementById(id); }
  function setStatus(text) { if (scan.status) scan.status.textContent = text; }
  function fillTargets(value) {
    var input = byId('sp-code-input');
    if (input) input.value = value;
    var stamp = document.querySelector('form.stamp-form input[name="cardId"]');
    if (stamp) stamp.value = value;
    // Trigger the existing search exactly like its submit button does: the
    // STAFF_SCRIPT submit listener on #sp-code-search runs the GET
    // search-code lookup and renders the found card with a stamp button.
    var form = byId('sp-code-search');
    if (form) {
      var ev;
      try { ev = new Event('submit', { bubbles: true, cancelable: true }); }
      catch (err) { ev = document.createEvent('Event'); ev.initEvent('submit', true, true); }
      form.dispatchEvent(ev);
    }
  }
  function onScanValue(raw) {
    if (!scan.open || scan.done) return;
    var value = normalizeScannedTarget(raw);
    if (!value) return;
    scan.done = true;
    closeScan();
    fillTargets(value);
  }
  function stopCamera() {
    if (scan.timer) { clearInterval(scan.timer); scan.timer = null; }
    if (scan.stream) {
      var tracks = scan.stream.getTracks();
      for (var i = 0; i < tracks.length; i++) { try { tracks[i].stop(); } catch (err) {} }
      scan.stream = null;
    }
    if (scan.reader) { try { scan.reader.reset(); } catch (err) {} scan.reader = null; }
    if (scan.video) {
      try { scan.video.srcObject = null; } catch (err) { scan.video.removeAttribute('src'); }
    }
  }
  function closeScan() {
    scan.open = false;
    stopCamera();
    if (scan.modal) scan.modal.hidden = true;
  }
  function zxingHints() {
    var hints = new Map();
    hints.set(ZXing.DecodeHintType.POSSIBLE_FORMATS, [ZXing.BarcodeFormat.CODE_128, ZXing.BarcodeFormat.QR_CODE]);
    return hints;
  }
  function zxingDecodeFrame(video) {
    var reader = new ZXing.BrowserMultiFormatReader(zxingHints(), 120);
    scan.reader = reader;
    reader.decodeFromVideoElement(video).then(function (result) {
      if (!scan.open) return;
      var text = result && result.getText ? result.getText() : '';
      if (text) onScanValue(text);
    }).catch(function () {
      // NotFound/stream hiccup: keep scanning with a fresh attempt.
      if (scan.open) setTimeout(function () { zxingDecodeFrame(video); }, 200);
    });
  }
  function startZxing(video) {
    if (typeof ZXing === 'undefined') {
      setStatus('Decoder wird geladen …');
      loadZxing(function () { if (scan.open) zxingDecodeFrame(video); });
      return;
    }
    zxingDecodeFrame(video);
  }
  function startDecode(video) {
    if (window.BarcodeDetector) {
      try {
        var det = new BarcodeDetector({ formats: ['code_128', 'qr_code'] });
        scan.timer = setInterval(function () {
          if (!scan.open) return;
          det.detect(video).then(function (codes) {
            if (!scan.open || !codes || !codes.length) return;
            var v = codes[0].rawValue;
            if (v) onScanValue(v);
          }).catch(function () {});
        }, 180);
        return;
      } catch (err) { /* no BarcodeDetector → zxing fallback */ }
    }
    startZxing(video);
  }
  function startCamera() {
    setStatus('Kartencode auf dem Kundenhandy anvisieren …');
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      setStatus('Live-Kamera nicht verfügbar — bitte „Foto verwenden" nutzen.');
      return;
    }
    navigator.mediaDevices.getUserMedia({ audio: false, video: { facingMode: { ideal: 'environment' } } }).then(function (stream) {
      if (!scan.open) { var ts = stream.getTracks(); for (var k = 0; k < ts.length; k++) ts[k].stop(); return; }
      scan.stream = stream;
      try { scan.video.srcObject = stream; } catch (err) { scan.video.src = URL.createObjectURL(stream); }
      var p = scan.video.play();
      if (p && p.catch) p.catch(function () {});
      var tries = 0;
      var ready = setInterval(function () {
        if (!scan.open) { clearInterval(ready); return; }
        if (scan.video.readyState >= 2) { clearInterval(ready); startDecode(scan.video); }
        else if (++tries > 40) { clearInterval(ready); setStatus('Kamera wird nicht bereit — bitte „Foto verwenden" nutzen.'); }
      }, 150);
    }).catch(function () {
      if (scan.open) setStatus('Kamera nicht verfügbar oder Zugriff verweigert — bitte „Foto verwenden" nutzen.');
    });
  }
  function openScan() {
    if (scan.open) return;
    scan.open = true;
    scan.done = false;
    if (scan.file) scan.file.value = '';
    if (scan.modal) scan.modal.hidden = false;
    startCamera();
  }
  function loadZxing(cb) {
    if (typeof ZXing !== 'undefined') { cb(); return; }
    var s = document.createElement('script');
    s.src = '/vendor/zxing.min.js';
    s.onload = cb;
    s.onerror = function () { setStatus('Decoder konnte nicht geladen werden.'); };
    document.head.appendChild(s);
  }
  /** Downscale a picked photo before decoding (iOS photos are ~12MP; a long
   *  side of 1280px is plenty for a barcode and keeps decode fast in RAM). */
  function downscaledDataUrl(img, cb) {
    var MAX = 1280;
    var w = img.naturalWidth || img.width;
    var h = img.naturalHeight || img.height;
    if (!w || !h) { cb(img.src); return; }
    var scale = Math.min(1, MAX / Math.max(w, h));
    if (scale >= 1) { cb(img.src); return; }
    var c = document.createElement('canvas');
    c.width = Math.round(w * scale);
    c.height = Math.round(h * scale);
    var ctx = c.getContext('2d');
    if (!ctx) { cb(img.src); return; }
    ctx.drawImage(img, 0, 0, c.width, c.height);
    cb(c.toDataURL('image/jpeg', 0.85));
  }
  function decodeFile(file) {
    if (scan.done) return;
    setStatus('Foto wird gelesen …');
    stopCamera();
    var url = URL.createObjectURL(file);
    var img = new Image();
    img.onload = function () {
      loadZxing(function () {
        downscaledDataUrl(img, function (src) {
          if (src !== url) URL.revokeObjectURL(url);
          var dec = new Image();
          dec.onload = function () {
            var reader = new ZXing.BrowserMultiFormatReader(zxingHints(), 120);
            reader.decodeFromImageElement(dec).then(function (result) {
              var text = result && result.getText ? result.getText() : '';
              if (text) { URL.revokeObjectURL(url); onScanValue(text); }
              else { URL.revokeObjectURL(url); scan.done = false; setStatus('Kein Code im Foto gefunden. Bitte erneut versuchen.'); }
            }).catch(function () {
              URL.revokeObjectURL(url);
              scan.done = false;
              setStatus('Kein Code im Foto gefunden. Bitte erneut versuchen.');
            });
          };
          dec.onerror = function () { URL.revokeObjectURL(url); scan.done = false; setStatus('Foto konnte nicht gelesen werden.'); };
          dec.src = src;
        });
      });
    };
    img.onerror = function () { URL.revokeObjectURL(url); scan.done = false; setStatus('Foto konnte nicht gelesen werden.'); };
    img.src = url;
  }
  // Delegated click: survives every dashboard #sp-app swap.
  document.addEventListener('click', function (ev) {
    var el = ev.target && ev.target.closest ? ev.target.closest('.sp-scan-btn') : null;
    if (!el) return;
    ev.preventDefault();
    openScan();
  });
  function bindModal() {
    scan.modal = byId('sp-scan-modal');
    scan.video = byId('sp-scan-video');
    scan.status = byId('sp-scan-status');
    scan.file = byId('sp-scan-file');
    var close = byId('sp-scan-close');
    if (close) close.addEventListener('click', function () { closeScan(); });
    if (scan.file) scan.file.addEventListener('change', function () {
      var f = scan.file.files && scan.file.files[0];
      if (f) decodeFile(f);
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bindModal);
  else bindModal();
})();
</script>`;
}