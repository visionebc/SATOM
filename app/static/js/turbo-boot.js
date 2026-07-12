/* turbo-boot.js — configure Turbo Drive for this multi-page app so background
 * jobs (firmware uploads) survive page navigation. Loaded in <head> BEFORE any
 * body script, so its DOMContentLoaded compatibility shim is installed before the
 * page's inline init runs.
 *
 * WHY (the whole point): Turbo Drive replaces navigation with fetch+swap so the
 * JS runtime — and any in-flight XHR upload held by jobs.js — is NEVER torn down.
 * Two things a naive drop-in would break, handled here:
 *
 *  1. Pages init on `DOMContentLoaded`, which fires only on the FIRST load, never
 *     on a Turbo visit. We remap every
 *     `document.addEventListener('DOMContentLoaded', fn)` to Turbo's per-visit
 *     `turbo:load` (once per visit), running it immediately if the visit already
 *     loaded (a late/async script). This is why the 37 templates that use
 *     DOMContentLoaded keep initialising after a Turbo visit WITH NO per-page
 *     edit. Correct ONLY for body scripts (which re-run each visit and thus
 *     re-register); head scripts must use `turbo:load` directly (jobs.js does).
 *
 *  2. Forms. Form mode is set OPT-IN: form submits do a normal full-page (native)
 *     submit, sidestepping Turbo's 303-redirect requirement and every form-render
 *     edge case. Only LINK navigation is Turbo-driven — which is all that is
 *     needed for an upload to survive the user clicking around the app.
 *
 *  3. Downloads. Anchors that stream a file (…/download or [download]) are marked
 *     data-turbo="false" on every render so Turbo lets the browser download them
 *     natively instead of trying to render a binary.
 */
(function () {
  'use strict';
  if (!window.Turbo) return;   // Turbo failed to load → app behaves exactly as before.

  // Links = Turbo (client-side, preserves the runtime). Forms = native submit.
  try { window.Turbo.setFormMode('optin'); } catch (e) {}

  // Show progress bar immediately (default is 500ms delay).
  try { window.Turbo.setProgressBarDelay(0); } catch (e) {}

  var origAdd = document.addEventListener.bind(document);

  // ── DOMContentLoaded → turbo:load compatibility shim ────────────────────────
  var pageLoaded = (document.readyState !== 'loading');
  origAdd('turbo:load', function () { pageLoaded = true; });
  origAdd('turbo:before-render', function () { pageLoaded = false; });
  origAdd('turbo:visit', function () { pageLoaded = false; });

  document.addEventListener = function (type, listener, opts) {
    if (type === 'DOMContentLoaded' && typeof listener === 'function') {
      if (pageLoaded) {
        // This visit already fired turbo:load (a late/async body script) — run now.
        try { listener.call(document, new Event('DOMContentLoaded')); }
        catch (e) { if (window.console && console.error) console.error(e); }
      } else {
        // Run on THIS visit's turbo:load then auto-remove; the body script
        // re-registers a fresh one on the next visit → no accumulation.
        origAdd('turbo:load', listener, { once: true });
      }
      return;
    }
    return origAdd(type, listener, opts);
  };

  // ── Navigation loading feedback (progress bar + content dim) ─────────────────
  origAdd('turbo:visit', function () {
    var main = document.getElementById('fw-main');
    if (main) main.classList.add('fw-navigating');
  });
  origAdd('turbo:load', function () {
    var main = document.getElementById('fw-main');
    if (!main) return;
    main.classList.remove('fw-navigating');
    // Cross-fade the freshly-rendered page in. Self-clean on animationend so
    // it re-triggers on the next visit.
    main.classList.add('fw-entering');
    main.addEventListener('animationend', function handler() {
      main.classList.remove('fw-entering');
      main.removeEventListener('animationend', handler);
    });
  });
  // Safety: clear dim if render happens without a load (cached pages).
  origAdd('turbo:before-render', function () {
    var main = document.getElementById('fw-main');
    if (main) main.classList.remove('fw-navigating');
  });

  // ── Let file downloads go native (Turbo would try to render the binary) ─────
  origAdd('turbo:load', function () {
    var links = document.querySelectorAll('a[href*="/download"], a[download]');
    for (var i = 0; i < links.length; i++) links[i].setAttribute('data-turbo', 'false');
  });

  // ── Per-tab ADOM ────────────────────────────────────────────────────────────
  // The ADOM in the session cookie is shared by EVERY tab, so switching ADOM
  // in one tab used to flip all the others on their next navigation. The
  // per-tab truth is sessionStorage.fmAdom (sessionStorage is per-tab and is
  // copied on tab-duplicate), sent as X-ADOM on every Turbo fetch; the server
  // resolves URL scope > X-ADOM > session, so this tab keeps its ADOM until
  // the user explicitly changes it (or navigates to a URL-scoped page).
  // An EXPLICIT ADOM switch (/product/enter/<key>) must move THIS TAB's truth
  // at click time: enter() writes the session, but the redirect chain re-sends
  // the tab's stale X-ADOM header (fetch keeps request headers across
  // same-origin redirects), which outranks the fresh session — a fortiadc tab
  // switching to fortiweb landed on a fortiweb-scoped page still carrying
  // X-ADOM: fortiadc and the gate bounced it right back to /adc/ (trapped).
  function fwAdomSwitchKey(href) {
    var m = /\/product\/enter\/([a-z][a-z0-9_-]*)(?:[/?#]|$)/.exec(String(href || ''));
    return m ? m[1] : null;
  }
  origAdd('click', function (e) {
    try {
      var a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
      var key = a && fwAdomSwitchKey(a.getAttribute('href'));
      if (key) sessionStorage.setItem('fmAdom', key);
    } catch (err) {}
  }, true);
  origAdd('turbo:before-fetch-request', function (e) {
    try {
      var key = e.detail && fwAdomSwitchKey(e.detail.url);
      if (key) sessionStorage.setItem('fmAdom', key);
      var adom = sessionStorage.getItem('fmAdom');
      if (adom && e.detail && e.detail.fetchOptions && e.detail.fetchOptions.headers) {
        e.detail.fetchOptions.headers['X-ADOM'] = adom;
      }
    } catch (err) {}
  });
  // Native (non-Turbo) form posts can't carry headers — stamp the tab's ADOM
  // as a hidden field instead (the server reads _adom on urlencoded posts).
  origAdd('submit', function (e) {
    try {
      var f = e.target;
      if (!f || f.nodeName !== 'FORM' || (f.method || '').toLowerCase() === 'get') return;
      if ((f.enctype || '').indexOf('multipart') === 0) return;
      // The product-select form is itself an explicit ADOM switch — adopt the
      // chosen product as this tab's truth before the post goes out.
      if ((f.getAttribute('action') || '').indexOf('/product/select') !== -1) {
        var chosen = f.querySelector('[name="product"]:checked') ||
                     f.querySelector('[name="product"]');
        if (chosen && chosen.value) sessionStorage.setItem('fmAdom', chosen.value);
      }
      var adom = sessionStorage.getItem('fmAdom');
      if (!adom) return;
      var inp = f.querySelector('input[name="_adom"]');
      if (!inp) {
        inp = document.createElement('input');
        inp.type = 'hidden';
        inp.name = '_adom';
        f.appendChild(inp);
      }
      inp.value = adom;
    } catch (err) {}
  }, true);
  origAdd('turbo:load', function () {
    try {
      var meta = document.querySelector('meta[name="current-product"]');
      var cur = meta && meta.content;
      if (!cur) return;
      var want = sessionStorage.getItem('fmAdom');
      if (want && want !== cur && !window.__fwAdomRealign) {
        // A full reload (F5 / new document) went out WITHOUT the header, so
        // the server rendered the session's ADOM, not this tab's. Re-visit
        // once via Turbo (which carries X-ADOM); if the mismatch persists
        // (URL scope won — an explicit scoped page), adopt it below instead.
        window.__fwAdomRealign = true;
        window.Turbo.visit(location.href, { action: 'replace' });
        return;
      }
      window.__fwAdomRealign = false;
      // Adopt whatever this tab is actually showing — a rendered page IS the
      // tab's ADOM (covers ADOM switches, URL-scoped jumps and fresh tabs).
      sessionStorage.setItem('fmAdom', cur);
    } catch (err) {}
  });

  // ── Re-stamp <style> + <script> nonces on Turbo navigation ─────────────────────────────
  // CSP is bound to the ORIGINAL full-load document (its response's nonce);
  // Turbo never creates a new document, so that nonce stays enforced for the
  // whole Turbo session. Turbo re-inserts body <script>/<style> carrying the
  // FETCHED response's (different, per-request) nonce, which no longer matches
  // — the browser CSP-blocks them. With script/style-src-elem nonce-gated
  // (no 'unsafe-inline'), a body <style> rendered with THIS response's nonce is
  // refused under the ACTIVE document CSP (the original load's nonce) — the page
  // renders UNSTYLED after a Turbo visit but fine on a full refresh. Re-stamp
  // every incoming body <style> with the live meta nonce BEFORE the swap so it
  // matches the active CSP (no flash of unstyled content).
  origAdd('turbo:before-render', function (e) {
    var body = e && e.detail && e.detail.newBody;
    if (!body) return;
    var meta = document.querySelector('meta[name=csp-nonce]');
    var nonce = meta && (meta.nonce || meta.content);
    if (!nonce) return;
    // Both <style> AND <script>: Turbo re-creates each incoming body <script>
    // via activateScriptElement, whose copyAttributes() copies the FETCHED
    // response's nonce LAST — clobbering the meta nonce — so the re-inserted
    // script carries the fetched nonce, not the active document's. Re-stamping
    // the source node here (before the swap) makes that copy land the live
    // (active-document) nonce, so it matches the enforced CSP.
    var nodes = body.querySelectorAll('style, script');
    for (var i = 0; i < nodes.length; i++) {
      try { nodes[i].nonce = nonce; } catch (err) {}
      nodes[i].setAttribute('nonce', nonce);
    }
  });
})();
