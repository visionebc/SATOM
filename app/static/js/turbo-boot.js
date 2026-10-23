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
  // Turbo.config is the current API; the top-level setters are deprecated
  // (a console warning on every full load) and kept only as the fallback.
  var tcfg = window.Turbo.config;
  try {
    if (tcfg && tcfg.forms) tcfg.forms.mode = 'optin';
    else window.Turbo.setFormMode('optin');
  } catch (e) {}

  // Show progress bar immediately (default is 500ms delay).
  try {
    if (tcfg && tcfg.drive) tcfg.drive.progressBarDelay = 0;
    else window.Turbo.setProgressBarDelay(0);
  } catch (e) {}

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

  // ── Page-scoped listeners: fwPageSignal() ───────────────────────────────────
  // `document` outlives every Turbo visit, and a body script re-runs on each
  // one. A body script that does document.addEventListener('click', fn) adds
  // ANOTHER fn per visit: after two visits to Deep monitors one click on a
  // chart opened the modal twice, two backdrops were stacked, closing removed
  // one and the screen stayed dimmed (2026-10-23). Pass
  // { signal: fwPageSignal() } and the listener is dropped when the next page
  // renders. Opt-in on purpose: ~15 scripts bind ONCE behind a window.__x
  // guard, and removing those automatically would leave them unbound.
  // tests/test_page_scoped_listeners.py ratchets the scripts that still don't.
  var pageCtl = null;
  window.fwPageSignal = function () {
    if (!pageCtl && typeof AbortController === 'function') pageCtl = new AbortController();
    return pageCtl ? pageCtl.signal : undefined;
  };
  origAdd('turbo:before-render', function () {
    if (pageCtl) { pageCtl.abort(); pageCtl = null; }
  });

  // ── Orphaned modal backdrops ─────────────────────────────────────────────────
  // Two Modal instances on one element (a doubled handler, `new
  // bootstrap.Modal(el)` called twice) leave a backdrop that no instance owns:
  // the dialog closes and the page stays dark and unclickable. When the last
  // open modal is hidden, nothing may still be dimming the page.
  origAdd('hidden.bs.modal', function () {
    if (document.querySelector('.modal.show, .modal[style*="display: block"]')) return;
    var stale = document.querySelectorAll('.modal-backdrop');
    for (var i = 0; i < stale.length; i++) stale[i].remove();
    document.body.classList.remove('modal-open');
    document.body.style.removeProperty('overflow');
    document.body.style.removeProperty('padding-right');
  });

  // ── Navigation loading feedback (progress bar + content dim) ─────────────────
  // Selecting an ADOM (/product/enter/<key>) swaps the whole chrome -- topbar
  // banner, sidebar menu, device switcher -- not just #fw-main, so a fade
  // limited to the content column is invisible. For ADOM switches cross-fade
  // the ENTIRE page; ordinary visits keep the light content-only fade so
  // normal navigation stays snappy.
  var fullPageNext = false;
  origAdd('turbo:visit', function (e) {
    var url = (e && e.detail && e.detail.url) || '';
    fullPageNext = url.indexOf('/product/enter/') !== -1;
    var main = document.getElementById('fw-main');
    if (main) main.classList.add('fw-navigating');
  });
  origAdd('turbo:load', function () {
    var main = document.getElementById('fw-main');
    if (main) main.classList.remove('fw-navigating');
    var whole = fullPageNext;
    fullPageNext = false;
    // Selecting a device is a native full-page POST (/architecture/select),
    // so it never rides turbo:visit. A flag set at submit time survives the
    // reload; consume it here to cross-fade the whole page in, same as ADOM.
    try { if (sessionStorage.getItem('fmDeviceEnter') === '1') { whole = true; sessionStorage.removeItem('fmDeviceEnter'); } } catch (e) {}
    var target = whole ? document.body : main;
    if (!target) return;
    var cls = whole ? 'fw-entering-page' : 'fw-entering';
    // Reduced motion: fortiweb.css sets `animation: none`, so animationend
    // never fires and the class would stay for the life of the page. While it
    // stays, its will-change:transform makes #fw-main a stacking context that
    // traps every modal inside it beneath Bootstrap's body-level backdrop: the
    // form is visible and cannot be clicked. No fade, no class.
    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    // Cross-fade the freshly-rendered view in. Self-clean on animationend or
    // animationcancel; guard on ev.target so a child's animation event
    // (gradient buttons, skeleton shimmer) bubbling up cannot cut the page
    // fade short. The timer is the last resort: removal never depends on a
    // single event arriving (the fade itself lasts 0.45 s).
    target.classList.add(cls);
    var done = function (ev) {
      if (ev && ev.target !== target) return;
      target.classList.remove(cls);
      target.removeEventListener('animationend', done);
      target.removeEventListener('animationcancel', done);
    };
    target.addEventListener('animationend', done);
    target.addEventListener('animationcancel', done);
    setTimeout(done, 1000);
  });
  // Safety: clear dim/fade if render happens without a load (cached pages).
  origAdd('turbo:before-render', function () {
    var main = document.getElementById('fw-main');
    if (main) main.classList.remove('fw-navigating');
    document.body.classList.remove('fw-entering-page');
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

  // ── Keep body <script> ORDER on Turbo visits ─────────────────────────────────
  // On a full load the parser runs an external <script src> to completion
  // before the inline <script> that follows it. Turbo re-inserts body scripts
  // programmatically: the inline copy runs AT ONCE, the external copy only
  // after its fetch. So an inline init that calls the external file's global
  // (initERDiagram, ExampleBrowser, ReportBuilder…) threw "is not defined"
  // after every Turbo visit and the page only worked after a refresh — and a
  // throw at the top of an inline IIFE also left every later handler in it
  // (Python Console's Run button) unwired.
  // Fix, once for every page: before the swap, park each executable inline
  // script that FOLLOWS an external one (type → text/x-fm-deferred, so
  // Turbo's copy does not run); after the swap, walk the body scripts in
  // document order and run a parked one only when every external script
  // before it has loaded (or failed). Same order as a full load.
  var DEFERRED = 'text/x-fm-deferred';
  var JS_TYPES = { '': 1, 'text/javascript': 1, 'application/javascript': 1, 'module': 1 };
  var settled = (typeof WeakSet === 'function') ? new WeakSet() : null;
  var walk = null;
  function blocking(s) {
    return s.hasAttribute('src') && !s.hasAttribute('async')
      && s.getAttribute('data-turbo-eval') !== 'false';
  }
  function pump() {
    var w = walk;
    if (!w) return;
    while (w.i < w.items.length) {
      var s = w.items[w.i];
      if (blocking(s)) {
        if (s.isConnected && settled && !settled.has(s)) return;  // wait for it
      } else if (s.getAttribute('type') === DEFERRED && s.isConnected) {
        var n = document.createElement('script');
        var meta = document.querySelector('meta[name=csp-nonce]');
        var nonce = s.nonce || s.getAttribute('nonce') || (meta && (meta.nonce || meta.content)) || '';
        if (nonce) n.nonce = nonce;
        var t = s.getAttribute('data-fm-type');
        if (t) n.type = t;
        n.textContent = s.textContent;
        s.parentNode.replaceChild(n, s);   // inline script: runs synchronously
      }
      w.i++;
    }
    if (walk === w) walk = null;
  }
  function onSettle(e) {
    var s = e && e.target;
    if (!s || s.tagName !== 'SCRIPT') return;
    if (settled) settled.add(s);
    pump();
  }
  // load/error do not bubble; capture on document sees every <script>.
  origAdd('load', onSettle, true);
  origAdd('error', onSettle, true);
  origAdd('turbo:before-render', function (e) {
    var body = e && e.detail && e.detail.newBody;
    if (!body || !settled) return;
    walk = null;   // a new visit cancels the previous page's pending walk
    var afterExternal = false;
    var nodes = body.querySelectorAll('script');
    for (var i = 0; i < nodes.length; i++) {
      var s = nodes[i];
      if (blocking(s)) { afterExternal = true; continue; }
      if (s.hasAttribute('src') || s.getAttribute('data-turbo-eval') === 'false') continue;
      var t = (s.getAttribute('type') || '').trim().toLowerCase();
      if (!afterExternal || !JS_TYPES.hasOwnProperty(t)) continue;  // JSON islands stay as they are
      if (t) s.setAttribute('data-fm-type', t);
      s.setAttribute('type', DEFERRED);
    }
  });
  origAdd('turbo:render', function () {
    if (!settled) return;
    walk = { items: Array.prototype.slice.call(document.body.querySelectorAll('script')), i: 0 };
    pump();
  });
})();
