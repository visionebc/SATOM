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

  // ── Let file downloads go native (Turbo would try to render the binary) ─────
  origAdd('turbo:load', function () {
    var links = document.querySelectorAll('a[href*="/download"], a[download]');
    for (var i = 0; i < links.length; i++) links[i].setAttribute('data-turbo', 'false');
  });
})();
