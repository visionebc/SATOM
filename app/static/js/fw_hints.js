/* fw_hints.js — turns every `[data-fw-hint]` "?" into a readable panel of prose.
 *
 * Three decisions here are the whole file, and each one is a defect avoided:
 *
 *  1. `container: 'body'`, pinned rather than assumed. Bootstrap 5 already
 *     defaults to <body>, so this is a LOCK, not a fix. The thing it locks
 *     out is real and measured: parented inside `.fw-card` (which is
 *     `overflow: hidden`) a 132px panel in a 123px card paints 58px and the
 *     rest is clipped away — and a paragraph cut in half still looks like a
 *     working tooltip. Anything that re-parents it (a Bootstrap 4-style
 *     default, a well-meant `container: '.fw-card'`) silently halves the
 *     text, so the value is pinned here and frozen by a guard.
 *
 *  2. Disposal on `turbo:before-render`. Turbo swaps the body without ever
 *     creating a new document; the tooltip elements Popper appended to <body>
 *     are NOT part of that swap, so without this every visit leaves its
 *     tooltips behind and a hover can pop up help for a control that is no
 *     longer on the page.
 *
 *  3. `init()` disposes first, so it is idempotent. Both `turbo:load` and the
 *     DOMContentLoaded shim in turbo-boot.js can fire it on the same visit;
 *     initialising twice would give two panels per icon.
 *
 * Degrades to the browser's native tooltip if Bootstrap is unavailable: the
 * text lives in the `title` attribute, and this file only ever upgrades it.
 *
 * Loads in <head>, AFTER bootstrap.bundle: a head script runs ONCE and
 * persists across Turbo visits, so its two document listeners are registered
 * once. In the body block (which Turbo re-executes every visit) each visit
 * would add another pair — the accumulation this file exists to prevent.
 * `jobs.js` sits in <head> for the same reason; the boot guard below covers
 * the case of it being pulled in twice anyway.
 */
(function () {
  'use strict';

  if (window.__fwHintsBooted) return;
  window.__fwHintsBooted = true;

  var live = [];

  function dispose() {
    for (var i = 0; i < live.length; i++) {
      try { live[i].dispose(); } catch (e) {}
    }
    live = [];
  }

  function init() {
    dispose();
    if (!window.bootstrap || !window.bootstrap.Tooltip) return;
    var nodes = document.querySelectorAll('[data-fw-hint]');
    for (var i = 0; i < nodes.length; i++) {
      try {
        live.push(new window.bootstrap.Tooltip(nodes[i], {
          container: 'body',
          customClass: 'fw-hint-tip',
          trigger: 'hover focus',
          placement: 'top',
          fallbackPlacements: ['top', 'bottom', 'right', 'left']
        }));
      } catch (e) {}
    }
  }

  document.addEventListener('turbo:before-render', dispose);
  document.addEventListener('turbo:load', init);
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
