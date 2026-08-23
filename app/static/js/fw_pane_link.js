/* fw_pane_link.js — a button OUTSIDE the tab list that reveals a pane.
 *
 * `data-bs-toggle="tab"` does NOT work here, and it fails in the one way a
 * button cannot report: silently. Bootstrap 5.3's Tab constructor resolves
 * its tab list with
 *
 *     this._parent = this._element.closest('.list-group, .nav, [role="tablist"]')
 *
 * and simply RETURNS when that finds nothing. The element still matches the
 * click data-api, so `show()` still runs — straight into
 * `querySelectorAll.call(undefined, ...)`, which throws `Illegal invocation`
 * inside Bootstrap's own handler. Nothing is logged by the app, the markup is
 * valid, the route is 200, every server-side test passes, and the operator
 * gets a button that does nothing. Measured in chromium with the app's real
 * CSP: two such buttons (Response engine -> Response policy, Architecture ->
 * Incidents console), both inert, two `Illegal invocation` errors.
 *
 * So the click is DELEGATED to the menu entry that already owns the pane:
 *
 *  1. It is the trigger Bootstrap can actually construct — it lives inside
 *     `<aside class="nav" role="tablist">`.
 *  2. It keeps the menu honest. The settings accordion folds groups from
 *     clicks on its own entries and from `shown.bs.tab` fired ON them;
 *     activating the pane from out here would reveal a section while the menu
 *     still highlights another one.
 *
 * `data-fw-pane-href` is the fallback, and it is required rather than
 * optional: on a surface where the pane does not exist (the standalone pages,
 * a caller whose permissions hide that menu entry) the button must still go
 * somewhere. A silent no-op is the defect this file exists to remove, so it
 * is not an available outcome.
 *
 * Delegated from `document`, in <head>: one listener for the life of the tab,
 * covering panes that Turbo swaps in later. The body block re-executes on
 * every Turbo visit and would stack a listener per visit.
 */
(function () {
  'use strict';

  if (window.__fwPaneLinkBooted) return;
  window.__fwPaneLinkBooted = true;

  var TABLIST = '.list-group, .nav, [role="tablist"]';

  document.addEventListener('click', function (ev) {
    var btn = ev.target && ev.target.closest ? ev.target.closest('[data-fw-pane]') : null;
    if (!btn) return;

    ev.preventDefault();

    var sel = btn.getAttribute('data-fw-pane') || '';
    var href = btn.getAttribute('data-fw-pane-href') || '';
    var trigger = null;

    if (sel) {
      var candidates = document.querySelectorAll('[data-bs-target="' + sel + '"]');
      for (var i = 0; i < candidates.length; i++) {
        if (candidates[i] !== btn && candidates[i].closest(TABLIST)) {
          trigger = candidates[i];
          break;
        }
      }
    }

    if (trigger) { trigger.click(); return; }
    if (href) { window.location.href = href; }
  });
})();
