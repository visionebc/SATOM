/* Plugin Studio > Examples pane (studio/index.html): install an example
 * bundle. Server side: app/views/studio.py (example_install) and
 * app/services/studio_examples.py, which never overwrites an object that
 * already exists. Installed examples are templates: there is no Remove
 * (operator, 2026-10-23); an app is disabled or reset from the Apps pane.
 */
(function () {
  'use strict';
  var cfgEl = document.getElementById('ex-config');
  if (!cfgEl) return;
  var CFG = JSON.parse(cfgEl.textContent);
  var meta = document.querySelector('meta[name="csrf-token"]');
  var CSRF = meta ? meta.getAttribute('content') : '';
  var box = document.getElementById('exMsg');
  function msg(text, bad) {
    if (!box) return;
    box.textContent = text;
    box.className = 'small mb-2 ' + (bad ? 'text-danger' : 'text-success');
  }
  function post(url) {
    return fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'X-CSRFToken': CSRF, 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body: '{}'
    }).then(function (r) {
      return r.json().catch(function () { return { error: 'HTTP ' + r.status }; }).then(function (d) {
        if (!r.ok || d.ok === false) throw new Error(d.error || ('HTTP ' + r.status));
        return d;
      });
    });
  }
  function done(d, verb) {
    var parts = [];
    if (d.created && d.created.length) parts.push('created ' + d.created.join(', '));
    if (d.kept && d.kept.length) parts.push('kept ' + d.kept.join(', '));
    msg(verb + ': ' + (parts.join('; ') || 'nothing to do') + '.');
    window.setTimeout(function () { window.location = CFG.back; }, 1200);
  }
  document.addEventListener('click', function (ev) {
    var b = ev.target.closest('[data-ex-install]');
    if (!b) return;
    var key = b.getAttribute('data-ex-install');
    b.disabled = true;
    post(CFG.install.replace('KEY', encodeURIComponent(key)))
      .then(function (d) { done(d, 'Installed'); })
      .catch(function (e) { b.disabled = false; msg(e.message, true); });
  });
})();
