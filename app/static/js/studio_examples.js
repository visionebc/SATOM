/* Python Studio > Examples pane (studio/index.html): install or remove an
 * example bundle. Server side: app/views/studio.py (example_install,
 * example_remove) and app/services/studio_examples.py, which never
 * overwrites an object that already exists and keeps any object something
 * else still uses.
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
    if (d.removed && d.removed.length) parts.push('removed ' + d.removed.join(', '));
    if (d.kept && d.kept.length) parts.push('kept ' + d.kept.join(', '));
    msg(verb + ': ' + (parts.join('; ') || 'nothing to do') + '.');
    window.setTimeout(function () { window.location = CFG.back; }, 1200);
  }
  document.addEventListener('click', function (ev) {
    var b = ev.target.closest('[data-ex-install],[data-ex-remove]');
    if (!b) return;
    var install = b.hasAttribute('data-ex-install');
    var key = b.getAttribute(install ? 'data-ex-install' : 'data-ex-remove');
    if (!install && !window.confirm('Remove the objects of this example? Rows in its data stores are deleted with them; objects something else uses are kept.')) return;
    b.disabled = true;
    post((install ? CFG.install : CFG.remove).replace('KEY', encodeURIComponent(key)))
      .then(function (d) { done(d, install ? 'Installed' : 'Removed'); })
      .catch(function (e) { b.disabled = false; msg(e.message, true); });
  });
})();
