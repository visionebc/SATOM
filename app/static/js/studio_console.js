/* Python Studio > Console — the scratch console (studio/_console.html).
 * Runs the textarea through studio.console_run with the ticked datasets and
 * shows stdout / stderr. Used by the Studio page and the script editor's
 * Console tab. Server side: app/views/studio.py, app/services/py_console.py.
 */
(function () {
  'use strict';

  var cfgEl = document.getElementById('pyc-config');
  if (!cfgEl) return;
  var CFG = {};
  try { CFG = JSON.parse(cfgEl.textContent) || {}; } catch (e) { return; }
  var metaTok = document.querySelector('meta[name="csrf-token"]');
  var CSRF = metaTok ? metaTok.getAttribute('content') : '';

  var srcEl = document.getElementById('pyc-src');
  var runBtn = document.getElementById('pyc-run');
  var statusEl = document.getElementById('pyc-status');
  var outEl = document.getElementById('pyc-stdout');
  var errWrap = document.getElementById('pyc-stderr-wrap');
  var errEl = document.getElementById('pyc-stderr');
  if (!srcEl || !runBtn) return;

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function boxes() { return document.querySelectorAll('.pyc-ds'); }

  if (window.ExampleBrowser) {
    window.ExampleBrowser.init({
      previewField: 'code',
      onInsert: function (ex) {
        srcEl.value = ex.code || ex.src || '';
        var want = ex.datasets || [];
        Array.prototype.forEach.call(boxes(), function (c) { c.checked = want.indexOf(c.value) >= 0; });
        srcEl.focus();
      }
    });
  }

  function run() {
    var keys = Array.prototype.filter.call(boxes(), function (c) { return c.checked; })
      .map(function (c) { return c.value; });
    runBtn.disabled = true;
    statusEl.innerHTML = '<span class="text-muted"><span class="spinner-border spinner-border-sm"></span> Running in the sandbox…</span>';
    outEl.textContent = '';
    errWrap.style.display = 'none';
    errEl.textContent = '';
    fetch(CFG.run, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF, 'Accept': 'application/json' },
      body: JSON.stringify({ source: srcEl.value, datasets: keys })
    }).then(function (r) {
      return r.json().catch(function () { return { error: 'HTTP ' + r.status }; })
        .then(function (d) { if (!r.ok) { throw new Error(d.error || ('HTTP ' + r.status)); } return d; });
    }).then(function (d) {
      runBtn.disabled = false;
      var badge;
      if (d.timed_out) { badge = '<span class="fw-badge fw-badge-warning">timed out</span>'; }
      else if (d.ok) { badge = '<span class="fw-badge fw-badge-success">ok</span>'; }
      else { badge = '<span class="fw-badge fw-badge-danger">exit ' + (d.returncode === null ? 'killed' : esc(d.returncode)) + '</span>'; }
      var ds = (d.datasets && d.datasets.length) ? d.datasets.join(', ') : 'none';
      statusEl.innerHTML = badge + ' <span class="text-muted">' + esc(d.duration_ms || 0) + ' ms · datasets: ' + esc(ds) + '</span>';
      outEl.textContent = d.stdout || '(no output)';
      if (d.stderr) { errWrap.style.display = 'block'; errEl.textContent = d.stderr; }
    }).catch(function (err) {
      runBtn.disabled = false;
      statusEl.innerHTML = '<span style="color:#8B1C2A;">Request failed: ' + esc(err.message || err) + '</span>';
    });
  }

  runBtn.addEventListener('click', run);
  srcEl.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); run(); }
  });
})();
