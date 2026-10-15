/* Operations → Automation → Scripts → one script: run now, cron preview and
 * saved runs. Server side: app/views/scripts.py, services/script_schedules.py.
 */
(function () {
  'use strict';
  var cfgEl = document.getElementById('sc-config');
  if (!cfgEl) return;
  var CFG = {};
  try { CFG = JSON.parse(cfgEl.textContent) || {}; } catch (e) { return; }
  var U = CFG.urls || {};
  var metaTok = document.querySelector('meta[name="csrf-token"]');
  var CSRF = metaTok ? metaTok.getAttribute('content') : '';
  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function post(url, body) {
    return fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF, 'Accept': 'application/json' },
      body: JSON.stringify(body || {})
    }).then(function (r) {
      return r.json().catch(function () { return { error: 'HTTP ' + r.status }; })
        .then(function (d) { if (!r.ok) { throw new Error(d.error || ('HTTP ' + r.status)); } return d; });
    });
  }
  var form = $('sc-form');
  form.addEventListener('submit', function (e) { e.preventDefault(); });
  function values() {
    var out = {};
    (CFG.fields || []).forEach(function (f) {
      var el = form.querySelector('[name="' + f.name + '"]');
      if (!el) return;
      if (f.type === 'checkbox') out[f.name] = el.checked;
      else if (f.type === 'lookup_multi') out[f.name] = Array.prototype.filter.call(el.options, function (o) { return o.selected && o.value; }).map(function (o) { return o.value; });
      else out[f.name] = el.value;
    });
    return out;
  }

  // ---- database fields: choices read for THIS user's ADOMs
  form.querySelectorAll('select[data-lookup]').forEach(function (sel) {
    var name = sel.getAttribute('data-lookup');
    var f = (CFG.fields || []).filter(function (x) { return x.name === name; })[0] || {};
    fetch(U.lookup.replace('FIELD', encodeURIComponent(name)), { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (res) {
        if (!res.ok) { sel.innerHTML = '<option value="">' + esc(res.d.error || 'could not read the choices') + '</option>'; sel.disabled = true; return; }
        var opts = res.d.options || [];
        sel.innerHTML = (f.type === 'lookup' && !f.required ? '<option value=""></option>' : '')
          + opts.map(function (o) { return '<option value="' + esc(o.value) + '">' + esc(o.label) + '</option>'; }).join('')
          + (opts.length ? '' : '<option value="" disabled>no rows</option>');
      })
      .catch(function () { sel.innerHTML = '<option value="">could not read the choices</option>'; });
  });

  // ---- run now
  function poll(rid, n) {
    fetch(U.status.replace('RID', encodeURIComponent(rid)), { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (st) {
        var badge = { ok: 'success', failed: 'danger', timeout: 'warning', running: 'info', queued: 'secondary' }[st.status] || 'secondary';
        $('sc-status').innerHTML = '<span class="fw-badge fw-badge-' + badge + '">' + esc(st.status) + '</span>'
          + (st.duration_ms ? ' <span class="text-muted small">' + (st.duration_ms / 1000).toFixed(1) + ' s</span>' : '');
        $('sc-out').textContent = (st.error ? 'error: ' + st.error + '\n\n' : '') + (st.output || '');
        $('sc-result').textContent = st.result != null ? JSON.stringify(st.result, null, 2) : '';
        if (st.status === 'queued' || st.status === 'running') {
          if (n > 900) return;
          setTimeout(function () { poll(rid, n + 1); }, n < 10 ? 500 : 1500);
        }
      })
      .catch(function () { setTimeout(function () { poll(rid, n + 1); }, 2000); });
  }
  $('sc-run').addEventListener('click', function () {
    $('sc-out').textContent = ''; $('sc-result').textContent = '';
    $('sc-status').innerHTML = '<span class="fw-badge fw-badge-secondary">queuing…</span>';
    post(U.run, { inputs: values() })
      .then(function (st) { poll(st.request_id, 0); })
      .catch(function (e) { $('sc-status').innerHTML = ''; $('sc-out').textContent = 'Not started: ' + e.message; });
  });

  // ---- cron preview
  var tmr = null;
  $('sc-cron').addEventListener('input', function () {
    clearTimeout(tmr);
    var expr = this.value.trim();
    if (!expr) { $('sc-cron-next').textContent = ''; return; }
    tmr = setTimeout(function () {
      fetch(U.preview + '?expr=' + encodeURIComponent(expr), { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
        .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
        .then(function (res) {
          var el = $('sc-cron-next');
          if (!res.ok) { el.className = 'small text-danger'; el.textContent = res.d.error; return; }
          el.className = 'small text-muted';
          el.textContent = 'Next: ' + res.d.next.join(' · ') + ' (' + res.d.tz + ')';
        });
    }, 300);
  });

  // ---- saved runs
  $('sc-save').addEventListener('click', function () {
    var msg = $('sc-save-msg');
    msg.className = 'small ms-2 text-muted'; msg.textContent = 'saving…';
    post(U.schedules, { name: $('sc-sname').value, cron: $('sc-cron').value, inputs: values() })
      .then(function () { window.location.reload(); })
      .catch(function (e) { msg.className = 'small ms-2 text-danger'; msg.textContent = e.message; });
  });
  document.querySelectorAll('tr[data-sid]').forEach(function (tr) {
    var sid = tr.getAttribute('data-sid');
    function act(sel, url, confirmText) {
      var b = tr.querySelector(sel);
      if (!b) return;
      b.addEventListener('click', function () {
        if (confirmText && !window.confirm(confirmText)) return;
        post(url.replace('SID', sid), {}).then(function () { window.location.reload(); })
          .catch(function (e) { window.alert(e.message); });
      });
    }
    act('.sc-toggle', U.toggle);
    act('.sc-upgrade', U.upgrade, 'Move this saved run to the current published version? Its values are checked against the new form.');
    act('.sc-delete', U.delete, 'Delete this saved run? Its saved password values are removed from the vault.');
  });
})();
