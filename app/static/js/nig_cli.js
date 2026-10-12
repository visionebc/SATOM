// "Not in GUI, but in CLI" — the CLI editor of the section on product views
// without their own editor (FortiGate, FortiAuthenticator, FortiADC,
// FortiAnalyzer tabs, objects only the CLI serves, the per-device page).
// Macro nig_cli in templates/_not_in_gui.html; routes
// /appliances/<id>/not-in-gui/{read,save}. Read fills the inputs (value AND
// data-orig, so an unchanged field is never sent); Preview renders the CLI
// script; Apply runs exactly the previewed change.
(function () {
  if (window.__nigCliBound) return;
  window.__nigCliBound = true;

  function esc(s) {
    return String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function post(url, payload) {
    return fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload) }).then(function (r) {
      return r.json().catch(function () { return { ok: false, error: 'HTTP ' + r.status }; });
    });
  }
  function base(sec) {
    var mk = sec.querySelector('[data-nig-mkey]'), pa = sec.querySelector('[data-nig-parent]');
    return { endpoint: sec.dataset.endpoint, mkey: mk ? mk.value.trim() : '',
      parent: pa ? pa.value.trim() : '' };
  }
  function url(sec, what) { return '/appliances/' + sec.dataset.aid + '/not-in-gui/' + what; }
  function changed(sec) {
    var out = {};
    sec.querySelectorAll('[data-nig-input]').forEach(function (el) {
      if (el.value !== (el.dataset.orig || '')) out[el.dataset.key] = el.value;
    });
    return out;
  }
  function needsRow(sec, b) {
    if (sec.dataset.kind !== 'singleton' && !b.mkey) return 'Name the row first.';
    var pa = sec.querySelector('[data-nig-parent]');
    if (pa && !b.parent) return 'Name the parent row first.';
    return '';
  }
  function show(sec, j, preview) {
    var out = sec.querySelector('.fw-nig-out'), cli = j.cli || {}, h = '';
    if (j.error) h += '<div class="fw-alert fw-alert-danger small mb-2">' + esc(j.error) + '</div>';
    if (cli.script && cli.script.length) {
      h += '<div class="small text-muted">' + (preview ? 'CLI script (not sent yet):' : 'CLI script sent:') +
        '</div><pre class="fw-nig-script small mb-2">' + esc(cli.script.join('\n')) + '</pre>';
    }
    if (!preview && j.ok) h += '<div class="fw-alert fw-alert-success small mb-0">Applied and read back over CLI.</div>';
    out.innerHTML = h;
  }

  function read(btn) {
    var sec = btn.closest('[data-nig-cli]'), msg = sec.querySelector('.fw-nig-read'), b = base(sec);
    var why = needsRow(sec, b);
    if (why) { msg.textContent = why; return; }
    b.names = Array.prototype.map.call(sec.querySelectorAll('[data-nig-input]'),
      function (el) { return el.dataset.key; });
    msg.textContent = 'reading…';
    post(url(sec, 'read'), b).then(function (j) {
      if (!j.ok) { msg.textContent = j.error || 'CLI read failed'; return; }
      Object.keys(j.values || {}).forEach(function (k) {
        var el = sec.querySelector('[data-nig-input][data-key="' + k + '"]');
        var v = j.values[k] == null ? '' : String(j.values[k]);
        if (!el) return;
        if (el.tagName === 'SELECT' && v && !el.querySelector('option[value="' + CSS.escape(v) + '"]')) {
          var o = document.createElement('option'); o.value = v; o.textContent = v; el.appendChild(o);
        }
        el.value = v; el.dataset.orig = v;
      });
      (j.secret || []).forEach(function (k) {
        var el = sec.querySelector('[data-nig-input][data-key="' + k + '"]');
        if (el) el.placeholder = 'secret — not shown';
      });
      msg.textContent = 'read over CLI';
    });
  }

  function preview(btn) {
    var sec = btn.closest('[data-nig-cli]'), apply = sec.querySelector('[data-js="nig-cli-apply"]');
    var b = base(sec), why = needsRow(sec, b);
    apply.disabled = true; sec.__nigPending = null;
    if (why) { show(sec, { error: why }, true); return; }
    b.fields = changed(sec);
    if (!Object.keys(b.fields).length) { show(sec, { error: 'No field changed.' }, true); return; }
    post(url(sec, 'save'), b).then(function (j) {
      show(sec, j, true);
      if (j.ok) { sec.__nigPending = b; apply.disabled = false; }
    });
  }

  function applyChange(btn) {
    var sec = btn.closest('[data-nig-cli]'), b = sec.__nigPending;
    if (!b) return;
    if (!confirm('Apply this CLI change to the device?')) return;
    btn.disabled = true;
    post(url(sec, 'save'), Object.assign({}, b, { apply: true })).then(function (j) {
      show(sec, j, false);
      sec.__nigPending = null;
      if (j.ok) {
        sec.querySelectorAll('[data-nig-input]').forEach(function (el) {
          if (Object.prototype.hasOwnProperty.call(b.fields, el.dataset.key)) el.dataset.orig = el.value;
        });
      }
    });
  }

  // Per-device page: the rows of each object the device's GUI does not draw,
  // read (GET, read only) a few at a time so the device is not flooded.
  function loadRows() {
    var queue = Array.prototype.slice.call(document.querySelectorAll('[data-nig-rows][data-src]'));
    function next() {
      var box = queue.shift();
      if (!box) return;
      fetch(box.dataset.src, { headers: { 'Accept': 'text/html' } }).then(function (r) {
        return r.text().then(function (t) { return r.ok ? t : '<p class="small text-danger mb-0">HTTP ' + r.status + '</p>'; });
      }).catch(function (e) {
        return '<p class="small text-danger mb-0">' + esc(e) + '</p>';
      }).then(function (html) {
        box.innerHTML = html;
        var got = box.querySelector('[data-nig-rows-loaded]');
        var cnt = box.parentNode.querySelector('[data-nig-rows-count]');
        if (got && cnt && !got.querySelector('[data-nig-rows-error]')) cnt.textContent = '(' + got.dataset.count + ')';
        next();
      });
    }
    for (var i = 0; i < 3; i++) next();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', loadRows);
  else loadRows();

  var FNS = { 'nig-cli-read': read, 'nig-cli-preview': preview, 'nig-cli-apply': applyChange };
  document.addEventListener('click', function (ev) {
    var btn = ev.target.closest && ev.target.closest('[data-js]');
    if (!btn || !btn.closest('[data-nig-cli]')) return;
    var fn = FNS[btn.dataset.js];
    if (fn) fn(btn);
  });
  // Editing after a preview invalidates it: Apply sends only what was previewed.
  document.addEventListener('input', function (ev) {
    var sec = ev.target.closest && ev.target.closest('[data-nig-cli]');
    if (!sec || !sec.__nigPending) return;
    sec.__nigPending = null;
    var a = sec.querySelector('[data-js="nig-cli-apply"]');
    if (a) a.disabled = true;
  });
})();
