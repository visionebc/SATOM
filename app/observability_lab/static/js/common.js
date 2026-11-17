/* SATOM Observability — shared page behaviour (no inline handlers: the CSP blocks them). */
(function () {
  'use strict';

  // Confirmation for destructive forms.
  document.querySelectorAll('form.obs-confirm').forEach(function (f) {
    f.addEventListener('submit', function (ev) {
      if (!window.confirm(f.getAttribute('data-confirm') || 'Are you sure?')) ev.preventDefault();
    });
  });

  // Submit feedback: the button shows it is working and cannot be pressed twice.
  document.querySelectorAll('form.obs-busy-form').forEach(function (f) {
    f.addEventListener('submit', function (ev) {
      if (ev.defaultPrevented) return;
      var b = f.querySelector('button[type=submit], button:not([type])');
      if (!b) return;
      setTimeout(function () {
        b.disabled = true; b.setAttribute('aria-busy', 'true');
        var l = b.querySelector('.obs-btn-label');
        var sp = document.createElement('span');
        sp.className = 'spinner-border spinner-border-sm me-1'; sp.setAttribute('aria-hidden', 'true');
        b.insertBefore(sp, b.firstChild);
        if (l) l.textContent = 'Working…';
      }, 0);
    });
  });

  // Show/hide password.
  document.querySelectorAll('.obs-reveal').forEach(function (b) {
    b.addEventListener('click', function () {
      var i = document.getElementById(b.getAttribute('data-target'));
      var show = i.type === 'password';
      i.type = show ? 'text' : 'password';
      b.setAttribute('aria-pressed', show); b.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      b.querySelector('i').className = 'bi bi-' + (show ? 'eye-slash' : 'eye');
    });
  });

  // Client-side filter: input[data-filter-target] hides [data-filter-item] that do not match.
  document.querySelectorAll('input[data-filter-target]').forEach(function (inp) {
    var root = document.getElementById(inp.getAttribute('data-filter-target'));
    if (!root) return;
    var live = document.createElement('span');
    live.className = 'visually-hidden'; live.setAttribute('aria-live', 'polite');
    inp.parentNode.appendChild(live);
    inp.addEventListener('input', function () {
      var q = inp.value.trim().toLowerCase(), shown = 0, items = root.querySelectorAll('[data-filter-item]');
      items.forEach(function (it) {
        var hit = !q || it.textContent.toLowerCase().indexOf(q) !== -1;
        it.classList.toggle('obs-filtered', !hit); if (hit) shown++;
      });
      live.textContent = shown + ' of ' + items.length + ' shown';
    });
  });

  // "Failed only" toggle for job steps.
  document.querySelectorAll('[data-only-failed]').forEach(function (cb) {
    var t = document.getElementById(cb.getAttribute('data-only-failed'));
    cb.addEventListener('change', function () {
      t.querySelectorAll('tr[data-ok="1"]').forEach(function (r) { r.classList.toggle('obs-hidden', cb.checked); });
    });
  });

  // Relative times ("5 min ago"); the absolute UTC time stays in the title.
  function rel(iso) {
    var s = Math.round((Date.now() - Date.parse(iso)) / 1000);
    if (isNaN(s)) return null;
    if (s < 45) return 'just now';
    if (s < 3600) return Math.round(s / 60) + ' min ago';
    if (s < 86400) return Math.round(s / 3600) + ' h ago';
    if (s < 86400 * 14) return Math.round(s / 86400) + ' d ago';
    return null;
  }
  function tick() {
    document.querySelectorAll('time.obs-ago').forEach(function (t) {
      var r = rel(t.getAttribute('datetime'));
      if (r) t.textContent = r;
    });
  }
  tick(); setInterval(tick, 60000);

  // File drop zone: show the chosen file name.
  document.querySelectorAll('.obs-drop').forEach(function (z) {
    var inp = z.querySelector('input[type=file]'), txt = z.querySelector('.obs-drop-text');
    function show() { if (inp.files && inp.files[0]) { txt.textContent = inp.files[0].name; z.classList.add('has-file'); } }
    inp.addEventListener('change', show);
    ['dragenter', 'dragover'].forEach(function (e) { z.addEventListener(e, function (ev) { ev.preventDefault(); z.classList.add('drag'); }); });
    ['dragleave', 'drop'].forEach(function (e) { z.addEventListener(e, function () { z.classList.remove('drag'); }); });
    z.addEventListener('drop', function (ev) { ev.preventDefault(); if (ev.dataTransfer.files.length) { inp.files = ev.dataTransfer.files; show(); } });
  });

  // Diagram thumbnails drawn from the stored layout.
  var NS = 'http://www.w3.org/2000/svg';
  document.querySelectorAll('svg.obs-thumb[data-layout]').forEach(function (svg) {
    var lay;
    try { lay = JSON.parse(svg.getAttribute('data-layout')); } catch (e) { return; }
    var nodes = lay.nodes || [], byId = {};
    if (!nodes.length) {
      var t = document.createElementNS(NS, 'text');
      t.setAttribute('x', 50); t.setAttribute('y', 30); t.setAttribute('class', 'obs-thumb-empty'); t.textContent = 'empty';
      svg.setAttribute('viewBox', '0 0 100 56'); svg.appendChild(t); return;
    }
    var x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    nodes.forEach(function (n) { byId[n.id] = n; x0 = Math.min(x0, n.x); y0 = Math.min(y0, n.y); x1 = Math.max(x1, n.x); y1 = Math.max(y1, n.y); });
    var pad = 110;
    svg.setAttribute('viewBox', [x0 - pad, y0 - pad * 0.7, (x1 - x0) + pad * 2, (y1 - y0) + pad * 1.4].join(' '));
    svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
    (lay.edges || []).forEach(function (e) {
      var a = byId[e.from], b = byId[e.to]; if (!a || !b) return;
      var l = document.createElementNS(NS, 'line');
      l.setAttribute('x1', a.x); l.setAttribute('y1', a.y); l.setAttribute('x2', b.x); l.setAttribute('y2', b.y);
      l.setAttribute('class', 'obs-thumb-edge'); svg.appendChild(l);
    });
    nodes.forEach(function (n) {
      var r = document.createElementNS(NS, 'rect');
      r.setAttribute('x', n.x - 70); r.setAttribute('y', n.y - 26); r.setAttribute('width', 140); r.setAttribute('height', 52);
      r.setAttribute('rx', 10); r.setAttribute('class', 'obs-thumb-node' + (n.source_id ? ' bound' : ''));
      svg.appendChild(r);
    });
  });
})();
