// WAF false-positive explainer — header Tools menu:  FWFpTriage.open()
// Paste an attack-log line (syslog key=value, JSON, or a raw HTTP request) and
// get: which module blocked it, which carve-out type addresses that module, the
// fields that scope it, and the exact FortiWeb payload — proved by running the
// real assembly, not a friendlier copy of it.
//
// Light chrome ONLY (docs/safeguards.md §9m). CSP-safe: no inline handlers.
(function () {
  if (window.FWFpTriage) return;

  function esc(s) {
    return String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, c =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function $(id) { return document.getElementById(id); }

  const MODAL_ID = 'fw-fptriage';
  let built = false;

  const SAMPLE = 'date=2026-08-16 time=11:20:03 log_id="20000010" msg_id=000000123456 ' +
    'device_id=FVVM00 vd="root" policy="pol-shop-cms" main_type="Signature Detection" ' +
    'sub_type="Cross Site Scripting" action="Alert_Deny" severity_level="High" ' +
    'src=198.51.100.31 src_port=51422 dst=192.0.2.90 dst_port=443 ' +
    'http_method="post" http_url="/api/v2/tickets?draft=1" http_host="soporte.example.com" ' +
    'http_agent="Mozilla/5.0" signature_id="090200001" ' +
    'msg="Cross Site Scripting detected in ARGS:body"';

  function buildModal() {
    if (built) return;
    built = true;
    const wrap = document.createElement('div');
    wrap.className = 'modal fade';
    wrap.id = MODAL_ID;
    wrap.tabIndex = -1;
    wrap.innerHTML =
      '<div class="modal-dialog modal-xl modal-dialog-scrollable"><div class="modal-content">' +
      '<div class="modal-header">' +
      '<h5 class="modal-title"><i class="bi bi-shield-exclamation me-2"></i>False-positive explainer</h5>' +
      '<button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>' +
      '<div class="modal-body">' +
      '<div class="row g-2">' +
      '<div class="col-md-9">' +
      '<label class="form-label small text-muted mb-1">Attack-log entry, or a raw HTTP request</label>' +
      '<textarea id="fw-fp-in" class="form-control font-monospace" rows="6" ' +
      'placeholder="date=… main_type=&quot;Signature Detection&quot; http_url=&quot;/x&quot; signature_id=&quot;0902…&quot;&#10;— or —&#10;{&quot;main_type&quot;: &quot;…&quot;}&#10;— or —&#10;POST /api/v2/tickets HTTP/1.1"></textarea>' +
      '</div>' +
      '<div class="col-md-3 d-flex flex-column gap-2 justify-content-end">' +
      '<button class="fw-btn fw-btn-primary" id="fw-fp-run"><i class="bi bi-search me-1"></i>Explain</button>' +
      '<button class="fw-btn" id="fw-fp-sample"><i class="bi bi-file-text me-1"></i>Load a sample</button>' +
      '<button class="fw-btn" id="fw-fp-clear"><i class="bi bi-x-lg me-1"></i>Clear</button>' +
      '</div></div>' +
      '<div id="fw-fp-err" class="text-danger small mt-2"></div>' +
      '<div id="fw-fp-out" class="mt-3"></div>' +
      '</div></div></div>';
    document.body.appendChild(wrap);
    $('fw-fp-run').addEventListener('click', run);
    $('fw-fp-sample').addEventListener('click', function () { $('fw-fp-in').value = SAMPLE; run(); });
    $('fw-fp-clear').addEventListener('click', function () {
      $('fw-fp-in').value = ''; $('fw-fp-out').innerHTML = ''; $('fw-fp-err').textContent = '';
    });
  }

  function post(url, body) {
    const opts = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(body)
    };
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (meta && meta.content) opts.headers['X-CSRFToken'] = meta.content;
    return fetch(url, opts).then(r => r.json().then(d => ({ status: r.status, d: d })));
  }

  function run() {
    const text = $('fw-fp-in').value;
    if (!text.trim()) { $('fw-fp-err').textContent = 'Paste an entry first.'; return; }
    $('fw-fp-err').textContent = '';
    $('fw-fp-out').innerHTML = '<div class="text-muted small">' +
      '<span class="spinner-border spinner-border-sm me-2"></span>Reading the entry…</div>';
    post('/fp-triage/triage', { text: text }).then(r => {
      if (!r.d || !r.d.ok) {
        $('fw-fp-out').innerHTML = '';
        $('fw-fp-err').textContent = (r.d && r.d.error) || 'Could not read that.';
        return;
      }
      render(r.d);
    }).catch(e => { $('fw-fp-err').textContent = String(e); });
  }

  function kv(k, v) {
    return '<div class="d-flex justify-content-between border-bottom py-1 small">' +
      '<span class="text-muted">' + esc(k) + '</span>' +
      '<span class="font-monospace text-end">' + esc(v) + '</span></div>';
  }

  function render(d) {
    let h = '';

    // --- what was read, and what was NOT --------------------------------
    h += '<div class="fw-card p-3 mb-3">' +
      '<div class="d-flex justify-content-between align-items-center mb-2">' +
      '<strong>Entry read</strong><span class="fw-badge fw-badge-secondary">' +
      esc(d.fmt || 'unknown format') + '</span></div>';
    Object.keys(d.row || {}).forEach(k => { h += kv(k, d.row[k]); });
    if (d.mapped && Object.keys(d.mapped).length) {
      h += '<div class="small text-muted mt-2">Renamed to SATOM\'s field names: ' +
        esc(Object.keys(d.mapped).map(k => k + ' → ' + d.mapped[k]).join(', ')) + '</div>';
    }
    if (d.unmapped && Object.keys(d.unmapped).length) {
      // Not debris: a field SATOM could not place is evidence the
      // recommendation below never saw.
      h += '<div class="alert alert-warning py-2 small mt-2 mb-0">' +
        '<i class="bi bi-exclamation-triangle me-1"></i><strong>Not used:</strong> ' +
        esc(Object.keys(d.unmapped).join(', ')) +
        ' — these keys are not attack-log fields SATOM recognises, so nothing below rests on them.</div>';
    }
    h += '</div>';

    if (d.missing && d.missing.length) {
      h += '<div class="alert alert-info py-2 small mb-3"><strong>Absent from this entry, and what each one decides:</strong><ul class="mb-0 mt-1">';
      d.missing.forEach(m => { h += '<li><span class="font-monospace">' + esc(m[0]) + '</span> — ' + esc(m[1]) + '</li>'; });
      h += '</ul></div>';
    }

    if (d.decoded && d.decoded.length) {
      h += '<div class="fw-card p-3 mb-3"><div class="fw-semibold mb-2">Payload, decoded</div>';
      d.decoded.forEach(l => {
        h += '<div class="small py-1 border-bottom"><span class="fw-badge fw-badge-info me-2">' +
          esc(l.how) + '</span><span class="font-monospace">' + esc(l.value) + '</span></div>';
      });
      h += '</div>';
    }

    // --- the carve-outs -------------------------------------------------
    (d.types || []).forEach((t, i) => {
      const rec = t.recommended || {};
      const prev = rec.preview || {};
      h += '<div class="fw-card p-3 mb-2">' +
        '<div class="d-flex justify-content-between align-items-start mb-1">' +
        '<div><strong>' + esc(t.label) + '</strong>' +
        '<div class="small text-muted">' + esc(t.group || '') + '</div></div>' +
        '<span class="fw-badge ' + (i === 0 ? 'fw-badge-success' : 'fw-badge-secondary') + '">' +
        (i === 0 ? 'recommended' : 'alternative') + '</span></div>' +
        '<div class="small mb-2">' + esc(t.why) + '</div>';

      if (t.subject && t.subject.value) {
        h += '<div class="small mb-2"><i class="bi bi-info-circle me-1"></i>' +
          esc(t.subject.label) + ' <span class="font-monospace">' + esc(t.subject.value) +
          '</span> — ' + esc(t.subject.note) + '</div>';
      }
      if ((t.scopers || []).length) {
        h += '<div class="small fw-semibold mt-2">Scoped by</div>';
        t.scopers.forEach(s => {
          const on = (rec.picked || []).indexOf(s.row_key) >= 0;
          h += '<div class="small py-1 border-bottom">' +
            '<span class="fw-badge ' + (on ? 'fw-badge-success' : 'fw-badge-secondary') + ' me-2">' +
            (on ? 'selected' : (s.required ? 'REQUIRED, absent' : 'available')) + '</span>' +
            esc(s.label) + (s.value ? ' = <span class="font-monospace">' + esc(s.value) + '</span>' : '') +
            '<div class="text-muted">' + esc(s.note) + '</div></div>';
        });
      }
      (rec.skipped || []).forEach(s => {
        h += '<div class="small text-muted py-1">— ' + esc(s.why) + '</div>';
      });
      if (prev.payload) {
        h += '<div class="small fw-semibold mt-2">Payload SATOM would build</div>' +
          '<pre class="fw-pre small mb-1">' + esc(JSON.stringify(prev.payload, null, 2)) + '</pre>';
      }
      (prev.warnings || []).forEach(w => {
        h += '<div class="alert alert-warning py-1 px-2 small mb-1">' + esc(w) + '</div>';
      });
      (prev.errors || []).forEach(w => {
        h += '<div class="alert alert-danger py-1 px-2 small mb-1">' + esc(w) + '</div>';
      });
      if (t.explain && t.explain.summary) {
        h += '<div class="small text-muted mt-1">' + esc(t.explain.summary) + '</div>';
      }
      h += '</div>';
    });

    // --- why there is no Save button ------------------------------------
    if (d.save) {
      h += '<div class="alert alert-secondary py-2 small mb-0">' +
        '<i class="bi bi-lock me-1"></i><strong>No Save here.</strong> ' + esc(d.save.note) +
        '<div class="mt-1"><strong>' + esc(d.save.where) + '</strong></div></div>';
    }
    $('fw-fp-out').innerHTML = h;
  }

  function modalObj() {
    if (window.bootstrap && bootstrap.Modal) return bootstrap.Modal.getOrCreateInstance($(MODAL_ID));
    return null;
  }

  window.FWFpTriage = {
    open: function (prefill) {
      buildModal();
      if (prefill) { $('fw-fp-in').value = prefill; }
      const m = modalObj();
      if (m) m.show(); else $(MODAL_ID).style.display = 'block';
    }
  };

  document.addEventListener('click', function (ev) {
    const t = ev.target.closest && ev.target.closest('[data-fw-fptriage-open]');
    if (!t) return;
    ev.preventDefault();
    window.FWFpTriage.open(t.getAttribute('data-fw-fptriage-open') || '');
  });
})();
