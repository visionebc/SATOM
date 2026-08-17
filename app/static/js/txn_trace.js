// Transaction tracer — header Tools menu:  FWTxnTrace.open()
// Leg A (through the appliance), leg B (DERIVED from its config, never
// measured) and leg C (straight to the backend), plus the diff that answers
// "is it the WAF or is it the app?".
//
// Light chrome ONLY (docs/safeguards.md §9m). CSP-safe: no inline handlers.
(function () {
  if (window.FWTxnTrace) return;

  function esc(s) {
    return String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, c =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function $(id) { return document.getElementById(id); }

  const MODAL_ID = 'fw-txntrace';
  let built = false;
  let lastLegs = [];
  let lastWindow = null;

  const VERDICT_CLASS = {
    appliance_decides: 'alert-danger',
    body_differs: 'alert-warning',
    appliance_transforms: 'alert-info',
    transparent: 'alert-success'
  };

  function buildModal() {
    if (built) return;
    built = true;
    const w = document.createElement('div');
    w.className = 'modal fade';
    w.id = MODAL_ID;
    w.tabIndex = -1;
    w.innerHTML =
      '<div class="modal-dialog modal-xl modal-dialog-scrollable"><div class="modal-content">' +
      '<div class="modal-header py-2">' +
      '<h6 class="modal-title mb-0"><i class="bi bi-diagram-3 me-1"></i>Transaction tracer' +
      '<span class="text-muted small fw-normal ms-1">client → appliance → backend</span></h6>' +
      '<button type="button" class="btn-close ms-auto" data-bs-dismiss="modal" aria-label="Close"></button></div>' +
      '<div class="modal-body pt-2">' +

      '<div class="row g-2">' +
      '<div class="col-md-6">' +
      '<label class="form-label small fw-bold mb-1">Leg A — VIP (through the appliance)</label>' +
      '<div class="input-group">' +
      '<select id="fw-tt-vipinv" class="form-select form-select-sm" style="max-width:45%"></select>' +
      '<input id="fw-tt-vip" class="form-control form-control-sm" placeholder="or https://shop.example.com">' +
      '</div></div>' +
      '<div class="col-md-6">' +
      '<label class="form-label small fw-bold mb-1">Leg C — backend (bypassing the appliance)</label>' +
      '<input id="fw-tt-backend" class="form-control form-control-sm" placeholder="192.0.2.90:8080">' +
      '</div>' +
      '<div class="col-md-3">' +
      '<label class="form-label small fw-bold mb-1">Method</label>' +
      '<select id="fw-tt-method" class="form-select form-select-sm"></select></div>' +
      '<div class="col-md-9">' +
      '<label class="form-label small fw-bold mb-1">Path</label>' +
      '<input id="fw-tt-path" class="form-control form-control-sm font-monospace" value="/"></div>' +
      '<div class="col-md-6">' +
      '<label class="form-label small fw-bold mb-1">Extra request headers (one per line)</label>' +
      '<textarea id="fw-tt-headers" class="form-control form-control-sm font-monospace" rows="3" ' +
      'placeholder="X-Forwarded-For: 203.0.113.9&#10;Accept-Language: es-MX"></textarea></div>' +
      '<div class="col-md-6">' +
      '<label class="form-label small fw-bold mb-1">Request body (mutating methods only)</label>' +
      '<textarea id="fw-tt-body" class="form-control form-control-sm font-monospace" rows="3"></textarea></div>' +
      '</div>' +

      '<div class="form-check mt-2" id="fw-tt-confirmwrap" style="display:none">' +
      '<input class="form-check-input" type="checkbox" id="fw-tt-confirm">' +
      '<label class="form-check-label small" for="fw-tt-confirm">' +
      'I understand this sends a real write to that application from this server.</label></div>' +

      '<div class="mt-2 d-flex gap-2 flex-wrap">' +
      '<button class="btn btn-sm btn-fw-primary" id="fw-tt-run"><i class="bi bi-play-fill me-1"></i>Trace</button>' +
      '<button class="btn btn-sm btn-fw-outline" id="fw-tt-curl"><i class="bi bi-terminal me-1"></i>Copy curl</button>' +
      '<button class="btn btn-sm btn-fw-outline" id="fw-tt-har"><i class="bi bi-download me-1"></i>Download HAR</button>' +
      '<button class="btn btn-sm btn-fw-secondary" id="fw-tt-corr"><i class="bi bi-link-45deg me-1"></i>Correlate attack log</button>' +
      '</div>' +

      '<hr>' +
      '<div class="row g-2 align-items-end">' +
      '<div class="col-md-5"><label class="form-label small fw-bold mb-1">' +
      'Leg B — appliance for the config read</label>' +
      '<select id="fw-tt-devinv" class="form-select form-select-sm"></select></div>' +
      '<div class="col-md-5"><label class="form-label small fw-bold mb-1">Server policy</label>' +
      '<input id="fw-tt-policy" class="form-control form-control-sm" placeholder="pol-shop-cms"></div>' +
      '<div class="col-md-2"><button class="btn btn-sm btn-fw-primary w-100" id="fw-tt-derive">' +
      '<i class="bi bi-file-earmark-code me-1"></i>Derive</button></div>' +
      '</div>' +

      '<div id="fw-tt-err" class="text-danger small mt-2"></div>' +
      '<div id="fw-tt-out" class="mt-3"></div>' +
      '<div id="fw-tt-legb" class="mt-3"></div>' +
      '<div id="fw-tt-corrout" class="mt-3"></div>' +
      '</div></div></div>';
    document.body.appendChild(w);

    $('fw-tt-run').addEventListener('click', run);
    $('fw-tt-derive').addEventListener('click', derive);
    $('fw-tt-curl').addEventListener('click', copyCurl);
    $('fw-tt-har').addEventListener('click', downloadHar);
    $('fw-tt-corr').addEventListener('click', correlate);
    $('fw-tt-method').addEventListener('change', onMethod);
    $('fw-tt-vipinv').addEventListener('change', function () {
      if (this.value) $('fw-tt-vip').value = '';
    });
    loadContext();
  }

  let CTX = { safe_methods: ['GET'], mutating_methods: [], may_free: false };

  function loadContext() {
    fetch('/txn-trace/context', { headers: { Accept: 'application/json' } })
      .then(r => r.json()).then(d => {
        if (!d || !d.ok) return;
        CTX = d;
        const opts = (d.appliances || []).map(a =>
          '<option value="' + esc(a.host) + '">' + esc(a.name) + ' — ' + esc(a.host) + '</option>').join('');
        $('fw-tt-vipinv').innerHTML = '<option value="">— free target —</option>' + opts;
        $('fw-tt-devinv').innerHTML = '<option value="">— pick —</option>' +
          (d.appliances || []).map(a =>
            '<option value="' + a.id + '">' + esc(a.name) + '</option>').join('');
        $('fw-tt-method').innerHTML =
          d.safe_methods.map(m => '<option>' + esc(m) + '</option>').join('') +
          d.mutating_methods.map(m => '<option>' + esc(m) + '</option>').join('');
        if (!d.may_free) {
          $('fw-tt-vip').disabled = true;
          $('fw-tt-vip').placeholder = 'free targets need the ' + d.free_permission + ' permission';
        }
      }).catch(() => {});
  }

  function onMethod() {
    const m = $('fw-tt-method').value;
    const mutating = (CTX.mutating_methods || []).indexOf(m) >= 0;
    $('fw-tt-confirmwrap').style.display = mutating ? '' : 'none';
    if (!mutating) $('fw-tt-confirm').checked = false;
  }

  function post(url, body) {
    const opts = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body)
    };
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (meta && meta.content) opts.headers['X-CSRFToken'] = meta.content;
    return fetch(url, opts).then(r => r.json().then(d => ({ status: r.status, d: d })));
  }

  function run() {
    const vip = $('fw-tt-vipinv').value || $('fw-tt-vip').value.trim();
    const backend = $('fw-tt-backend').value.trim();
    if (!vip && !backend) { $('fw-tt-err').textContent = 'Give at least a VIP or a backend.'; return; }
    $('fw-tt-err').textContent = '';
    $('fw-tt-out').innerHTML = '<div class="text-muted small">' +
      '<span class="spinner-border spinner-border-sm me-2"></span>Tracing…</div>';
    post('/txn-trace/run', {
      mode_a: $('fw-tt-vipinv').value ? 'inventory' : 'free',
      mode_c: 'free',
      vip: vip, backend: backend,
      method: $('fw-tt-method').value,
      path: $('fw-tt-path').value.trim() || '/',
      headers: $('fw-tt-headers').value,
      body: $('fw-tt-body').value,
      confirm_mutating: $('fw-tt-confirm').checked
    }).then(r => {
      if (!r.d || !r.d.ok) {
        $('fw-tt-out').innerHTML = '';
        $('fw-tt-err').textContent = (r.d && r.d.error) || 'The trace failed.';
        return;
      }
      lastLegs = r.d.legs || [];
      lastCurl = r.d.curl || [];
      lastWindow = r.d.window || null;
      render(r.d);
    }).catch(e => { $('fw-tt-err').textContent = String(e); });
  }

  function ms(v) { return (v === null || v === undefined) ? '—' : v + ' ms'; }

  function legCard(leg) {
    const t = leg.timing || {};
    let h = '<div class="fw-card">' +
      '<div class="fw-card-header">' +
      '<h6 class="fw-card-title">Leg ' + esc((leg.leg || '').toUpperCase()) + ' — ' + esc(leg.label || '') + '</h6>' +
      '<span class="fw-badge ' + (leg.ok ? (leg.status < 400 ? 'fw-badge-success' : 'fw-badge-warning') : 'fw-badge-danger') + '">' +
      (leg.ok ? esc(leg.status + ' ' + leg.reason) : 'failed') + '</span></div>' +
      '<div class="fw-card-body">';
    if (!leg.ok) {
      h += '<div class="text-danger small">' + esc(leg.error) + '</div></div></div>';
      return h;
    }
    const rq = leg.request || {};
    h += '<div class="small font-monospace mb-2">' + esc(rq.method) + ' ' +
      esc(rq.scheme + '://' + rq.host + rq.path) + ' → ' + esc(rq.ip + ':' + rq.port) +
      (rq.dialled_host ? ' <span class="text-muted">(dialled ' + esc(rq.dialled_host) + ')</span>' : '') + '</div>';
    h += '<div class="small mb-2">TCP ' + esc(ms(t.tcp_ms)) + ' · TLS ' + esc(ms(t.tls_ms)) +
      ' · TTFB ' + esc(ms(t.ttfb_ms)) + ' · total ' + esc(ms(t.total_ms)) + '</div>';
    if (leg.tls) {
      h += '<div class="small text-muted mb-2">' + esc(leg.tls.protocol + ' · ' + leg.tls.cipher) +
        (leg.tls.cn ? ' · cert CN ' + esc(leg.tls.cn) : '') +
        (leg.tls.days_left !== undefined && leg.tls.days_left !== null ? ' · ' + esc(leg.tls.days_left) + ' days left' : '') +
        '</div>';
    }
    h += '<details><summary class="small">Response headers (' + (leg.headers || []).length + ')</summary>' +
      '<div class="mt-1">';
    (leg.headers || []).forEach(kv => {
      h += '<div class="small font-monospace border-bottom py-1">' + esc(kv[0]) + ': ' + esc(kv[1]) + '</div>';
    });
    h += '</div></details>';
    h += '<div class="small text-muted mt-2">body ' + esc(leg.body_bytes) + ' bytes' +
      (leg.truncated ? ' (truncated)' : '') + ' · sha256 ' + esc((leg.body_sha256 || '').slice(0, 16)) + '…</div>';
    return h + '</div></div>';
  }

  function render(d) {
    let h = '';
    const v = (d.diff || {}).verdict;
    if (d.diff && d.diff.comparable && v) {
      h += '<div class="alert ' + (VERDICT_CLASS[v.key] || 'alert-secondary') +
        ' py-2 small"><strong>' + esc(v.text) + '</strong></div>';
    } else if (d.diff && !d.diff.comparable) {
      h += '<div class="alert alert-secondary py-2 small">' + esc(d.diff.why || '') + '</div>';
    }
    (d.legs || []).forEach(l => { h += legCard(l); });

    const df = d.diff;
    if (df && df.comparable) {
      h += '<div class="fw-card">' +
        '<div class="fw-card-header"><h6 class="fw-card-title">A vs C</h6>' +
        '<span class="fw-badge ' + (df.status.same && df.body.same ? 'fw-badge-success' : 'fw-badge-warning') + '">' +
        (df.status.same && df.body.same ? 'status + body match' : 'differs') + '</span></div>' +
        '<div class="fw-card-body">';
      h += '<div class="small border-bottom py-1">Status: <span class="font-monospace">' +
        esc(df.status.a) + '</span> vs <span class="font-monospace">' + esc(df.status.c) +
        '</span> <span class="fw-badge ' + (df.status.same ? 'fw-badge-success' : 'fw-badge-danger') + '">' +
        (df.status.same ? 'same' : 'DIFFERENT') + '</span></div>';
      h += '<div class="small border-bottom py-1">Body: ' + esc(df.body.a_bytes) + ' vs ' +
        esc(df.body.c_bytes) + ' bytes <span class="fw-badge ' +
        (df.body.same ? 'fw-badge-success' : 'fw-badge-warning') + '">' +
        (df.body.same ? 'identical' : 'different') + '</span></div>';
      const hd = df.headers;
      function hlist(title, arr, cls, fmt) {
        if (!arr.length) return '';
        let s = '<div class="small fw-semibold mt-2">' + esc(title) + '</div>';
        arr.forEach(x => {
          s += '<div class="small font-monospace border-bottom py-1"><span class="fw-badge ' +
            cls + ' me-2">' + esc(x.header) + '</span>' + esc(fmt(x)) + '</div>';
        });
        return s;
      }
      h += hlist('Added by the appliance (present on A, absent on C)',
        hd.added_by_appliance, 'fw-badge-info', x => x.value);
      h += hlist('Present on C but not on A (the appliance removed it)',
        hd.dropped_before_client, 'fw-badge-warning', x => x.value);
      h += hlist('Changed', hd.changed, 'fw-badge-warning',
        x => x.a + '   →   ' + x.c);
      if (hd.volatile.length) {
        h += '<details class="mt-2"><summary class="small text-muted">' +
          hd.volatile.length + ' volatile header(s) differ — normally not a finding</summary>';
        hd.volatile.forEach(x => {
          h += '<div class="small font-monospace py-1">' + esc(x.header) + ': ' +
            esc(x.a) + ' vs ' + esc(x.c) + '</div>';
        });
        h += '</details>';
      }
      h += '</div></div>';
    }
    $('fw-tt-out').innerHTML = h;
  }

  function derive() {
    const id = $('fw-tt-devinv').value;
    const pol = $('fw-tt-policy').value.trim();
    if (!id || !pol) { $('fw-tt-err').textContent = 'Pick an appliance and type a server policy.'; return; }
    $('fw-tt-legb').innerHTML = '<div class="text-muted small">' +
      '<span class="spinner-border spinner-border-sm me-2"></span>Reading the configuration…</div>';
    post('/txn-trace/derive', { appliance_id: Number(id), policy: pol }).then(r => {
      if (!r.d || !r.d.ok) {
        $('fw-tt-legb').innerHTML = '<div class="alert alert-danger py-2 small">' +
          esc((r.d && r.d.error) || 'derive failed') + '</div>';
        return;
      }
      renderLegB(r.d);
    }).catch(e => { $('fw-tt-err').textContent = String(e); });
  }

  function renderLegB(d) {
    // The banner is not decoration: leg B is the only part of this feature
    // SATOM cannot observe, and a table that looks like the measured ones
    // would be quoted as an observation.
    let h = '<div class="alert alert-info py-2 small"><i class="bi bi-info-circle me-1"></i>' +
      '<strong>Leg B is DERIVED, not measured.</strong> ' + esc(d.note) + '</div>';
    h += '<div class="fw-card">' +
      '<div class="fw-card-header"><h6 class="fw-card-title">What ' +
      esc(d.appliance) + ' forwards for ' + esc(d.policy) + '</h6>' +
      '<span class="fw-badge fw-badge-secondary">derived</span></div>' +
      '<div class="fw-card-body">';
    (d.rows || []).forEach(r => {
      if (!r.effect && r.state === 'off') return;
      const cls = r.state === 'on' ? 'fw-badge-info' : (r.state === 'unset' ? 'fw-badge-secondary' : 'fw-badge-secondary');
      h += '<div class="small border-bottom py-1">' +
        '<span class="fw-badge ' + cls + ' me-2">' + esc(r.applies_to) + '</span>' +
        '<span class="font-monospace">' + esc(r.object) + '.' + esc(r.field) + ' = ' + esc(r.value || '(empty)') + '</span>' +
        (r.effect ? '<div class="text-muted">' + esc(r.effect) + '</div>' : '') + '</div>';
    });
    h += '</div></div>';
    if ((d.backends || []).length) {
      h += '<div class="fw-card">' +
        '<div class="fw-card-header"><h6 class="fw-card-title">Pool members</h6></div>' +
        '<div class="fw-card-body">';
      d.backends.forEach(b => {
        h += '<div class="small font-monospace border-bottom py-1">' +
          esc(b.ip + ':' + b.port) + ' · ' + esc(b.status) +
          (b.ssl ? ' · ssl ' + esc(b.ssl) : '') +
          (b.backup && b.backup !== 'disable' ? ' · BACKUP' : '') + '</div>';
      });
      h += '</div></div>';
    }
    if ((d.absent || []).length) {
      h += '<details class="mb-2"><summary class="small text-muted">' + d.absent.length +
        ' setting(s) SATOM did not read — not the same as "off"</summary>';
      d.absent.forEach(a => {
        h += '<div class="small py-1"><span class="font-monospace">' + esc(a.object + '.' + a.field) +
          '</span> — ' + esc(a.why) + '</div>';
      });
      h += '</details>';
    }
    $('fw-tt-legb').innerHTML = h;
  }

  function correlate() {
    const id = $('fw-tt-devinv').value;
    if (!id || !lastWindow) {
      $('fw-tt-err').textContent = 'Trace first, then pick the appliance whose attack log to search.';
      return;
    }
    const ips = lastLegs.map(l => (l.request || {}).ip).filter(Boolean);
    post('/txn-trace/correlate', {
      appliance_id: Number(id), window: lastWindow, source_ips: ips
    }).then(r => {
      if (!r.d || !r.d.ok) {
        $('fw-tt-corrout').innerHTML = '<div class="alert alert-danger py-2 small">' +
          esc((r.d && r.d.error) || 'correlation failed') + '</div>';
        return;
      }
      let h = '<div class="alert alert-secondary py-2 small">' + esc(r.d.note) + '</div>';
      if (!(r.d.candidates || []).length) {
        h += '<div class="small text-muted">No attack-log entry falls in the trace window.</div>';
      }
      (r.d.candidates || []).forEach(c => {
        const row = c.row || {};
        h += '<div class="fw-card"><div class="fw-card-body"><div class="small">' +
          '<strong>' + esc(row.main_type || '') + '</strong> ' + esc(row.sub_type || '') +
          ' · <span class="font-monospace">' + esc(row.http_url || '') + '</span>' +
          ' · src ' + esc(row.src || '') + '</div>' +
          '<div class="small text-muted">' + esc(c.why) + '</div></div></div>';
      });
      $('fw-tt-corrout').innerHTML = h;
    }).catch(e => { $('fw-tt-err').textContent = String(e); });
  }

  // The curl lines are built SERVER-SIDE by txn_trace.to_curl and shipped with
  // the trace. Rebuilding them here would be a second author for the same
  // string, and the copy the operator pastes into a ticket would drift from
  // the request SATOM actually sent.
  let lastCurl = [];

  function copyCurl() {
    if (!lastCurl.length) { $('fw-tt-err').textContent = 'Trace first.'; return; }
    const text = lastCurl.map(c => '# ' + (c.label || c.leg) + '\n' + c.cmd).join('\n\n');
    const show = function () {
      let pre = $('fw-tt-curlout');
      if (!pre) {
        $('fw-tt-out').insertAdjacentHTML('afterbegin',
          '<div class="fw-card">' +
          '<div class="fw-card-header"><h6 class="fw-card-title">curl</h6></div>' +
          '<div class="fw-card-body">' +
          '<pre class="fw-pre small mb-0" id="fw-tt-curlout"></pre></div></div>');
        pre = $('fw-tt-curlout');
      }
      pre.textContent = text;
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(show, show);
    } else {
      show();
    }
  }

  function downloadHar() {
    if (!lastLegs.length) { $('fw-tt-err').textContent = 'Trace first.'; return; }
    post('/txn-trace/har', { legs: lastLegs }).then(r => {
      if (!r.d || !r.d.ok) return;
      const blob = new Blob([JSON.stringify(r.d.har, null, 1)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'satom-trace.har';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(a.href);
    });
  }

  function modalObj() {
    if (window.bootstrap && bootstrap.Modal) return bootstrap.Modal.getOrCreateInstance($(MODAL_ID));
    return null;
  }

  window.FWTxnTrace = {
    open: function (prefill) {
      buildModal();
      if (prefill) $('fw-tt-vip').value = prefill;
      onMethod();
      const m = modalObj();
      if (m) m.show(); else $(MODAL_ID).style.display = 'block';
    }
  };

  document.addEventListener('click', function (ev) {
    const t = ev.target.closest && ev.target.closest('[data-fw-txntrace-open]');
    if (!t) return;
    ev.preventDefault();
    window.FWTxnTrace.open(t.getAttribute('data-fw-txntrace-open') || '');
  });
})();
