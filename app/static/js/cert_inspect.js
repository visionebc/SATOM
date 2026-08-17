// Certificate & chain inspector — header Tools menu:  FWCertInspect.open()
// Paste a PEM (or a fullchain, or an `openssl s_client` transcript) or probe a
// live host:port, and get the chain in order, every link verified, and the
// findings that decide whether a client will accept it.
//
// Light chrome ONLY (docs/safeguards.md §9m): this product is a white theme
// with an orange accent. Status colour comes from .fw-badge-*, which is
// calibrated against white — a dark-theme pastel here renders at ~1.4:1 and a
// badge that says "crit" becomes unreadable.
// CSP-safe: createElement + addEventListener only, no inline handlers.
(function () {
  if (window.FWCertInspect) return;

  function esc(s) {
    return String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, c =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function $(id) { return document.getElementById(id); }

  // Severity → badge class. The map is the ONLY place a colour is chosen, so a
  // new severity cannot silently render as the neutral grey pill.
  const SEV = { crit: 'fw-badge-danger', warn: 'fw-badge-warning', info: 'fw-badge-info', ok: 'fw-badge-success' };
  function sevClass(s) { return SEV[s] || 'fw-badge-secondary'; }

  // Built from parts at runtime, never written as one literal: a PEM
  // private-key header anywhere in a source file aborts the public-mirror
  // publish. The release scanner cannot tell a UI placeholder from a real
  // key, and must not learn to — a scanner with an exception is a scanner a
  // real key walks past. tests/test_no_pem_literals.py has enforced this
  // over .js since 2026-08-17. The concatenation renders to exactly the same
  // bytes, so the placeholder the user sees is unchanged: do NOT "simplify"
  // it back into a single string.
  const KEY_PEM_PLACEHOLDER = '-'.repeat(5) + 'BEGIN PRIVATE KEY' + '-'.repeat(5);

  const MODAL_ID = 'fw-certinspect';
  let built = false;

  function buildModal() {
    if (built) return;
    built = true;
    const wrap = document.createElement('div');
    wrap.className = 'modal fade';
    wrap.id = MODAL_ID;
    wrap.tabIndex = -1;
    wrap.innerHTML =
      '<div class="modal-dialog modal-xl modal-dialog-scrollable">' +
      '<div class="modal-content">' +
      '<div class="modal-header">' +
      '<h5 class="modal-title"><i class="bi bi-patch-check me-2"></i>Certificate inspector</h5>' +
      '<button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>' +
      '<div class="modal-body">' +
      '<ul class="nav nav-tabs mb-3" id="fw-ci-tabs">' +
      '<li class="nav-item"><a class="nav-link active" href="#" data-ci-tab="paste">Paste PEM</a></li>' +
      '<li class="nav-item"><a class="nav-link" href="#" data-ci-tab="probe">Probe a host</a></li>' +
      '</ul>' +

      '<div data-ci-pane="paste">' +
      '<div class="row g-2">' +
      '<div class="col-md-8">' +
      '<label class="form-label small text-muted mb-1">Certificate / fullchain (PEM)</label>' +
      '<textarea id="fw-ci-pem" class="form-control font-monospace" rows="7" ' +
      'placeholder="-----BEGIN CERTIFICATE-----&#10;…"></textarea></div>' +
      '<div class="col-md-4">' +
      '<label class="form-label small text-muted mb-1">Hostname to check (optional)</label>' +
      '<input id="fw-ci-host" class="form-control" placeholder="shop.example.com">' +
      '<label class="form-label small text-muted mb-1 mt-2">Private key (optional)</label>' +
      '<textarea id="fw-ci-key" class="form-control font-monospace" rows="3" ' +
      'placeholder="' + KEY_PEM_PLACEHOLDER + '"></textarea>' +
      '<div class="form-text">Checked in-process against the leaf. Never stored, never logged.</div>' +
      '</div></div>' +
      '<div class="mt-2"><button class="fw-btn fw-btn-primary" id="fw-ci-run">' +
      '<i class="bi bi-search me-1"></i>Inspect</button></div>' +
      '</div>' +

      '<div data-ci-pane="probe" style="display:none">' +
      '<div class="row g-2 align-items-end">' +
      '<div class="col-md-5">' +
      '<label class="form-label small text-muted mb-1">Inventory destination</label>' +
      '<select id="fw-ci-inv" class="form-select"></select></div>' +
      '<div class="col-md-5">' +
      '<label class="form-label small text-muted mb-1">…or a free target ' +
      '<span id="fw-ci-freelock" class="fw-badge fw-badge-secondary ms-1" style="display:none">permission required</span></label>' +
      '<input id="fw-ci-free" class="form-control" placeholder="host:443 or https://host/path"></div>' +
      '<div class="col-md-2">' +
      '<button class="fw-btn fw-btn-primary w-100" id="fw-ci-probe"><i class="bi bi-broadcast me-1"></i>Probe</button>' +
      '</div></div>' +
      '<div class="form-text mt-1" id="fw-ci-probenote"></div>' +
      '</div>' +

      '<div id="fw-ci-err" class="text-danger small mt-2"></div>' +
      '<div id="fw-ci-out" class="mt-3"></div>' +
      '</div></div></div>';
    document.body.appendChild(wrap);

    wrap.querySelectorAll('[data-ci-tab]').forEach(a => {
      a.addEventListener('click', function (ev) {
        ev.preventDefault();
        const t = a.getAttribute('data-ci-tab');
        wrap.querySelectorAll('[data-ci-tab]').forEach(x =>
          x.classList.toggle('active', x === a));
        wrap.querySelectorAll('[data-ci-pane]').forEach(p => {
          p.style.display = (p.getAttribute('data-ci-pane') === t) ? '' : 'none';
        });
      });
    });
    $('fw-ci-run').addEventListener('click', runPaste);
    $('fw-ci-probe').addEventListener('click', runProbe);
    loadTargets();
  }

  function loadTargets() {
    fetch('/cert-inspect/targets', { headers: { 'Accept': 'application/json' } })
      .then(r => r.json())
      .then(d => {
        if (!d || !d.ok) return;
        const sel = $('fw-ci-inv');
        sel.innerHTML = '<option value="">— pick an appliance —</option>' +
          (d.targets || []).map(t =>
            '<option value="' + esc(t.host) + '">' + esc(t.name) + ' — ' +
            esc(t.host) + ':' + esc(t.port) + '</option>').join('');
        if (!d.may_free) {
          $('fw-ci-free').disabled = true;
          $('fw-ci-freelock').style.display = '';
        }
        // The chain/leaf distinction is a property of the SERVER, not of the
        // certificate — saying so before the operator probes is what stops
        // "completeness unknown" reading as a defect in their target.
        $('fw-ci-probenote').textContent = d.openssl
          ? 'The full chain is read with openssl s_client, so chain completeness is measured.'
          : 'openssl is not installed on this SATOM node: only the leaf can be read, and chain completeness will be reported as UNKNOWN (not "incomplete").';
      })
      .catch(() => {});
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

  function busy(on, msg) {
    $('fw-ci-err').textContent = '';
    $('fw-ci-out').innerHTML = on
      ? '<div class="text-muted small"><span class="spinner-border spinner-border-sm me-2"></span>' + esc(msg) + '</div>'
      : '';
  }

  function runPaste() {
    busy(true, 'Parsing…');
    post('/cert-inspect/paste', {
      pem: $('fw-ci-pem').value,
      key: $('fw-ci-key').value,
      hostname: $('fw-ci-host').value.trim()
    }).then(r => {
      if (!r.d || !r.d.ok) { fail(r.d); return; }
      render(r.d, null);
    }).catch(e => fail({ error: String(e) }));
  }

  function runProbe() {
    const inv = $('fw-ci-inv').value;
    const free = $('fw-ci-free').value.trim();
    if (!inv && !free) { $('fw-ci-err').textContent = 'Pick an inventory destination or type a target.'; return; }
    busy(true, 'Opening a TLS connection from the server…');
    post('/cert-inspect/probe', inv
      ? { mode: 'inventory', target: inv }
      : { mode: 'free', target: free }
    ).then(r => {
      if (!r.d || !r.d.ok) { fail(r.d); return; }
      render(r.d, r.d);
    }).catch(e => fail({ error: String(e) }));
  }

  function fail(d) {
    $('fw-ci-out').innerHTML = '';
    $('fw-ci-err').textContent = (d && d.error) ? d.error : 'The request failed.';
  }

  function kv(k, v, mono) {
    return '<div class="d-flex justify-content-between border-bottom py-1 small">' +
      '<span class="text-muted">' + esc(k) + '</span>' +
      '<span class="' + (mono ? 'font-monospace ' : '') + 'text-end">' + esc(v) + '</span></div>';
  }

  function chainBanner(d) {
    if (d.chain_source === 'leaf') {
      return '<div class="alert alert-info py-2 small mb-3">' +
        '<i class="bi bi-info-circle me-1"></i><strong>Chain completeness: UNKNOWN.</strong> ' +
        'Only the leaf certificate could be read on this node, so whether the server sends its ' +
        'intermediates was not measured. This is not the same as "incomplete".</div>';
    }
    if (d.chain_complete === true) {
      return '<div class="alert alert-success py-2 small mb-3">' +
        '<i class="bi bi-check-circle me-1"></i><strong>Chain complete</strong> — ' + esc(d.chain_anchor) + '</div>';
    }
    if (d.chain_complete === false) {
      return '<div class="alert alert-danger py-2 small mb-3">' +
        '<i class="bi bi-exclamation-octagon me-1"></i><strong>Chain incomplete</strong> — ' + esc(d.chain_anchor) + '</div>';
    }
    return '';
  }

  function render(d, probe) {
    let h = '';
    if (probe) {
      h += '<div class="small text-muted mb-2">Connected to <span class="font-monospace">' +
        esc(probe.resolved) + ':' + esc(probe.port) + '</span>, SNI <span class="font-monospace">' +
        esc(probe.sni) + '</span>' +
        (probe.protocol ? ' · ' + esc(probe.protocol) : '') +
        (probe.cipher ? ' · ' + esc(probe.cipher) : '') + '</div>';
    }
    h += chainBanner(d);

    const fs = d.findings || [];
    if (!fs.length) {
      h += '<div class="alert alert-success py-2 small"><i class="bi bi-check-circle me-1"></i>' +
        'Nothing to report on ' + esc(d.count) + ' certificate(s).</div>';
    } else {
      h += '<div class="fw-card p-0 mb-3"><div class="list-group list-group-flush">';
      fs.forEach(f => {
        h += '<div class="list-group-item">' +
          '<div class="d-flex align-items-start gap-2">' +
          '<span class="fw-badge ' + sevClass(f.severity) + '">' + esc(f.severity) + '</span>' +
          '<div class="flex-grow-1"><div class="fw-semibold">' + esc(f.title) + '</div>' +
          '<div class="small text-muted">' + esc(f.detail) + '</div>' +
          (f.fix ? '<div class="small mt-1"><i class="bi bi-wrench-adjustable me-1"></i>' + esc(f.fix) + '</div>' : '') +
          '</div></div></div>';
      });
      h += '</div></div>';
    }

    (d.certificates || []).forEach((c, i) => {
      const role = i === 0 ? 'leaf' : (c.self_signed ? 'root' : 'intermediate');
      h += '<div class="fw-card p-3 mb-2">' +
        '<div class="d-flex justify-content-between align-items-center mb-2">' +
        '<strong>' + esc(c.cn || c.subject_dn || ('certificate ' + (i + 1))) + '</strong>' +
        '<span class="fw-badge fw-badge-secondary">' + esc(role) + '</span></div>' +
        kv('Subject', c.subject_dn, true) +
        kv('Issuer', c.issuer_dn, true) +
        kv('Valid', (c.not_before || '?') + '  →  ' + (c.not_after || '?')) +
        kv('Days left', c.days_left === null || c.days_left === undefined ? '?' : c.days_left) +
        kv('Key', (c.key_type || '?') + (c.key_bits ? ' ' + c.key_bits + '-bit' : '')) +
        kv('Signature hash', c.sig_algo || '?') +
        kv('Serial', c.serial, true) +
        kv('SHA-256', c.fingerprint_sha256, true) +
        ((c.sans && c.sans.length) ? kv('SAN', c.sans.join(', '), true) : '') +
        '</div>';
    });

    if (d.links && d.links.length) {
      h += '<div class="fw-card p-3 mb-2"><div class="fw-semibold mb-2">Link verification</div>';
      d.links.forEach(l => {
        const b = l.verified === true ? 'fw-badge-success' :
          l.verified === false ? 'fw-badge-danger' : 'fw-badge-secondary';
        const t = l.verified === true ? 'signature verified' :
          l.verified === false ? 'SIGNATURE DOES NOT VERIFY' : 'not checked (unsupported algorithm)';
        h += '<div class="small py-1 border-bottom"><span class="fw-badge ' + b + ' me-2">' + esc(t) + '</span>' +
          '<span class="font-monospace">' + esc(l.child) + '</span> ← <span class="font-monospace">' + esc(l.parent) + '</span></div>';
      });
      h += '</div>';
    }

    if (d.hostname && d.hostname.checked) {
      const ok = d.hostname.match === true;
      h += '<div class="fw-card p-3 mb-2"><div class="fw-semibold mb-1">Hostname</div>' +
        '<span class="fw-badge ' + (ok ? 'fw-badge-success' : 'fw-badge-danger') + '">' +
        (ok ? 'covered by ' + esc(d.hostname.matched_name) : 'NOT covered') + '</span>' +
        '<div class="small text-muted mt-1">Checked against ' + esc(d.hostname.source) + ': ' +
        esc((d.hostname.names || []).join(', ')) + '</div></div>';
    }
    if (d.private_key && d.private_key.checked) {
      const ok = d.private_key.match === true;
      h += '<div class="fw-card p-3 mb-2"><div class="fw-semibold mb-1">Private key</div>' +
        '<span class="fw-badge ' + (ok ? 'fw-badge-success' : 'fw-badge-danger') + '">' +
        (ok ? 'matches the leaf certificate' : 'DOES NOT match the leaf certificate') + '</span></div>';
    }
    $('fw-ci-out').innerHTML = h;
  }

  function modalObj() {
    if (window.bootstrap && bootstrap.Modal) return bootstrap.Modal.getOrCreateInstance($(MODAL_ID));
    return null;
  }

  window.FWCertInspect = {
    open: function (prefill) {
      buildModal();
      if (prefill) { $('fw-ci-free').value = prefill; }
      const m = modalObj();
      if (m) m.show(); else $(MODAL_ID).style.display = 'block';
    }
  };

  document.addEventListener('click', function (ev) {
    const t = ev.target.closest && ev.target.closest('[data-fw-certinspect-open]');
    if (!t) return;
    ev.preventDefault();
    window.FWCertInspect.open(t.getAttribute('data-fw-certinspect-open') || '');
  });
})();
