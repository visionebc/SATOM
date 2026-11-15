// Transaction tracer — the PAGE at /txn-trace/ (Operations › Troubleshooting).
// Until 2026-10-16 it was a header Tools-menu modal; the form markup now lives
// in templates/txn_trace/index.html so its labels translate, and this file
// renders what the trace RETURNS.
//
// Leg A (through the appliance), leg B (DERIVED from its config, never
// measured) and leg C (straight to the backend), plus the diff that answers
// "is it the WAF or is it the app?", every cookie the legs set, and a HAR
// viewer that reads the trace's HAR or any HAR file the operator opens
// (read in the browser, never uploaded).
//
// Light chrome ONLY (docs/safeguards.md §9m). CSP-safe: no inline handlers.
// Turbo Drive re-runs this script on every visit: the definitions run once,
// init() runs on every visit that lands on the page.
(function () {
  if (!window.FWTxnTrace) {
    function esc(s) {
      return String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }
    function $(id) { return document.getElementById(id); }

    let lastLegs = [];
    let lastWindow = null;
    let lastCurl = [];
    let harEntries = [];

    const VERDICT_CLASS = {
      appliance_decides: 'alert-danger',
      body_differs: 'alert-warning',
      appliance_transforms: 'alert-info',
      transparent: 'alert-success'
    };
    const FINDING_BADGE = { danger: 'fw-badge-danger', warning: 'fw-badge-warning', info: 'fw-badge-secondary' };
    // A HAR file is read whole into memory; a devtools export of a long session
    // can be hundreds of MB and would freeze the tab instead of failing.
    const MAX_HAR_BYTES = 50 * 1024 * 1024;
    const MAX_TEXT = 200 * 1024;
    // A session value is one 100-300 character token: in a narrow column it
    // broke one character per line (seen in the first live render). A block
    // with a floor and a ceiling wraps it into a few readable lines.
    const VALUE_CELL = 'min-width:240px;max-width:420px;word-break:break-all;white-space:normal';

    let CTX = { safe_methods: ['GET'], mutating_methods: [], may_free: false };

    function init() {
      const root = $('fw-tt-page');
      if (!root || root.dataset.ttBound) return;
      root.dataset.ttBound = '1';
      lastLegs = []; lastWindow = null; lastCurl = []; harEntries = [];
      $('fw-tt-run').addEventListener('click', run);
      $('fw-tt-derive').addEventListener('click', derive);
      $('fw-tt-curl').addEventListener('click', copyCurl);
      $('fw-tt-har').addEventListener('click', downloadHar);
      $('fw-tt-harview').addEventListener('click', viewTraceHar);
      $('fw-tt-corr').addEventListener('click', correlate);
      $('fw-tt-method').addEventListener('change', onMethod);
      $('fw-tt-harfile').addEventListener('change', openHarFile);
      $('fw-tt-harfilter').addEventListener('input', renderHarTable);
      $('fw-tt-vipinv').addEventListener('change', function () {
        if (this.value) $('fw-tt-vip').value = '';
      });
      if (root.dataset.prefillVip) $('fw-tt-vip').value = root.dataset.prefillVip;
      if (root.dataset.prefillBackend) $('fw-tt-backend').value = root.dataset.prefillBackend;
      if (root.dataset.prefillPath) $('fw-tt-path').value = root.dataset.prefillPath;
      loadContext();
    }

    function loadContext() {
      fetch('/txn-trace/context', { headers: { Accept: 'application/json' } })
        .then(r => r.json()).then(d => {
          if (!d || !d.ok || !$('fw-tt-page')) return;
          CTX = d;
          // An inventory pick is the appliance's MANAGEMENT address on its
          // configured port, not a VIP: SATOM knows the device, not the virtual
          // servers behind it. Type the VIP in the free field for that.
          const opts = (d.appliances || []).map(a => {
            const hp = (String(a.host).indexOf(':') >= 0 ? '[' + a.host + ']' : a.host) + ':' + (a.port || 443);
            return '<option value="' + esc(hp) + '">' + esc(a.name) + ' — management ' + esc(hp) + '</option>';
          }).join('');
          $('fw-tt-vipinv').innerHTML = '<option value="">— VIP typed on the right —</option>' + opts;
          // Leg B reads FortiWeb server policies: only FortiWeb devices can answer.
          $('fw-tt-devinv').innerHTML = '<option value="">— pick a FortiWeb —</option>' +
            (d.appliances || []).filter(a => a.kind === 'fortiweb').map(a =>
              '<option value="' + a.id + '">' + esc(a.name) + '</option>').join('');
          $('fw-tt-method').innerHTML =
            d.safe_methods.map(m => '<option>' + esc(m) + '</option>').join('') +
            d.mutating_methods.map(m => '<option>' + esc(m) + '</option>').join('');
          if (!d.may_free) {
            $('fw-tt-vip').disabled = true;
            $('fw-tt-vip').placeholder = 'free targets need the ' + d.free_permission + ' permission';
            $('fw-tt-backend').disabled = true;
            $('fw-tt-backend').placeholder = 'a backend is a free target: needs ' + d.free_permission;
          }
          onMethod();
        }).catch(() => {});
    }

    function onMethod() {
      const m = $('fw-tt-method').value;
      const mutating = (CTX.mutating_methods || []).indexOf(m) >= 0;
      $('fw-tt-confirmwrap').style.display = mutating ? '' : 'none';
      if (!mutating) $('fw-tt-confirm').checked = false;
    }

    function checked(el) { return !!(el && el.checked); }

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
      $('fw-tt-cookies').innerHTML = '';
      $('fw-tt-out').innerHTML = '<div class="text-muted small">' +
        '<span class="spinner-border spinner-border-sm me-2"></span>Tracing…</div>';
      post('/txn-trace/run', {
        mode_a: $('fw-tt-vipinv').value ? 'inventory' : 'free',
        mode_c: backend ? 'free' : 'inventory',
        vip: vip, backend: backend,
        method: $('fw-tt-method').value,
        path: $('fw-tt-path').value.trim() || '/',
        headers: $('fw-tt-headers').value,
        body: $('fw-tt-body').value,
        confirm_mutating: $('fw-tt-confirm').checked,
        reveal: checked($('fw-tt-reveal'))
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
        renderCookies(r.d);
        obsGrade(r.d);
      }).catch(e => { $('fw-tt-err').textContent = String(e); });
    }

    // The security-header grade of leg A's response (HTTP Observatory
    // scoring, headers only) and a way to the full site grade. Scores what the
    // trace already returned; no extra request leaves this server.
    function obsGrade(d) {
      const box = $('fw-tt-obsgrade');
      if (!box) return;
      box.innerHTML = '';
      const a = (d.legs || []).find(l => l.leg === 'a' && l.ok);
      if (!a) return;
      const rq = a.request || {};
      post('/observatory/api/grade-headers', {
        headers: a.headers || [], set_cookie: a.set_cookie || [],
        url: (rq.scheme || 'https') + '://' + (rq.host || '') + (rq.path || '/')
      }).then(r => {
        if (!r.d || !r.d.ok) return;
        const g = r.d.grade || '';
        const cls = g.charAt(0) === 'A' ? 'fw-badge-success' : g.charAt(0) === 'B' ? 'fw-badge-info'
          : g.charAt(0) === 'C' ? 'fw-badge-warning' : 'fw-badge-danger';
        box.innerHTML = '<div class="small d-flex align-items-center gap-2 flex-wrap">' +
          '<i class="bi bi-clipboard2-pulse"></i> Security headers of leg A ' +
          '<span class="fw-badge ' + cls + '" style="font-weight:700">' + esc(g) + '</span> ' +
          esc(r.d.score) + ' <span class="text-muted">(' + esc(r.d.note) + ')</span>' +
          '<a class="btn btn-sm btn-fw-outline" href="/observatory/">Open in HTTP Observatory</a></div>';
      }).catch(() => {});
    }

    function ms(v) { return (v === null || v === undefined) ? '—' : v + ' ms'; }

    // Credential values, when the trace was run with Reveal values, arrive in
    // the leg's SEPARATE `secrets` block; every other field is redacted. The
    // panel puts them back next to the header they belong to, marked.
    function secretPool(pairs) {
      const pool = {};
      (pairs || []).forEach(kv => {
        const k = String(kv[0]).toLowerCase();
        (pool[k] = pool[k] || []).push(kv[1]);
      });
      return pool;
    }

    function headerRows(pairs, secretPairs) {
      const pool = secretPool(secretPairs);
      let h = '';
      (pairs || []).forEach(kv => {
        const vals = pool[String(kv[0]).toLowerCase()];
        const real = vals && vals.length ? vals.shift() : null;
        h += '<div class="small font-monospace border-bottom py-1 text-break">' + esc(kv[0]) + ': ' +
          (real !== null
            ? esc(real) + ' <span class="fw-badge fw-badge-warning ms-1">revealed</span>'
            : esc(kv[1])) + '</div>';
      });
      return h;
    }

    function legCard(leg) {
      const t = leg.timing || {};
      const sec = leg.secrets || null;
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
      h += '<div class="small font-monospace mb-2 text-break">' + esc(rq.method) + ' ' +
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
      h += '<details><summary class="small">Request headers sent (' + (rq.headers || []).length + ')</summary>' +
        '<div class="mt-1">' + headerRows(rq.headers, sec && sec.request_headers) + '</div></details>';
      h += '<details><summary class="small">Response headers (' + (leg.headers || []).length + ')</summary>' +
        '<div class="mt-1">' + headerRows(leg.headers, sec && sec.response_headers) + '</div></details>';
      if (leg.body_preview) {
        h += '<details><summary class="small">Response body (first ' + esc(leg.body_preview.length) +
          ' characters)</summary><pre class="fw-pre small mt-1 mb-0">' + esc(leg.body_preview) + '</pre></details>';
      }
      h += '<div class="small text-muted mt-2">body ' + esc(leg.body_bytes) + ' bytes' +
        (leg.truncated ? ' (truncated)' : '') + ' · sha256 ' + esc((leg.body_sha256 || '').slice(0, 16)) + '…</div>';
      return h + '</div></div>';
    }

    function render(d) {
      let h = '';
      const v = (d.diff || {}).verdict;
      if (d.revealed) {
        h += '<div class="alert alert-warning py-2 small"><i class="bi bi-eye me-1"></i>' +
          'Credential values are shown on this page. They were not written to the audit log; ' +
          'leaving or reloading the page discards them.</div>';
      }
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
            s += '<div class="small font-monospace border-bottom py-1 text-break"><span class="fw-badge ' +
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

    // ---- Cookies ---------------------------------------------------------
    function flag(on) {
      return on ? '<span class="fw-badge fw-badge-success">yes</span>'
                : '<span class="fw-badge fw-badge-secondary">no</span>';
    }

    function cookieTable(leg, findings) {
      const cookies = leg.set_cookie || [];
      const values = (leg.secrets && leg.secrets.set_cookie_values) || null;
      const sent = (leg.request || {}).cookie_names || [];
      let h = '<div class="fw-card"><div class="fw-card-header">' +
        '<h6 class="fw-card-title">Cookies — leg ' + esc((leg.leg || '').toUpperCase()) + '</h6>' +
        '<span class="fw-badge fw-badge-secondary">' + cookies.length + ' set</span></div>' +
        '<div class="fw-card-body">';
      if (sent.length) {
        h += '<div class="small mb-2">Sent with the request: ' +
          sent.map(n => '<span class="fw-badge fw-badge-info me-1">' + esc(n) + '</span>').join('') + '</div>';
      }
      if (!cookies.length) {
        h += '<div class="small text-muted">This response set no cookie.</div></div></div>';
        return h;
      }
      h += '<div class="fw-table-wrapper"><table class="fw-table small mb-0"><thead><tr>' +
        '<th>Name</th><th>Value</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th>' +
        '<th>Path</th><th>Domain</th><th>Expires / Max-Age</th></tr></thead><tbody>';
      cookies.forEach((c, i) => {
        const val = values ? values[i] : null;
        h += '<tr><td class="font-monospace">' + esc(c.name) + '</td>' +
          '<td>' + (val !== null && val !== undefined
            ? '<span class="fw-badge fw-badge-warning fw-badge-nowrap">revealed</span>' +
              '<div class="font-monospace small mt-1" style="' + VALUE_CELL + '">' + esc(val) + '</div>'
            : '<span class="text-muted">redacted</span>') + '</td>' +
          '<td>' + flag(c.secure) + '</td><td>' + flag(c.httponly) + '</td>' +
          '<td>' + esc(c.samesite || '—') + '</td><td class="font-monospace">' + esc(c.path || '—') + '</td>' +
          '<td class="font-monospace">' + esc(c.domain || '—') + '</td>' +
          '<td class="font-monospace">' + esc(c.max_age ? 'Max-Age=' + c.max_age : (c.expires || 'session')) + '</td></tr>';
      });
      h += '</tbody></table></div>';
      if ((findings || []).length) {
        h += '<div class="small fw-semibold mt-2">What a browser does with them</div>';
        findings.forEach(f => {
          h += '<div class="small border-bottom py-1"><span class="fw-badge ' +
            (FINDING_BADGE[f.level] || 'fw-badge-secondary') + ' me-2">' + esc(f.cookie) + '</span>' +
            esc(f.text) + '</div>';
        });
      }
      return h + '</div></div>';
    }

    function renderCookies(d) {
      let h = '';
      const findings = d.cookie_findings || {};
      (d.legs || []).filter(l => l.ok).forEach(l => { h += cookieTable(l, findings[l.leg]); });
      const ck = (d.diff || {}).cookies;
      if (d.diff && d.diff.comparable && ck) {
        const none = !(ck.added_by_appliance || []).length && !(ck.dropped_by_appliance || []).length &&
          !(ck.flags_changed || []).length;
        h += '<div class="fw-card"><div class="fw-card-header"><h6 class="fw-card-title">Cookies A vs C</h6>' +
          '<span class="fw-badge ' + (none ? 'fw-badge-success' : 'fw-badge-warning') + '">' +
          (none ? 'same cookies, same flags' : 'differ') + '</span></div><div class="fw-card-body">';
        (ck.added_by_appliance || []).forEach(c => {
          h += '<div class="small border-bottom py-1"><span class="fw-badge fw-badge-info me-2">' + esc(c.name) +
            '</span>issued by the appliance (set on A, not on C) — its own session or persistence cookie</div>';
        });
        (ck.dropped_by_appliance || []).forEach(c => {
          h += '<div class="small border-bottom py-1"><span class="fw-badge fw-badge-warning me-2">' + esc(c.name) +
            '</span>set by the backend but not by the appliance — the appliance removed it</div>';
        });
        (ck.flags_changed || []).forEach(c => {
          h += '<div class="small border-bottom py-1"><span class="fw-badge fw-badge-warning me-2">' + esc(c.name) +
            '</span>rewritten: ' + c.flags.map(f => esc(f.flag + ' ' + JSON.stringify(f.c) + ' → ' + JSON.stringify(f.a))).join(', ') +
            ' <span class="text-muted">(backend → client)</span></div>';
        });
        if (none) h += '<div class="small text-muted">The appliance neither adds, removes nor rewrites a cookie on this transaction.</div>';
        h += '</div></div>';
      }
      $('fw-tt-cookies').innerHTML = h;
    }

    // ---- Leg B / correlation ---------------------------------------------
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
        const cls = r.state === 'on' ? 'fw-badge-info' : 'fw-badge-secondary';
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
      // The tracer's EGRESS address (the source the appliance logged), not the
      // address each leg dialled.
      const ips = lastLegs.map(l => (l.request || {}).src_ip).filter(Boolean);
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

    // ---- HAR -------------------------------------------------------------
    // The HAR of a trace is built SERVER-SIDE (txn_trace.to_har) for the same
    // reason as the curl line. Values travel only when the operator ticked
    // "include values" AND holds the reveal permission; the server refuses the
    // request otherwise rather than handing back a quietly redacted file.
    function traceHar() {
      if (!lastLegs.length) {
        $('fw-tt-err').textContent = 'Trace first.';
        return Promise.resolve(null);
      }
      return post('/txn-trace/har', { legs: lastLegs, secrets: checked($('fw-tt-harvalues')) }).then(r => {
        if (!r.d || !r.d.ok) {
          $('fw-tt-err').textContent = (r.d && r.d.error) || 'HAR export failed.';
          return null;
        }
        return r.d;
      });
    }

    function downloadHar() {
      traceHar().then(d => {
        if (!d) return;
        const blob = new Blob([JSON.stringify(d.har, null, 1)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = d.secrets ? 'satom-trace-with-values.har' : 'satom-trace.har';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(a.href);
      });
    }

    function viewTraceHar() {
      traceHar().then(d => {
        if (!d) return;
        showHar(d.har, 'This trace' + (d.secrets ? ' — with values' : ' — values redacted'));
        $('fw-tt-harcard').scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    }

    function openHarFile(ev) {
      const f = ev.target.files && ev.target.files[0];
      ev.target.value = '';
      if (!f) return;
      if (f.size > MAX_HAR_BYTES) {
        $('fw-tt-hartable').innerHTML = '<div class="alert alert-danger py-2 small">' +
          esc(f.name) + ' is ' + esc(Math.round(f.size / 1048576)) + ' MB; the viewer reads up to ' +
          esc(MAX_HAR_BYTES / 1048576) + ' MB.</div>';
        return;
      }
      const rd = new FileReader();
      rd.onload = function () {
        let har;
        try { har = JSON.parse(rd.result); } catch (e) {
          $('fw-tt-hartable').innerHTML = '<div class="alert alert-danger py-2 small">' +
            esc(f.name) + ' is not JSON: ' + esc(e.message) + '</div>';
          return;
        }
        showHar(har, f.name + ' — read locally, not uploaded');
      };
      rd.onerror = function () {
        $('fw-tt-hartable').innerHTML = '<div class="alert alert-danger py-2 small">Could not read ' + esc(f.name) + '.</div>';
      };
      rd.readAsText(f);
    }

    function showHar(har, source) {
      const log = har && har.log;
      $('fw-tt-hardetail').innerHTML = '';
      if (!log || !Array.isArray(log.entries)) {
        harEntries = [];
        $('fw-tt-harsrc').textContent = source;
        $('fw-tt-hartable').innerHTML = '<div class="alert alert-danger py-2 small">' +
          'Not a HAR file: there is no log.entries list.</div>';
        return;
      }
      harEntries = log.entries.map((e, i) => ({ e: e || {}, i: i }));
      const creator = log.creator ? (log.creator.name || '') + ' ' + (log.creator.version || '') : '';
      $('fw-tt-harsrc').textContent = source + ' · ' + harEntries.length + ' entr' +
        (harEntries.length === 1 ? 'y' : 'ies') + (creator.trim() ? ' · ' + creator.trim() : '') +
        (log.comment ? ' · ' + log.comment : '');
      renderHarTable();
    }

    function startMs(e) {
      const t = Date.parse(e.startedDateTime || '');
      return isNaN(t) ? null : t;
    }

    function statusBadge(s) {
      s = Number(s) || 0;
      const cls = s === 0 ? 'fw-badge-danger' : s < 300 ? 'fw-badge-success' : s < 400 ? 'fw-badge-info'
        : s < 500 ? 'fw-badge-warning' : 'fw-badge-danger';
      return '<span class="fw-badge ' + cls + '">' + esc(s || 'failed') + '</span>';
    }

    function size(n) {
      n = Number(n);
      if (!(n >= 0)) return '—';
      return n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
    }

    function renderHarTable() {
      if (!harEntries.length) {
        if ($('fw-tt-harsrc').textContent) {
          $('fw-tt-hartable').innerHTML = '<div class="small text-muted">This HAR has no entries.</div>';
        }
        return;
      }
      const q = ($('fw-tt-harfilter').value || '').trim().toLowerCase();
      const starts = harEntries.map(x => startMs(x.e)).filter(t => t !== null);
      const t0 = starts.length ? Math.min.apply(null, starts) : null;
      let tEnd = t0;
      harEntries.forEach(x => {
        const s = startMs(x.e);
        if (s !== null) tEnd = Math.max(tEnd, s + (Number(x.e.time) || 0));
      });
      const span = Math.max(1, (tEnd || 0) - (t0 || 0));
      let rows = '';
      let shown = 0;
      harEntries.forEach(x => {
        const e = x.e, rq = e.request || {}, rs = e.response || {};
        const hay = ((rq.method || '') + ' ' + (rq.url || '') + ' ' + (rs.status || '') + ' ' +
          (e.comment || '')).toLowerCase();
        if (q && hay.indexOf(q) < 0) return;
        shown++;
        const s = startMs(e);
        const left = (t0 !== null && s !== null) ? ((s - t0) / span) * 100 : 0;
        const width = Math.max(0.5, ((Number(e.time) || 0) / span) * 100);
        const mime = ((rs.content || {}).mimeType || '').split(';')[0];
        rows += '<tr data-har-row="' + x.i + '" style="cursor:pointer">' +
          '<td class="text-muted">' + (x.i + 1) + '</td>' +
          '<td class="font-monospace">' + esc(rq.method || '') + '</td>' +
          '<td>' + statusBadge(rs.status) + '</td>' +
          '<td class="font-monospace text-break">' + esc(rq.url || '') +
          (e.comment ? ' <span class="text-muted">· ' + esc(e.comment) + '</span>' : '') + '</td>' +
          '<td class="small">' + esc(mime || '—') + '</td>' +
          '<td class="text-nowrap">' + esc(size((rs.content || {}).size !== undefined ? rs.content.size : rs.bodySize)) + '</td>' +
          '<td class="text-nowrap">' + esc(Math.round(Number(e.time) || 0)) + ' ms</td>' +
          '<td style="min-width:120px"><div class="bg-light border" style="height:8px;position:relative">' +
          '<div class="bg-primary" style="position:absolute;top:0;bottom:0;left:' + left.toFixed(2) +
          '%;width:' + Math.min(100 - left, width).toFixed(2) + '%"></div></div></td></tr>';
      });
      $('fw-tt-hartable').innerHTML = '<div class="small text-muted mb-1">' + shown + ' of ' +
        harEntries.length + ' shown · click a row for its headers, cookies, timings and content</div>' +
        '<div class="fw-table-wrapper"><table class="fw-table small mb-0"><thead><tr>' +
        '<th>#</th><th>Method</th><th>Status</th><th>URL</th><th>Type</th><th>Size</th><th>Time</th><th>Waterfall</th>' +
        '</tr></thead><tbody>' + rows + '</tbody></table></div>';
      $('fw-tt-hartable').querySelectorAll('[data-har-row]').forEach(tr => {
        tr.addEventListener('click', () => showHarEntry(Number(tr.getAttribute('data-har-row'))));
      });
    }

    function nvTable(list, empty) {
      if (!Array.isArray(list) || !list.length) return '<div class="small text-muted">' + esc(empty) + '</div>';
      return list.map(h => '<div class="small font-monospace border-bottom py-1 text-break">' +
        esc(h.name) + ': ' + esc(h.value) + '</div>').join('');
    }

    function harCookies(list, title) {
      let h = '<div class="small fw-semibold mt-2">' + esc(title) + '</div>';
      if (!Array.isArray(list) || !list.length) return h + '<div class="small text-muted">none</div>';
      h += '<div class="fw-table-wrapper"><table class="fw-table small mb-0"><thead><tr><th>Name</th><th>Value</th>' +
        '<th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Path</th><th>Domain</th><th>Expires</th></tr></thead><tbody>';
      list.forEach(c => {
        h += '<tr><td class="font-monospace">' + esc(c.name) + '</td>' +
          '<td>' + (c.value ? '<div class="font-monospace small" style="' + VALUE_CELL + '">' + esc(c.value) + '</div>'
            : '<span class="text-muted">—</span>') + '</td>' +
          '<td>' + (c.secure === undefined ? '—' : flag(c.secure)) + '</td>' +
          '<td>' + (c.httpOnly === undefined ? '—' : flag(c.httpOnly)) + '</td>' +
          '<td>' + esc(c.sameSite || '—') + '</td><td class="font-monospace">' + esc(c.path || '—') + '</td>' +
          '<td class="font-monospace">' + esc(c.domain || '—') + '</td><td class="font-monospace">' + esc(c.expires || '—') + '</td></tr>';
      });
      return h + '</tbody></table></div>';
    }

    function showHarEntry(i) {
      const x = harEntries.find(y => y.i === i);
      if (!x) return;
      const e = x.e, rq = e.request || {}, rs = e.response || {}, tm = e.timings || {};
      const content = rs.content || {};
      let text = typeof content.text === 'string' ? content.text : '';
      let note = '';
      if (content.encoding === 'base64') note = 'base64-encoded (shown as stored)';
      if (text.length > MAX_TEXT) { text = text.slice(0, MAX_TEXT); note = 'first ' + MAX_TEXT + ' characters shown'; }
      let timings = '';
      ['blocked', 'dns', 'connect', 'ssl', 'send', 'wait', 'receive'].forEach(k => {
        const v = tm[k];
        timings += '<div class="small border-bottom py-1"><span class="font-monospace">' + esc(k) + '</span>: ' +
          esc(v === undefined || v === null || v < 0 ? 'n/a' : Math.round(v * 10) / 10 + ' ms') + '</div>';
      });
      let h = '<div class="fw-card"><div class="fw-card-header">' +
        '<h6 class="fw-card-title text-break">#' + (i + 1) + ' ' + esc(rq.method || '') + ' ' + esc(rq.url || '') + '</h6>' +
        statusBadge(rs.status) + '</div><div class="fw-card-body">' +
        '<div class="small text-muted mb-2">' + esc(e.startedDateTime || '') +
        (e.serverIPAddress ? ' · server ' + esc(e.serverIPAddress) : '') +
        ' · ' + esc(rs.httpVersion || '') + ' ' + esc(rs.statusText || '') +
        (rs.redirectURL ? ' · redirect → ' + esc(rs.redirectURL) : '') + '</div>' +
        '<div class="row g-3"><div class="col-lg-6">' +
        '<div class="small fw-semibold">Request headers</div>' + nvTable(rq.headers, 'none') +
        (Array.isArray(rq.queryString) && rq.queryString.length
          ? '<div class="small fw-semibold mt-2">Query string</div>' + nvTable(rq.queryString, '') : '') +
        harCookies(rq.cookies, 'Request cookies') +
        '<div class="small fw-semibold mt-2">Timings</div>' + timings +
        '</div><div class="col-lg-6">' +
        '<div class="small fw-semibold">Response headers</div>' + nvTable(rs.headers, 'none') +
        harCookies(rs.cookies, 'Response cookies') +
        '<div class="small fw-semibold mt-2">Content</div>' +
        '<div class="small text-muted">' + esc(content.mimeType || 'no type') + ' · ' + esc(size(content.size)) +
        (content.comment ? ' · ' + esc(content.comment) : '') + (note ? ' · ' + esc(note) : '') + '</div>' +
        (text ? '<pre class="fw-pre small mt-1 mb-0"></pre>' : '<div class="small text-muted">No content text in this HAR entry.</div>') +
        '</div></div></div></div>';
      $('fw-tt-hardetail').innerHTML = h;
      // textContent, not innerHTML: a HAR body is somebody else's HTML.
      const pre = $('fw-tt-hardetail').querySelector('pre');
      if (pre) pre.textContent = text;
      $('fw-tt-hardetail').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    window.FWTxnTrace = {
      init: init,
      // Kept for links that still call it: the tracer is a page now.
      open: function (prefill) {
        window.location.href = '/txn-trace/' + (prefill ? '?vip=' + encodeURIComponent(prefill) : '');
      }
    };

    document.addEventListener('click', function (ev) {
      const t = ev.target.closest && ev.target.closest('[data-fw-txntrace-open]');
      if (!t) return;
      ev.preventDefault();
      window.FWTxnTrace.open(t.getAttribute('data-fw-txntrace-open') || '');
    });
  }
  window.FWTxnTrace.init();
})();
