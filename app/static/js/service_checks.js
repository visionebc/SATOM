/* Monitoring › Service checks (2026-11-17). Drives monitoring/checks.html.
   No inline handlers (CSP); every server value is escaped before it reaches
   innerHTML. Reads #sc-config for its URLs and the kind catalogue. */
(function () {
  'use strict';
  var cfgEl = document.getElementById('sc-config');
  if (!cfgEl) return;
  var CFG = JSON.parse(cfgEl.textContent);
  var BASE = CFG.base.replace(/\/$/, '');
  var KL = CFG.kindLabel, CERT = CFG.certKinds, WEB = CFG.webKinds;
  var checks = [];

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function csrf() { var m = document.querySelector('meta[name="csrf-token"]'); return m ? m.content : ''; }
  function post(url, body) {
    return fetch(url, { method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf(), Accept: 'application/json' },
      body: JSON.stringify(body || {}) })
      .then(function (r) { return r.json().catch(function () { return { ok: false, error: 'HTTP ' + r.status }; }); });
  }
  function ago(iso) {
    if (!iso) return 'never';
    var s = Math.round((Date.now() - Date.parse(iso)) / 1000);
    if (isNaN(s)) return '';
    if (s < 45) return 'just now';
    if (s < 3600) return Math.round(s / 60) + ' min ago';
    if (s < 86400) return Math.round(s / 3600) + ' h ago';
    return Math.round(s / 86400) + ' d ago';
  }
  var ST = { up: ['ok', 'check-circle-fill', 'Up'], degraded: ['stale', 'exclamation-triangle-fill', 'Degraded'],
    down: ['error', 'x-octagon-fill', 'Down'], error: ['error', 'bug-fill', 'Error'], unknown: ['none', 'hourglass', 'Not run yet'] };
  function pill(status) {
    var s = ST[status] || ST.unknown;
    return '<span class="obs-pill st-' + s[0] + '"><i class="bi bi-' + s[1] + '" aria-hidden="true"></i><span>' + s[2] + '</span></span>';
  }
  function target(c) {
    var t = c.target || {};
    if (t.url) return t.url;
    var h = (t.host || '') + (t.port ? ':' + t.port : '');
    if (c.kind === 'dns') h += ' · ' + (t.rtype || 'A') + ' ' + (t.name || '');
    if (c.kind === 'openvpn') h += ' · ' + (t.proto || 'udp');
    if (c.kind === 'ipsec') h += ' · IKEv' + (t.ike_version || 2) + (t.nat_t ? ' NAT-T' : '');
    return h;
  }
  function certCell(c) {
    var l = c.latest;
    if (!l || l.cert_days_left == null) return CERT.indexOf(c.kind) >= 0 ? '<span class="text-muted">—</span>' : '<span class="text-muted small">n/a</span>';
    var d = l.cert_days_left, cls = d < 0 ? 'text-danger' : (d <= c.cert_warn_days ? 'text-warning' : 'text-success');
    return '<span class="' + cls + '">' + (d < 0 ? 'expired' : d + ' d') + '</span>';
  }
  function actions(c) {
    var h = '<button type="button" class="btn btn-sm btn-outline-secondary" data-act="detail" data-id="' + c.id + '" title="Details"><i class="bi bi-card-list"></i></button>';
    if (!CFG.mayWrite) return h;
    return h + ' <button type="button" class="btn btn-sm btn-outline-secondary" data-act="run" data-id="' + c.id + '" title="Run now"><i class="bi bi-play-fill"></i></button>' +
      ' <button type="button" class="btn btn-sm btn-outline-secondary" data-act="edit" data-id="' + c.id + '" title="Edit"><i class="bi bi-pencil"></i></button>' +
      ' <button type="button" class="btn btn-sm btn-outline-secondary" data-act="muted" data-id="' + c.id + '" title="' + (c.muted ? 'Unmute alerts' : 'Mute alerts') + '"><i class="bi bi-bell' + (c.muted ? '-slash' : '') + '"></i></button>' +
      ' <button type="button" class="btn btn-sm btn-outline-secondary" data-act="enabled" data-id="' + c.id + '" title="' + (c.enabled ? 'Pause' : 'Resume') + '"><i class="bi bi-' + (c.enabled ? 'pause' : 'play') + '-circle"></i></button>' +
      ' <button type="button" class="btn btn-sm btn-outline-secondary" data-act="delete" data-id="' + c.id + '" title="Delete"><i class="bi bi-trash"></i></button>';
  }
  function shotUrl(c) { return BASE + '/' + c.id + '/screenshot?t=' + encodeURIComponent(c.last_shot_at || ''); }

  function webCard(c) {
    var l = c.latest || {};
    var img = c.has_shot ? '<img class="sc-shot" loading="lazy" alt="Screenshot of ' + esc(c.name) + '" src="' + esc(shotUrl(c)) + '">'
      : '<div class="sc-shot sc-shot-none"><i class="bi bi-camera" aria-hidden="true"></i><span>' + esc(CFG.shots ? 'No screenshot yet' : 'Screenshots are off on this node') + '</span></div>';
    return '<article class="fw-card sc-card st-' + esc(c.last_status) + (c.enabled ? '' : ' is-paused') + '" id="check-' + c.id + '">' +
      '<button type="button" class="sc-shot-btn" data-act="detail" data-id="' + c.id + '" aria-label="Details of ' + esc(c.name) + '">' + img + '</button>' +
      '<div class="sc-card-body"><div class="d-flex align-items-center gap-2"><b class="text-truncate">' + esc(c.name) + '</b><span class="ms-auto">' + pill(c.last_status) + '</span></div>' +
      '<div class="small text-muted text-truncate" title="' + esc(target(c)) + '">' + esc(KL[c.kind] || c.kind) + ' · ' + esc(target(c)) + '</div>' +
      '<div class="sc-facts small"><span>HTTP <b>' + esc((l.detail || {}).http_status || '—') + '</b></span><span>' + (l.latency_ms != null ? Math.round(l.latency_ms) + ' ms' : '— ms') + '</span><span>cert ' + certCell(c) + '</span><span>24 h ' + (c.uptime_24h != null ? c.uptime_24h + ' %' : '—') + '</span></div>' +
      '<div class="small sc-summary" title="' + esc(c.last_summary) + '">' + esc(c.last_summary || 'Not run yet') + '</div>' +
      '<div class="d-flex align-items-center gap-1 mt-2"><span class="small text-muted me-auto">' + esc(ago(c.last_checked_at)) + (c.muted ? ' · muted' : '') + (c.enabled ? '' : ' · paused') + '</span>' + actions(c) + '</div></div></article>';
  }
  function tableRows(list) {
    return '<div class="fw-card"><div class="table-responsive"><table class="table table-sm align-middle mb-0 fw-table"><thead><tr>' +
      '<th>Status</th><th>Name</th><th>Service</th><th>Target</th><th>Latency</th><th>Certificate</th><th>24 h</th><th>Last result</th><th>Checked</th><th></th></tr></thead><tbody>' +
      list.map(function (c) {
        var l = c.latest || {};
        return '<tr id="check-' + c.id + '" class="' + (c.enabled ? '' : 'sc-paused') + '"><td>' + pill(c.last_status) + '</td><td><b>' + esc(c.name) + '</b>' + (c.muted ? ' <i class="bi bi-bell-slash text-muted" title="alerts muted"></i>' : '') + '</td>' +
          '<td>' + esc(KL[c.kind] || c.kind) + '</td><td class="small"><code>' + esc(target(c)) + '</code></td>' +
          '<td>' + (l.latency_ms != null ? Math.round(l.latency_ms) + ' ms' : '—') + '</td><td>' + certCell(c) + '</td>' +
          '<td>' + (c.uptime_24h != null ? c.uptime_24h + ' %' : '—') + '</td>' +
          '<td class="small sc-summary-cell" title="' + esc(c.last_summary) + '">' + esc(c.last_summary || '—') + '</td>' +
          '<td class="small text-muted text-nowrap">' + esc(ago(c.last_checked_at)) + '</td><td class="text-nowrap text-end">' + actions(c) + '</td></tr>';
      }).join('') + '</tbody></table></div></div>';
  }
  function render() {
    var by = {};
    CFG.groups.forEach(function (g) { by[g[0]] = []; });
    checks.forEach(function (c) { CFG.groups.forEach(function (g) { if (g[2].indexOf(c.kind) >= 0) by[g[0]].push(c); }); });
    CFG.groups.forEach(function (g) {
      var box = document.querySelector('[data-group="' + g[0] + '"]'), list = by[g[0]];
      document.querySelector('[data-count="' + g[0] + '"]').textContent = list.length;
      if (!list.length) { box.innerHTML = '<div class="sc-empty text-muted small p-3">No ' + esc(g[1]) + ' checks yet' + (CFG.mayWrite ? ' — use “Add check”.' : '.') + '</div>'; return; }
      box.innerHTML = g[0] === 'web' ? list.map(webCard).join('') : tableRows(list);
    });
    var counts = { total: checks.length, up: 0, degraded: 0, down: 0, unknown: 0 };
    checks.forEach(function (c) { var s = c.last_status === 'error' ? 'down' : c.last_status; if (counts[s] != null) counts[s]++; });
    Object.keys(counts).forEach(function (k) { var el = document.querySelector('[data-kpi="' + k + '"]'); if (el) el.textContent = counts[k]; });
    document.getElementById('sc-updated').textContent = 'updated ' + new Date().toLocaleTimeString();
  }
  function load() {
    return fetch(CFG.data, { credentials: 'same-origin', headers: { Accept: 'application/json' } })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (d) { checks = d.checks || []; render(); })
      .catch(function (e) { document.querySelectorAll('[data-group]').forEach(function (b) { b.innerHTML = '<div class="fw-alert fw-alert-danger small">Could not load the checks: ' + esc(e.message) + '</div>'; }); });
  }
  function byId(id) { for (var i = 0; i < checks.length; i++) if (checks[i].id === id) return checks[i]; return null; }

  // ---------- detail ----------
  function certBlock(cert) {
    if (!cert) return '<p class="text-muted small mb-0">This protocol exposes no certificate, or none was read on the last run.</p>';
    if (cert.error && !cert.not_after) return '<p class="small text-warning mb-0">' + esc(cert.error) + '</p>';
    var rows = [['Subject', cert.subject], ['Issuer', cert.issuer], ['Valid from', cert.not_before], ['Valid until', cert.not_after],
      ['Days left', cert.days_left], ['Names (SAN)', (cert.sans || []).join(', ')], ['Chain trusted', cert.chain_ok == null ? 'not checked' : (cert.chain_ok ? 'yes' : 'no')],
      ['Name matches', cert.hostname_ok == null ? 'not checked' : (cert.hostname_ok ? 'yes' : 'no')], ['Self-signed', cert.self_signed ? 'yes' : 'no'], ['SHA-256', cert.sha256]];
    if (cert.error) rows.push(['Note', cert.error]);
    return '<table class="table table-sm small mb-0"><tbody>' + rows.map(function (r) { return '<tr><th class="text-muted fw-normal" style="width:150px">' + r[0] + '</th><td><code>' + esc(r[1]) + '</code></td></tr>'; }).join('') + '</tbody></table>';
  }
  function openDetail(id) {
    var c = byId(id); if (!c) return;
    var body = document.getElementById('scDetailBody');
    document.getElementById('scDetailTitle').textContent = c.name + ' — ' + (KL[c.kind] || c.kind);
    body.innerHTML = '<div class="obs-skel" style="height:220px"></div>';
    bootstrap.Modal.getOrCreateInstance(document.getElementById('scDetail')).show();
    fetch(BASE + '/' + id + '/history?hours=24', { credentials: 'same-origin' }).then(function (r) { return r.json(); }).then(function (d) {
      var res = d.results || [], last = res[0] || {};
      var hist = res.slice(0, 120).map(function (r) {
        return '<tr><td class="text-nowrap small">' + esc((r.at || '').replace('T', ' ').replace('Z', '')) + '</td><td>' + pill(r.status) + '</td><td>' + (r.latency_ms != null ? Math.round(r.latency_ms) + ' ms' : '—') + '</td><td class="small">' + esc(r.summary) + '</td></tr>';
      }).join('');
      var strip = res.slice(0, 96).reverse().map(function (r) { return '<span class="sc-tick st-' + esc(r.status) + '" title="' + esc(r.at + ' · ' + r.status) + '"></span>'; }).join('');
      body.innerHTML =
        '<div class="row g-3"><div class="col-lg-' + (WEB.indexOf(c.kind) >= 0 ? '7' : '12') + '">' +
        '<div class="d-flex align-items-center gap-2 mb-2">' + pill(c.last_status) + '<span class="small">' + esc(c.last_summary) + '</span></div>' +
        '<div class="small text-muted mb-2"><code>' + esc(target(c)) + '</code> · every ' + c.interval_min + ' min · uptime 24 h ' + (c.uptime_24h != null ? c.uptime_24h + ' %' : '—') + '</div>' +
        '<div class="sc-strip mb-3" aria-label="Last results, oldest first">' + strip + '</div>' +
        '<h6 class="text-uppercase small text-muted">Certificate</h6>' + certBlock(last.cert) +
        '<h6 class="text-uppercase small text-muted mt-3">Protocol facts (last run)</h6><pre class="sc-pre small">' + esc(JSON.stringify(last.detail || {}, null, 2)) + '</pre>' +
        '</div>' + (WEB.indexOf(c.kind) >= 0 ? '<div class="col-lg-5"><h6 class="text-uppercase small text-muted">Screenshot</h6>' +
          (c.has_shot ? '<a href="' + esc(shotUrl(c)) + '" target="_blank" rel="noopener"><img class="sc-shot-full" alt="Screenshot of ' + esc(c.name) + '" src="' + esc(shotUrl(c)) + '"></a><div class="small text-muted mt-1">' + esc(ago(c.last_shot_at)) + '</div>'
            : '<p class="small text-muted">' + (CFG.shots ? 'No screenshot yet.' : 'Screenshots are off on this node.') + '</p>') + '</div>' : '') +
        '</div><h6 class="text-uppercase small text-muted mt-3">Last 24 hours</h6><div class="table-responsive"><table class="table table-sm align-middle fw-table"><thead><tr><th>When (UTC)</th><th>Status</th><th>Latency</th><th>Result</th></tr></thead><tbody>' +
        (hist || '<tr><td colspan="4" class="text-muted small">No results yet.</td></tr>') + '</tbody></table></div>';
    }).catch(function (e) { body.innerHTML = '<div class="fw-alert fw-alert-danger small">' + esc(e.message) + '</div>'; });
  }

  // ---------- editor ----------
  var F = {
    url: ['URL', 'text', 'https://www.example.com/', 12], method: ['Method', ['GET', 'HEAD'], 'GET', 3],
    expect_status: ['Expected HTTP status', 'text', '200-399', 4], keyword: ['Must contain (optional)', 'text', '', 5],
    host: ['Host', 'text', '', 8], port: ['Port', 'number', '', 4], sni: ['SNI / name to check (optional)', 'text', '', 6],
    verify_tls: ['Require a trusted certificate', 'check', true, 6], expect_banner: ['Banner must match (regex, optional)', 'text', '', 12],
    name: ['Record name', 'text', '', 6], rtype: ['Type', ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'], 'A', 3], expect: ['Answer must contain (optional)', 'text', '', 3],
    starttls: ['STARTTLS', 'check', true, 6], vendor: ['Portal', ['fortinet', 'cisco', 'paloalto', 'pulse', 'generic'], 'fortinet', 4],
    proto: ['Transport', ['udp', 'tcp'], 'udp', 3], tls_auth_key: ['tls-auth static key (optional, secret)', 'secret', '', 12],
    key_direction: ['Key direction', [['', 'none'], ['1', '1 (client)'], ['0', '0']], '', 3], auth_digest: ['tls-auth digest', ['SHA1', 'SHA256', 'SHA512'], 'SHA1', 3],
    tls_crypt_key: ['tls-crypt key (optional, secret)', 'secret', '', 12],
    ike_version: ['IKE version', [['2', 'IKEv2'], ['1', 'IKEv1']], '2', 3], nat_t: ['NAT-T (UDP 4500)', 'check', false, 3],
    server_public_key: ['Server public key', 'text', '', 12], client_private_key: ['Monitoring peer private key (secret)', 'secret', '', 9],
    preshared_key: ['Preshared key (optional, secret)', 'secret', '', 12]
  };
  var FIELDS = {
    http: ['url', 'method', 'expect_status', 'keyword'], https: ['url', 'method', 'expect_status', 'keyword', 'verify_tls'],
    tls: ['host', 'port', 'sni', 'verify_tls'], tcp: ['host', 'port', 'expect_banner'], dns: ['host', 'port', 'name', 'rtype', 'expect'],
    ssh: ['host', 'port'], smtp: ['host', 'port', 'starttls', 'verify_tls'], sslvpn: ['host', 'port', 'vendor', 'verify_tls'],
    openvpn: ['host', 'port', 'proto', 'verify_tls', 'tls_auth_key', 'key_direction', 'auth_digest', 'tls_crypt_key'],
    ipsec: ['host', 'port', 'ike_version', 'nat_t'], wireguard: ['host', 'port', 'server_public_key', 'client_private_key', 'preshared_key']
  };
  var PORTS = { tls: 443, dns: 53, ssh: 22, smtp: 25, sslvpn: 443, openvpn: 1194, ipsec: 500, wireguard: 51820 };
  var HELP = {
    sslvpn: 'TLS handshake and certificate, then the vendor login portal must answer with its own page.',
    openvpn: 'A real OpenVPN reset handshake (and the server certificate through the control channel). A server with tls-auth or tls-crypt stays silent without its key.',
    ipsec: 'An IKE_SA_INIT the responder must answer — any IKE reply proves the daemon. IKE shows its certificate only inside the encrypted exchange; add a FortiGate to read the tunnel itself.',
    wireguard: 'A real Noise handshake. WireGuard answers ONLY keys it knows: add the monitoring peer\'s public key to the server. WireGuard has no certificate.',
    tcp: 'Without a banner pattern this only proves the port accepts a connection — prefer a protocol check when there is one.'
  };
  var editing = null;
  function fieldHtml(name, val, isEdit) {
    var f = F[name], id = 'scf-' + name, col = 'col-md-' + f[3];
    if (f[1] === 'check') return '<div class="' + col + ' d-flex align-items-end"><div class="form-check"><input class="form-check-input" type="checkbox" id="' + id + '" data-t="' + name + '"' + ((val == null ? f[2] : val) ? ' checked' : '') + '><label class="form-check-label small" for="' + id + '">' + f[0] + '</label></div></div>';
    if (Array.isArray(f[1])) {
      var cur = val == null ? f[2] : String(val);
      return '<div class="' + col + '"><label class="form-label" for="' + id + '">' + f[0] + '</label><select class="form-select form-select-sm" id="' + id + '" data-t="' + name + '">' +
        f[1].map(function (o) { var v = Array.isArray(o) ? o[0] : o, l = Array.isArray(o) ? o[1] : o; return '<option value="' + esc(v) + '"' + (String(v) === cur ? ' selected' : '') + '>' + esc(l) + '</option>'; }).join('') + '</select></div>';
    }
    if (f[1] === 'secret') {
      var kept = isEdit && editing && (editing.secret_fields || []).indexOf(name) >= 0;
      var extra = name === 'client_private_key' ? '<div class="col-md-3 d-flex align-items-end"><button type="button" class="btn btn-sm btn-outline-secondary w-100" id="sc-wg-gen"><i class="bi bi-key me-1"></i>Generate</button></div><div class="col-12 small text-muted" id="sc-wg-pub"></div>' : '';
      return '<div class="' + col + '"><label class="form-label" for="' + id + '">' + f[0] + '</label><textarea class="form-control form-control-sm font-monospace" rows="' + (name.indexOf('key') >= 0 && name !== 'client_private_key' && name !== 'preshared_key' ? 4 : 1) + '" id="' + id + '" data-t="' + name + '" autocomplete="off" spellcheck="false" placeholder="' + (kept ? 'stored — leave empty to keep it' : '') + '"></textarea></div>' + extra;
    }
    return '<div class="' + col + '"><label class="form-label" for="' + id + '">' + f[0] + '</label><input class="form-control form-control-sm" id="' + id + '" data-t="' + name + '" type="' + (f[1] === 'number' ? 'number' : 'text') + '" value="' + esc(val == null ? (name === 'port' ? '' : f[2]) : val) + '" placeholder="' + esc(name === 'port' ? (PORTS[document.getElementById('sc-kind').value] || '') : (f[1] === 'text' && !val ? f[2] : '')) + '"></div>';
  }
  function drawFields(isEdit) {
    var kind = document.getElementById('sc-kind').value, t = (isEdit && editing && editing.kind === kind) ? editing.target : {};
    var html = (FIELDS[kind] || []).map(function (n) { return fieldHtml(n, t[n], isEdit); }).join('');
    if (HELP[kind]) html += '<div class="col-12 small text-muted"><i class="bi bi-info-circle me-1"></i>' + esc(HELP[kind]) + '</div>';
    document.getElementById('sc-fields').innerHTML = html;
    document.querySelectorAll('[data-for-cert]').forEach(function (el) { el.hidden = CERT.indexOf(kind) < 0; });
    document.querySelectorAll('[data-for-web]').forEach(function (el) { el.hidden = WEB.indexOf(kind) < 0; });
    document.querySelectorAll('[data-for-ipsec]').forEach(function (el) { el.hidden = kind !== 'ipsec'; });
    var gen = document.getElementById('sc-wg-gen');
    if (gen) gen.addEventListener('click', function () {
      post(BASE + '/wireguard-keypair').then(function (d) {
        if (!d.ok) return;
        document.getElementById('scf-client_private_key').value = d.private_key;
        document.getElementById('sc-wg-pub').innerHTML = 'Add this peer to the server: public key <code>' + esc(d.public_key) + '</code> (AllowedIPs can be a single unused /32).';
      });
    });
  }
  function openEditor(c) {
    editing = c || null;
    var form = document.getElementById('scEditForm');
    form.reset();
    document.getElementById('scEditTitle').textContent = c ? 'Edit ' + c.name : 'Add check';
    form.elements.id.value = c ? c.id : '';
    form.elements.name.value = c ? c.name : '';
    document.getElementById('sc-kind').value = c ? c.kind : 'https';
    if (c) {
      form.elements.interval_min.value = c.interval_min; form.elements.timeout_s.value = c.timeout_s;
      form.elements.cert_warn_days.value = c.cert_warn_days; form.elements.screenshot_every_min.value = c.screenshot_every_min;
      form.elements.fgt_appliance_id.value = c.fgt_appliance_id || ''; form.elements.fgt_tunnel.value = c.fgt_tunnel || '';
    }
    drawFields(!!c);
    document.getElementById('sc-edit-error').hidden = true;
    bootstrap.Modal.getOrCreateInstance(document.getElementById('scEdit')).show();
  }
  function collect() {
    var form = document.getElementById('scEditForm'), t = {};
    document.querySelectorAll('#sc-fields [data-t]').forEach(function (el) {
      var n = el.getAttribute('data-t');
      if (el.type === 'checkbox') t[n] = el.checked;
      else if (el.value.trim() !== '') t[n] = F[n][1] === 'number' ? Number(el.value) : el.value.trim();
      else if (F[n][1] === 'secret') t[n] = CFG.secretPlaceholder;
    });
    return { name: form.elements.name.value, kind: document.getElementById('sc-kind').value, target: t,
      interval_min: form.elements.interval_min.value, timeout_s: form.elements.timeout_s.value,
      cert_warn_days: form.elements.cert_warn_days.value, screenshot_every_min: form.elements.screenshot_every_min.value,
      fgt_appliance_id: form.elements.fgt_appliance_id.value, fgt_tunnel: form.elements.fgt_tunnel.value, enabled: editing ? editing.enabled : true };
  }
  var formEl = document.getElementById('scEditForm');
  if (formEl) {
    document.getElementById('sc-kind').addEventListener('change', function () { drawFields(!!editing); });
    formEl.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var btn = document.getElementById('sc-save'), err = document.getElementById('sc-edit-error');
      btn.disabled = true; btn.querySelector('.sc-save-label').textContent = 'Running…';
      var id = formEl.elements.id.value;
      post(id ? BASE + '/' + id : BASE + '/', collect()).then(function (d) {
        btn.disabled = false; btn.querySelector('.sc-save-label').textContent = 'Save and run';
        if (!d.ok) { err.textContent = d.error || 'Not saved.'; err.hidden = false; return; }
        bootstrap.Modal.getOrCreateInstance(document.getElementById('scEdit')).hide();
        load();
      });
    });
  }
  var add = document.getElementById('sc-add');
  if (add) add.addEventListener('click', function () { openEditor(null); });
  document.getElementById('sc-refresh').addEventListener('click', load);

  document.addEventListener('click', function (ev) {
    var b = ev.target.closest('[data-act]'); if (!b) return;
    var id = Number(b.getAttribute('data-id')), act = b.getAttribute('data-act'), c = byId(id);
    if (act === 'detail') openDetail(id);
    else if (act === 'edit') openEditor(c);
    else if (act === 'run') { b.disabled = true; b.innerHTML = '<span class="spinner-border spinner-border-sm" aria-hidden="true"></span>'; post(BASE + '/' + id + '/run').then(load); }
    else if (act === 'muted' || act === 'enabled') post(BASE + '/' + id + '/toggle', { field: act }).then(load);
    else if (act === 'delete') { if (window.confirm('Delete the check "' + (c ? c.name : id) + '" and its history?')) post(BASE + '/' + id + '/delete').then(load); }
  });

  load();
  setInterval(function () { if (!document.hidden) load(); }, 60000);
  if (location.hash && /^#check-\d+$/.test(location.hash)) {
    setTimeout(function () { openDetail(Number(location.hash.slice(7))); }, 600);
  }
})();
