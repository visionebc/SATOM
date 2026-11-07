/* Web Server Manager (Linux ADOM). One client for every module page:
 *   - "Sign in as" (credential) and "Run as" (automatic / my account / root)
 *   - api(op, args): POST /webserver/<server>/api/<op>; a 401 "need" answer
 *     opens the authentication dialog and retries with what was typed. The
 *     typed secrets live in this page's memory only (and only if "remember
 *     in this tab" is ticked); SATOM uses them for that call and forgets them.
 *   - job(op, args): long operations (packages, scripts, certbot) run in the
 *     background with a progress bar.
 * Every decision -- may this user, this credential, as root, on this server
 * -- is made by the server (services/wsm.py); this file only asks.
 */
(function () {
  'use strict';
  var CFG = JSON.parse(document.getElementById('wsm-config').textContent);
  var CSRF = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
  var PAGE = CFG.page;
  var KEY = 'satom.wsm.' + CFG.slug;
  var tabSecrets = {};
  var $ = function (s, r) { return (r || document).querySelector(s); };

  // ---------- small DOM helpers --------------------------------------------
  function h(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]; }); }
  function el(tag, attrs, kids) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      var v = attrs[k];
      if (v == null || v === false) return;
      if (k === 'text') e.textContent = v;
      else if (k === 'html') e.innerHTML = v;
      else if (k.slice(0, 2) === 'on') e.addEventListener(k.slice(2), v);
      else if (k === 'cls') e.className = v;
      else e.setAttribute(k, v === true ? '' : v);
    });
    (kids || []).forEach(function (c) { if (c != null) e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return e;
  }
  function btn(label, icon, cls, onclick, title) {
    return el('button', { type: 'button', cls: 'btn btn-sm ' + (cls || 'btn-outline-secondary'), onclick: onclick, title: title },
      [icon ? el('i', { cls: 'bi ' + icon + (label ? ' me-1' : '') }) : null, label || null]);
  }
  function input(attrs) { return el('input', Object.assign({ cls: 'form-control form-control-sm' }, attrs)); }
  function select(opts, value, attrs) {
    var s = el('select', Object.assign({ cls: 'form-select form-select-sm' }, attrs || {}));
    opts.forEach(function (o) { var v = Array.isArray(o) ? o[0] : o, t = Array.isArray(o) ? o[1] : o; var op = el('option', { value: v, text: t }); if (String(v) === String(value)) op.selected = true; s.appendChild(op); });
    return s;
  }
  function field(label, control, help) {
    var id = control.id || ('f' + Math.random().toString(36).slice(2, 8)); control.id = id;
    return el('div', { cls: 'mb-2' }, [el('label', { cls: 'fw-form-label', for: id, text: label }), control, help ? el('div', { cls: 'text-muted wsm-small', text: help }) : null]);
  }
  function check(label, checked, attrs) {
    var id = 'c' + Math.random().toString(36).slice(2, 8);
    var i = el('input', Object.assign({ type: 'checkbox', cls: 'form-check-input', id: id }, attrs || {})); i.checked = !!checked;
    var w = el('div', { cls: 'form-check' }, [i, el('label', { cls: 'form-check-label', for: id, text: label })]);
    w.input = i; return w;
  }
  function badge(text, kind, title) { return el('span', { cls: 'wsm-badge ' + (kind || 'wsm-muted'), text: text, title: title }); }
  function card(title, icon, kids, cls) { return el('div', { cls: 'fw-card p-3 ' + (cls || '') }, [title ? el('div', { cls: 'wsm-card-title' }, [icon ? el('i', { cls: 'bi ' + icon }) : null, title]) : null].concat(kids || [])); }
  function pre(text, light) { return el('pre', { cls: 'wsm-pre' + (light ? ' light' : ''), text: text || '' }); }
  function size(n) { n = +n || 0; if (n < 1024) return n + ' B'; var u = ['KB', 'MB', 'GB', 'TB'], i = -1; do { n /= 1024; i++; } while (n >= 1024 && i < 3); return n.toFixed(n < 10 ? 1 : 0) + ' ' + u[i]; }
  function when(ts) { if (!ts) return ''; var d = new Date(ts * 1000); return d.toISOString().slice(0, 16).replace('T', ' '); }
  function flash(kind, text) {
    var box = $('#wsm-flash');
    var m = el('div', { cls: 'wsm-msg ' + kind }, [el('i', { cls: 'bi ' + (kind === 'ok' ? 'bi-check-circle' : kind === 'warn' ? 'bi-exclamation-triangle' : 'bi-x-octagon') }), el('div', { text: text }), el('button', { cls: 'x', type: 'button', 'aria-label': 'Close', onclick: function () { m.remove(); } }, [el('i', { cls: 'bi bi-x' })])]);
    box.prepend(m);
    if (kind === 'ok') setTimeout(function () { m.remove(); }, 6000);
    while (box.children.length > 4) box.lastChild.remove();
  }
  function table(cols, rows, opts) {
    opts = opts || {};
    var t = el('table', { cls: 'fw-table wsm-table' });
    t.appendChild(el('thead', {}, [el('tr', {}, cols.map(function (c) { return el('th', { text: c }); }))]));
    var tb = el('tbody'); t.appendChild(tb);
    if (!rows.length) tb.appendChild(el('tr', {}, [el('td', { colspan: cols.length, cls: 'text-muted p-3', text: opts.empty || 'Nothing here.' })]));
    rows.forEach(function (r) { tb.appendChild(el('tr', {}, r.map(function (c) { return c instanceof Node ? el('td', {}, [c]) : el('td', { text: c == null ? '' : String(c) }); }))); });
    return el('div', { cls: 'fw-table-wrapper' }, [t]);
  }
  function modal(id) { return bootstrap.Modal.getOrCreateInstance(document.getElementById(id)); }

  // ---------- confirm / dialog ----------------------------------------------
  function confirmBox(opts) {
    return new Promise(function (resolve) {
      $('#wsm-confirm-title').textContent = opts.title || 'Please confirm';
      var body = $('#wsm-confirm-body'); body.innerHTML = '';
      if (opts.node) body.appendChild(opts.node); else body.textContent = opts.text || '';
      var typed = $('#wsm-confirm-typed'), inp = $('#wsm-confirm-input');
      typed.classList.toggle('d-none', !opts.typed); inp.value = '';
      if (opts.typed) $('#wsm-confirm-typed-label').textContent = 'Type ' + opts.typed + ' to confirm';
      var ok = $('#wsm-confirm-ok');
      ok.className = 'btn ' + (opts.danger ? 'btn-danger' : 'btn-fw-primary');
      ok.textContent = opts.ok || 'Confirm';
      var done = false, m = modal('wsm-confirm-modal');
      ok.onclick = function () { if (opts.typed && inp.value.trim() !== opts.typed) { inp.classList.add('is-invalid'); return; } done = true; m.hide(); resolve(true); };
      document.getElementById('wsm-confirm-modal').addEventListener('hidden.bs.modal', function f() { this.removeEventListener('hidden.bs.modal', f); if (!done) resolve(false); });
      m.show();
    });
  }
  function dialog(title, body, buttons, large) {
    $('#wsm-dialog-title').textContent = title;
    var b = $('#wsm-dialog-body'); b.innerHTML = ''; b.appendChild(body);
    var f = $('#wsm-dialog-foot'); f.innerHTML = '';
    (buttons || []).forEach(function (x) { f.appendChild(x); });
    f.appendChild(el('button', { type: 'button', cls: 'btn btn-outline-secondary', 'data-bs-dismiss': 'modal', text: 'Close' }));
    $('#wsm-dialog .modal-dialog').className = 'modal-dialog ' + (large === false ? '' : 'modal-xl');
    var m = modal('wsm-dialog'); m.show(); return m;
  }

  // ---------- acting-as bar --------------------------------------------------
  var credSel = $('#wsm-cred'), runSel = $('#wsm-runas');
  function creds() { return CFG.credentials || []; }
  function currentCred() { var id = +credSel.value; return creds().filter(function (c) { return c.id === id; })[0]; }
  function fillCreds() {
    var saved = localStorage.getItem(KEY + '.cred');
    credSel.innerHTML = '';
    var usable = creds().filter(function (c) { return c.usable; });
    if (!usable.length) credSel.appendChild(el('option', { value: '', text: '— add a credential on the Overview —' }));
    usable.forEach(function (c) {
      var t = c.name + ' (' + c.ssh_user + (c.auth_type === 'agent' ? ', restricted agent' : '') + ')';
      credSel.appendChild(el('option', { value: c.id, text: t }));
    });
    if (saved && usable.some(function (c) { return String(c.id) === saved; })) credSel.value = saved;
    runSel.value = localStorage.getItem(KEY + '.runas') || 'auto';
    describeActAs();
  }
  function describeActAs() {
    var c = currentCred(), who = $('#wsm-who'); who.innerHTML = '';
    if (!c) { who.appendChild(badge('no credential', 'wsm-bad')); return; }
    var canRoot = c.escalation !== 'none' && CFG.perms.root;
    Array.prototype.forEach.call(runSel.options, function (o) { o.disabled = o.value !== 'self' && !canRoot; });
    if (!canRoot && runSel.value !== 'self') runSel.value = 'self';
    var r = runSel.value;
    if (r === 'root') who.append(badge('root', 'wsm-root'), ' every operation runs as root through sudo (as ' + c.ssh_user + ')');
    else if (r === 'auto') who.append(badge(c.ssh_user, 'wsm-info'), ' sudo only when the server refuses (' + (c.escalation === 'sudo_nopasswd' ? 'NOPASSWD rule' : c.sudo_password === 'same' && c.auth_type === 'password' ? 'with your password' : 'asks the sudo password') + ')');
    else who.append(badge(c.ssh_user, 'wsm-info'), canRoot ? ' never uses sudo' : ' this credential does not use sudo');
    if (!c.store_secret && c.auth_type !== 'agent') who.append(' ', badge('asks for its secret', 'wsm-warn'));
  }
  credSel.addEventListener('change', function () { localStorage.setItem(KEY + '.cred', credSel.value); describeActAs(); });
  runSel.addEventListener('change', function () { localStorage.setItem(KEY + '.runas', runSel.value); describeActAs(); });
  var adv = $('#wsm-advanced');
  adv.checked = localStorage.getItem('satom.wsm.advanced') === '1';
  document.body.classList.toggle('wsm-advanced', adv.checked);
  adv.addEventListener('change', function () { localStorage.setItem('satom.wsm.advanced', adv.checked ? '1' : '0'); document.body.classList.toggle('wsm-advanced', adv.checked); });

  // ---------- secrets dialog ---------------------------------------------------
  function askSecrets(need, why, cred) {
    return new Promise(function (resolve) {
      $('#wsm-secret-why').textContent = why || 'This operation needs your credentials.';
      var isKey = cred && cred.auth_type === 'key';
      ['secret', 'passphrase', 'sudo'].forEach(function (f) { $('#wsm-secret-f-' + f).classList.toggle('d-none', need.indexOf(f) < 0); });
      $('#wsm-secret-label').textContent = isKey ? 'Private key' : 'Password of ' + (cred ? cred.ssh_user : 'the account');
      $('#wsm-secret-secret').classList.toggle('d-none', isKey);
      $('#wsm-secret-key').classList.toggle('d-none', !isKey);
      ['secret', 'key', 'passphrase', 'sudo'].forEach(function (f) { $('#wsm-secret-' + f).value = ''; });
      var done = false, m = modal('wsm-secret-modal');
      $('#wsm-secret-ok').onclick = function () {
        done = true; m.hide();
        resolve({ secret: isKey ? $('#wsm-secret-key').value : $('#wsm-secret-secret').value,
          passphrase: $('#wsm-secret-passphrase').value, sudo: $('#wsm-secret-sudo').value,
          keep: $('#wsm-secret-keep').checked });
      };
      document.getElementById('wsm-secret-modal').addEventListener('hidden.bs.modal', function f() { this.removeEventListener('hidden.bs.modal', f); if (!done) resolve(null); });
      m.show();
      setTimeout(function () { var x = need[0] === 'sudo' ? $('#wsm-secret-sudo') : isKey ? $('#wsm-secret-key') : $('#wsm-secret-secret'); x.focus(); }, 300);
    });
  }

  // ---------- API -----------------------------------------------------------------
  function post(url, body) {
    return fetch(url, { method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF, 'X-CSRF-Token': CSRF, 'Accept': 'application/json', 'X-ADOM': 'linux' },
      body: JSON.stringify(body || {}) }).then(function (r) {
      return r.json().catch(function () { return { ok: false, error: 'HTTP ' + r.status }; }).then(function (d) { d._status = r.status; return d; });
    });
  }
  function trace(op, args, d) {
    var safe = JSON.parse(JSON.stringify(args || {}));
    ['content', 'content_b64', 'private_key', 'password', 'certificate'].forEach(function (k) { if (safe[k]) safe[k] = '<' + String(safe[k]).length + ' chars>'; });
    var res = d.result ? JSON.stringify(d.result, null, 1) : '';
    $('#wsm-trace-body').textContent = 'operation: ' + op + '\nrun as: ' + runSel.value + ' -> ' + (d.who ? d.who.user + ' (uid ' + d.who.uid + ')' : '?') + (d.sudo ? ' via sudo' : '') +
      '\narguments: ' + JSON.stringify(safe, null, 1) + '\n' + (d.ok ? 'result (' + d.ms + ' ms): ' + (res.length > 6000 ? res.slice(0, 6000) + '\n…' : res) : 'error: ' + (d.error || ''));
  }
  function call(url, op, args, opts) {
    opts = opts || {};
    var c = currentCred();
    if (!c) return Promise.reject(new Error('Pick a credential first (Overview > Credentials).'));
    var body = Object.assign({ cred: c.id, run_as: opts.runAs || runSel.value, args: args || {}, secrets: tabSecrets[c.id] || {} }, opts.extra || {});
    return post(url, body).then(function (d) {
      if (d._status === 401 && d.need) {
        return askSecrets(d.need, d.why, c).then(function (s) {
          if (!s) throw new Error('Cancelled.');
          var merged = Object.assign({}, tabSecrets[c.id] || {});
          ['secret', 'passphrase', 'sudo'].forEach(function (k) { if (s[k]) merged[k] = s[k]; });
          if (s.keep) tabSecrets[c.id] = merged;
          return post(url, Object.assign(body, { secrets: merged })).then(function (d2) {
            if (d2._status === 401) { delete tabSecrets[c.id]; throw new Error(d2.why || 'Still not authenticated.'); }
            return d2;
          });
        });
      }
      return d;
    }).then(function (d) {
      if (op) trace(op, args, d);
      if (!d.ok) {
        var e = new Error(d.error || ('HTTP ' + d._status)); e.data = d;
        if (d.code === 'sudo_password') delete (tabSecrets[c.id] || {}).sudo;
        if (d.code === 'auth') delete tabSecrets[c.id];
        throw e;
      }
      if (d.sudo) noteSudo();
      return d;
    });
  }
  function noteSudo() { var w = $('#wsm-who'); if (w && !w.querySelector('.wsm-sudo-used')) { var b = badge('last operation used sudo', 'wsm-root'); b.classList.add('wsm-sudo-used'); w.append(' ', b); } }
  function api(op, args, opts) { return call(CFG.api.replace('OP', op), op, args, opts).then(function (d) { return d.result; }); }
  function apiFull(op, args, opts) { return call(CFG.api.replace('OP', op), op, args, opts); }
  function job(op, args, opts) {
    opts = opts || {};
    var bar = opts.progress;
    return call(CFG.job.replace('OP', op), op, args, { extra: { title: opts.title || op } }).then(function (d) {
      return new Promise(function (resolve, reject) {
        function poll() {
          fetch(CFG.jobs.replace('JOB', d.job_id), { credentials: 'same-origin', headers: { Accept: 'application/json' } })
            .then(function (r) { return r.json(); }).then(function (j) {
              if (bar) { bar.querySelector('div').style.width = (j.percent || 10) + '%'; if (bar.nextSibling) bar.nextSibling.textContent = j.message || ''; }
              if (j.status === 'success') { if (bar) bar.querySelector('div').style.width = '100%'; trace(op, args, Object.assign({ ok: true }, j.result || {})); resolve(j.result || {}); }
              else if (j.status === 'error' || j.status === 'cancelled') reject(new Error(j.error || j.status));
              else setTimeout(poll, 1500);
            }).catch(function () { setTimeout(poll, 3000); });
        }
        poll();
      });
    });
  }
  function fail(e) { flash('err', e && e.message ? e.message : String(e)); }
  function progressBar() { var w = el('div', { cls: 'mb-2' }); var b = el('div', { cls: 'wsm-progress' }, [el('div')]); w.append(b, el('div', { cls: 'text-muted wsm-small' })); w.bar = b; return w; }
  function root() { return $('#wsm-page'); }
  function setPage(nodes) { var r = root(); r.innerHTML = ''; nodes.forEach(function (n) { if (n) r.appendChild(n); }); }
  function loading(text) { return el('div', { cls: 'text-muted p-3' }, [el('span', { cls: 'spinner-border spinner-border-sm me-2' }), text || 'Loading…']); }
  function download(name, data, b64, type) {
    var blob;
    if (b64) { var bin = atob(data), arr = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i); blob = new Blob([arr], { type: type || 'application/octet-stream' }); }
    else blob = new Blob([data], { type: type || 'text/plain' });
    var a = el('a', { href: URL.createObjectURL(blob), download: name }); document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }
  function needWrites() { if (!CFG.allow_writes) { flash('warn', 'This server is read-only in SATOM: turn on Allow changes on the Overview.'); return false; } return true; }

  // ======================================================================
  //  OVERVIEW: identity check + credentials
  // ======================================================================
  function pageHome() {
    var list = $('#wsm-creds');
    function draw() {
      list.innerHTML = '';
      var rows = creds().map(function (c) {
        var st = { active: 'wsm-ok', expired: 'wsm-bad', revoked: 'wsm-bad', disabled: 'wsm-muted' }[c.state];
        var acts = el('div', { cls: 'd-flex gap-1 flex-nowrap' });
        if (c.manageable) {
          if (c.auth_type !== 'agent' && c.state !== 'revoked') acts.appendChild(btn('', 'bi-pencil', null, function () { credForm(c); }, 'Edit'));
          if (c.state === 'active') acts.appendChild(btn('', 'bi-pause-circle', null, function () { credStatus(c, 'disabled'); }, 'Disable'));
          else if (c.state !== 'revoked') acts.appendChild(btn('', 'bi-play-circle', null, function () { credStatus(c, 'active'); }, 'Enable'));
          if (c.state !== 'revoked' && c.auth_type !== 'agent') acts.appendChild(btn('', 'bi-x-octagon', 'btn-outline-danger', function () { credStatus(c, 'revoked'); }, 'Revoke now'));
          acts.appendChild(btn('', 'bi-trash', 'btn-outline-danger', function () { credStatus(c, null, true); }, 'Delete'));
        }
        if (c.public_key) acts.appendChild(btn('', 'bi-clipboard', null, function () { dialog('Public key of ' + c.name, el('div', {}, [el('p', { text: 'Add this line to ~' + c.ssh_user + '/.ssh/authorized_keys on the server:' }), pre(c.public_key, true)]), [], false); }, 'Public key'));
        var how = c.auth_type === 'agent' ? 'satom-webctl key (vhosts and certificates only)' : (c.auth_type === 'key' ? 'SSH key' : 'password') + (c.store_secret ? ', kept by SATOM' : ', asked every time');
        var esc = c.escalation === 'none' ? 'no sudo' : c.escalation === 'sudo_nopasswd' ? 'sudo (NOPASSWD rule)' : 'sudo with ' + (c.sudo_password === 'same' && c.auth_type === 'password' ? 'the same password' : 'a password asked each time');
        return [el('div', {}, [el('strong', { text: c.name }), c.shared ? badge('shared', 'wsm-info') : badge('mine', 'wsm-muted'), el('div', { cls: 'text-muted wsm-small', text: c.description || '' })]),
          c.ssh_user, el('div', { cls: 'wsm-small' }, [how, el('br'), esc + ' · run as ' + c.run_as]),
          el('div', {}, [badge(c.state, st), c.expires_at ? el('div', { cls: 'text-muted wsm-small', text: 'expires ' + c.expires_at }) : null]),
          c.last_used_at || '—', acts];
      });
      list.appendChild(table(['Name', 'SSH user', 'How', 'State', 'Last used', ''], rows, { empty: 'No credential yet: add your SSH account.' }));
    }
    function credStatus(c, status, del) {
      var txt = del ? 'Delete credential ' + c.name + '? Scheduled jobs using it will wait for authentication.' :
        status === 'revoked' ? 'Revoke ' + c.name + ' now? Its stored secret is erased at once and every scheduled job using it stops. This cannot be undone (add a new credential instead).' :
          (status === 'active' ? 'Enable ' : 'Disable ') + c.name + '?';
      confirmBox({ text: txt, danger: del || status === 'revoked', typed: status === 'revoked' ? c.name : null }).then(function (ok) {
        if (!ok) return;
        post(CFG.base + 'credentials/' + c.id + '/status', del ? { delete: true } : { status: status }).then(function (d) {
          if (!d.ok) return fail(new Error(d.error)); CFG.credentials = d.credentials; draw(); fillCreds(); flash('ok', 'Saved.');
        });
      });
    }
    function credForm(c) {
      c = c || { auth_type: 'password', escalation: 'sudo', sudo_password: 'same', run_as: 'auto', store_secret: true, modules: [] };
      var f = {};
      f.name = input({ value: c.name || '', maxlength: 64, placeholder: 'eric on webserver01' });
      f.user = input({ value: c.ssh_user || '', maxlength: 32, placeholder: 'eric' });
      f.auth = select([['password', 'Password'], ['key', 'SSH private key']], c.auth_type);
      f.secret = input({ type: 'password', autocomplete: 'new-password', placeholder: c.id && c.has_secret ? '(unchanged — type to replace)' : '' });
      f.key = el('textarea', { cls: 'form-control form-control-sm wsm-mono', rows: 5, placeholder: c.id && c.has_secret ? '(unchanged — paste to replace)' : '-----BEGIN OPENSSH PRIVATE KEY-----' });
      f.gen = check('Generate a new key pair in SATOM (you add the public key to the server)', false);
      f.pass = input({ type: 'password', autocomplete: 'new-password', placeholder: 'only if the key has one' });
      f.store = check('SATOM keeps the secret (needed for scheduled jobs); untick to be asked at every operation', c.store_secret);
      f.esc = select([['none', 'Never use sudo'], ['sudo', 'sudo with a password'], ['sudo_nopasswd', 'sudo without password (a NOPASSWD rule exists on the server)']], c.escalation);
      f.sudopw = select([['same', 'the same password as the SSH account'], ['ask', 'ask me every time']], c.sudo_password);
      f.runas = select([['auto', 'Automatic: my account, sudo when refused'], ['self', 'Always my account'], ['root', 'Always root (sudo)']], c.run_as);
      f.shared = check('Shared service credential (other operators of this server may use it)', c.shared, CFG.perms.credentials ? {} : { disabled: true });
      f.exp = input({ type: 'date', value: c.expires_at || '' });
      f.desc = input({ value: c.description || '', maxlength: 300 });
      var modsBox = el('div', { cls: 'd-flex flex-wrap gap-2' });
      var MODS = ['files', 'sites', 'certs', 'security', 'scripts', 'cron', 'packages', 'services', 'logs', 'users', 'ssh'];
      var modChecks = MODS.map(function (m) { var x = check(m, c.modules.indexOf(m) >= 0); modsBox.appendChild(x); return [m, x.input]; });
      var secretWrap = el('div'), keyWrap = el('div');
      secretWrap.appendChild(field('Password', f.secret));
      keyWrap.append(field('Private key (OpenSSH or PEM)', f.key), f.gen, field('Key passphrase', f.pass));
      function sync() {
        var key = f.auth.value === 'key';
        secretWrap.classList.toggle('d-none', key || !f.store.input.checked);
        keyWrap.classList.toggle('d-none', !key || !f.store.input.checked);
        f.sudopw.parentNode.classList.toggle('d-none', f.esc.value !== 'sudo' || key);
        f.runas.disabled = f.esc.value === 'none'; if (f.esc.value === 'none') f.runas.value = 'self';
      }
      [f.auth, f.esc, f.store.input].forEach(function (x) { x.addEventListener('change', sync); });
      var body = el('div', {}, [
        el('div', { cls: 'row g-2' }, [el('div', { cls: 'col-md-6' }, [field('Name', f.name)]), el('div', { cls: 'col-md-6' }, [field('SSH user on the server', f.user)])]),
        el('div', { cls: 'row g-2' }, [el('div', { cls: 'col-md-6' }, [field('Sign in with', f.auth)]), el('div', { cls: 'col-md-6 pt-4' }, [f.store])]),
        secretWrap, keyWrap,
        el('hr'),
        el('div', { cls: 'row g-2' }, [el('div', { cls: 'col-md-6' }, [field('When the account is not allowed', f.esc, 'SATOM never edits sudoers: it uses what the server already allows.')]), el('div', { cls: 'col-md-6' }, [field('sudo asks for', f.sudopw)])]),
        field('Run as', f.runas),
        el('hr'),
        f.shared, field('Expires on (optional)', f.exp), field('Description', f.desc),
        el('div', { cls: 'fw-form-label' }, ['Only for these modules (none ticked = all)']), modsBox
      ]);
      sync();
      var save = el('button', { type: 'button', cls: 'btn btn-fw-primary', text: 'Save', onclick: function () {
        var data = { name: f.name.value, ssh_user: f.user.value, auth_type: f.auth.value, escalation: f.esc.value,
          sudo_password: f.sudopw.value, run_as: f.runas.value, store_secret: f.store.input.checked ? '1' : '',
          shared: f.shared.input.checked ? '1' : '', expires_at: f.exp.value, description: f.desc.value,
          modules: modChecks.filter(function (m) { return m[1].checked; }).map(function (m) { return m[0]; }) };
        if (f.auth.value === 'key') { data.secret = f.key.value; data.passphrase = f.pass.value; data.generate_key = f.gen.input.checked ? '1' : ''; }
        else data.secret = f.secret.value;
        post(CFG.base + 'credentials' + (c.id ? '/' + c.id : ''), data).then(function (d) {
          if (!d.ok) return fail(new Error(d.error));
          CFG.credentials = d.credentials; modal('wsm-dialog').hide(); draw(); fillCreds();
          if (!c.id) { credSel.value = d.id; localStorage.setItem(KEY + '.cred', d.id); describeActAs(); }
          flash('ok', 'Credential saved.' + (d.public_key ? ' Add its public key to the server (key icon in the list).' : ''));
          if (d.public_key && data.generate_key) dialog('Public key', el('div', {}, [el('p', { text: 'Add this line to ~' + data.ssh_user + '/.ssh/authorized_keys on the server, then press Check access:' }), pre(d.public_key, true)]), [], false);
        });
      } });
      dialog(c.id ? 'Edit credential' : 'Add credential', body, [save], false);
    }
    $('#wsm-cred-new').addEventListener('click', function () { credForm(null); });
    $('#wsm-check').addEventListener('click', function () {
      var c = currentCred(), box = $('#wsm-identity');
      if (!c) return fail(new Error('Pick a credential first.'));
      box.innerHTML = ''; box.appendChild(loading('Signing in to ' + CFG.host + ' as ' + c.ssh_user + '…'));
      call(CFG.base + 'credentials/' + c.id + '/check', 'whoami', {}).then(function (d) {
        var s = d.self || {}, r = d.root || {};
        var kv = el('div', { cls: 'wsm-kv' });
        function row(k, v) { kv.append(el('div', { text: k }), v instanceof Node ? v : el('div', { text: v })); }
        row('Signed in as', el('div', {}, [badge(s.user + ' (uid ' + s.uid + ')', 'wsm-info')]));
        row('Groups', (s.groups || []).join(', '));
        row('Can become root', r.ok ? el('div', {}, [badge('yes, through sudo', 'wsm-root')]) : el('div', {}, [badge('no', 'wsm-muted'), ' ', r.error || r.why || '']));
        row('Server', s.hostname + ' — ' + (s.os || {}).name);
        row('Package manager', s.pkg_manager || '—');
        row('Web servers', Object.keys(s.web || {}).join(', ') || 'none found');
        row('PHP', ((s.php || {}).cli || '—') + ((s.php || {}).fpm || []).map(function (f) { return ' · FPM ' + f.version; }).join(''));
        row('Firewall', s.firewall || 'none');
        row('certbot', s.certbot ? 'installed' : 'not installed');
        row('Helper', 'satom-wsm ' + s.helper + ' on Python ' + s.python);
        if (s.sudo && s.sudo.rules) { var adv = el('div', { cls: 'wsm-advanced-only' }, [pre(s.sudo.rules, true)]); row('sudo rules', adv); }
        box.innerHTML = ''; box.appendChild(kv);
      }).catch(function (e) { box.innerHTML = ''; box.appendChild(el('div', { cls: 'wsm-msg err', text: e.message })); });
    });
    draw();
  }

  // ======================================================================
  //  FILE MANAGER
  // ======================================================================
  function pageFiles() {
    var state = { path: localStorage.getItem(KEY + '.path') || '/var/www', hidden: false, sel: {} };
    // A site-scoped profile: start in (and stay under) the sites' roots.
    if (CFG.jail && CFG.jail.length && !CFG.jail.some(function (r) {
      return state.path === r || state.path.indexOf(r + '/') === 0; })) { state.path = CFG.jail[0]; }
    var pathIn = input({ cls: 'form-control form-control-sm wsm-path wsm-mono', value: state.path });
    var hiddenBox = check('Show hidden files', false);
    var listBox = el('div'), info = el('div', { cls: 'text-muted wsm-small mb-1' });
    var drop = el('div', { cls: 'wsm-drop mb-2', html: '<i class="bi bi-cloud-upload"></i> Drop files here to upload into this folder, or <a href="#" class="wsm-up">choose files</a> (up to 8 MB each)' });
    var fileIn = el('input', { type: 'file', multiple: true, cls: 'd-none' });
    function go(p) { state.path = p; pathIn.value = p; localStorage.setItem(KEY + '.path', p); load(); }
    function selected() { return Object.keys(state.sel).filter(function (k) { return state.sel[k]; }); }
    function load() {
      listBox.innerHTML = ''; listBox.appendChild(loading());
      state.sel = {};
      api('fs.list', { path: state.path, hidden: hiddenBox.input.checked }).then(function (r) {
        info.textContent = r.entries.length + ' item(s)' + (r.skipped ? ', ' + r.skipped + ' skipped (unreadable or unsafe names)' : '') + (r.writable ? '' : ' · this folder is read-only for this account');
        var rows = [];
        if (r.parent) rows.push(['', el('span', { cls: 'wsm-name-link', text: '..', onclick: function () { go(r.parent); } }), '', '', '', '', '']);
        r.entries.forEach(function (e) {
          var full = (r.path === '/' ? '' : r.path) + '/' + e.name;
          var cb = el('input', { type: 'checkbox', cls: 'form-check-input', onchange: function () { state.sel[full] = cb.checked; } });
          var isDir = e.type === 'dir' || e.target_dir;
          var icon = el('i', { cls: 'bi ' + (isDir ? 'bi-folder-fill' : e.type === 'link' ? 'bi-link-45deg' : 'bi-file-earmark') });
          var name = el('span', { cls: 'wsm-name-link', text: e.name + (e.type === 'link' ? ' → ' + (e.target || '') : ''), onclick: function () { isDir ? go(full) : openFile(full); } });
          var acts = el('div', { cls: 'd-flex gap-1' }, [
            !isDir ? btn('', 'bi-pencil-square', null, function () { openFile(full); }, 'Open / edit') : null,
            !isDir ? btn('', 'bi-download', null, function () { dl(full, e.name); }, 'Download') : null,
            btn('', 'bi-input-cursor-text', null, function () { rename(full); }, 'Rename / move'),
            btn('', 'bi-shield-lock', null, function () { perms([full], e); }, 'Permissions and owner'),
            /\.(zip|tar|tgz|gz|tar\.gz|tar\.bz2|tar\.xz)$/i.test(e.name) ? btn('', 'bi-file-zip', null, function () { extract(full); }, 'Extract here') : null,
            btn('', 'bi-trash', 'btn-outline-danger', function () { del([full]); }, 'Delete')]);
          rows.push([cb, el('span', {}, [icon, ' ', name]), isDir ? '' : size(e.size), el('span', { cls: 'wsm-mono', text: e.mode }), e.owner + ':' + e.group, when(e.mtime), acts]);
        });
        listBox.innerHTML = ''; listBox.appendChild(table(['', 'Name', 'Size', 'Mode', 'Owner', 'Modified', ''], rows, { empty: 'Empty folder.' }));
      }).catch(function (e) { listBox.innerHTML = ''; listBox.appendChild(el('div', { cls: 'wsm-msg err', text: e.message })); });
    }
    function openFile(path) {
      api('fs.read', { path: path, text: true }).then(function (r) {
        var body = el('div');
        var lang = WsmEditor.langOf(path);
        var langSel = select(WsmEditor.langs, lang);
        var host = el('div');
        if (r.binary) {
          if (/\.(png|jpe?g|gif|webp|svg|ico)$/i.test(path)) body.appendChild(el('img', { src: 'data:image/' + (path.split('.').pop().replace('jpg', 'jpeg').replace('svg', 'svg+xml')) + ';base64,' + r.content_b64, style: 'max-width:100%;max-height:480px;' }));
          else body.appendChild(el('p', { text: 'Binary file (' + size(r.size) + '): download it to open it.' }));
          return dialog(path, body, [btn('Download', 'bi-download', 'btn-fw-primary', function () { download(path.split('/').pop(), r.content_b64, true); })]);
        }
        var bar = el('div', { cls: 'wsm-toolbar' }, [el('span', { cls: 'wsm-small text-muted', text: size(r.size) + ' · mode ' + r.mode }), langSel]);
        var preview = /\.(html?|svg)$/i.test(path) ? btn('Preview', 'bi-eye', null, function () {
          var fr = el('iframe', { cls: 'wsm-preview', sandbox: '' }); fr.srcdoc = ed.value();
          dialog('Preview (scripts disabled): ' + path, fr, [], true);
        }) : null;
        var hist = btn('History', 'bi-clock-history', null, function () { history(path); });
        bar.append(preview || '', hist);
        body.append(bar, host);
        var ed = WsmEditor.create(host, { text: r.content, lang: lang, onSave: function () { save.click(); } });
        langSel.addEventListener('change', function () { ed.setLang(langSel.value); });
        var save = btn('Save', 'bi-save', 'btn-fw-primary', function () {
          if (!needWrites()) return;
          api('fs.write', { path: path, content: ed.value(), base_sha256: r.sha256 }).then(function (w) {
            r.sha256 = w.sha256; flash('ok', 'Saved ' + path + (w.history ? ' (previous version kept in History)' : ''));
          }).catch(fail);
        });
        dialog(path, body, [save]);
        setTimeout(function () { ed.focus(); }, 300);
      }).catch(fail);
    }
    function history(path) {
      api('fs.history', { path: path }).then(function (r) {
        var rows = r.versions.map(function (v) {
          return [v.version, size(v.size), el('div', { cls: 'd-flex gap-1' }, [
            btn('View', 'bi-eye', null, function () { api('fs.version', { path: path, version: v.version }).then(function (x) { dialog(path + ' @ ' + v.version, pre(x.content || '(binary)', true), [], true); }).catch(fail); }),
            btn('Restore', 'bi-arrow-counterclockwise', 'btn-outline-danger', function () { confirmBox({ text: 'Restore ' + path + ' to ' + v.version + '? The current content is kept as a new version.' }).then(function (ok) { if (ok) api('fs.restore', { path: path, version: v.version }).then(function () { flash('ok', 'Restored.'); modal('wsm-dialog').hide(); }).catch(fail); }); })])];
        });
        dialog('History of ' + path, el('div', {}, [el('p', { cls: 'wsm-small text-muted', text: 'SATOM keeps the last 25 versions of a file it overwrites, on the server, readable only by the account that saved them.' }), table(['Version (UTC)', 'Size', ''], rows, { empty: 'No saved versions.' })]), [], true);
      }).catch(fail);
    }
    function dl(path, name) { api('fs.read', { path: path, text: false }).then(function (r) { download(name, r.content_b64, true); }).catch(fail); }
    function rename(path) {
      var to = input({ value: path, cls: 'form-control form-control-sm wsm-mono' });
      var copy = check('Copy instead of moving', false);
      dialog('Rename, move or copy', el('div', {}, [field('New path', to), copy]), [btn('Apply', 'bi-check', 'btn-fw-primary', function () {
        if (!needWrites()) return;
        api(copy.input.checked ? 'fs.copy' : 'fs.move', { path: path, to: to.value }).then(function () { modal('wsm-dialog').hide(); flash('ok', 'Done.'); load(); }).catch(fail);
      })], false);
    }
    function perms(paths, e) {
      var mode = input({ value: e ? e.mode.slice(-3) : '644', cls: 'form-control form-control-sm wsm-mono', maxlength: 4 });
      var owner = input({ value: e ? e.owner : '' }), group = input({ value: e ? e.group : '' });
      var rec = check('Apply to everything inside (folders get the folder mode)', false);
      var dmode = input({ value: '755', cls: 'form-control form-control-sm wsm-mono', maxlength: 4 });
      var grid = el('div', { cls: 'row g-2' });
      [['r', 'Read'], ['w', 'Write'], ['x', 'Run / enter']].forEach(function () {});
      dialog('Permissions: ' + paths.join(', '), el('div', {}, [
        el('div', { cls: 'row g-2' }, [el('div', { cls: 'col-4' }, [field('Mode (e.g. 644, 755)', mode)]), el('div', { cls: 'col-4' }, [field('Owner', owner)]), el('div', { cls: 'col-4' }, [field('Group', group)])]),
        el('p', { cls: 'wsm-small text-muted', text: '644 = owner reads and writes, everyone reads. 755 = also runnable / enterable. 600 = only the owner. Changing the owner needs administrator rights.' }),
        rec, field('Mode for folders when applying inside', dmode), grid]), [btn('Apply', 'bi-check', 'btn-fw-primary', function () {
        if (!needWrites()) return;
        var p = api('fs.chmod', { paths: paths, mode: mode.value, recursive: rec.input.checked, dir_mode: rec.input.checked ? dmode.value : '' });
        if (e && (owner.value !== e.owner || group.value !== e.group)) p = p.then(function () { return api('fs.chown', { paths: paths, owner: owner.value, group: group.value, recursive: rec.input.checked }); });
        p.then(function () { modal('wsm-dialog').hide(); flash('ok', 'Permissions changed.'); load(); }).catch(fail);
      })], false);
    }
    function del(paths) {
      confirmBox({ title: 'Delete', text: 'Delete ' + paths.length + ' item(s)?\n' + paths.join('\n') + '\nItems up to 64 MB in total are kept in a backup on the server first.', danger: true, ok: 'Delete' }).then(function (ok) {
        if (!ok || !needWrites()) return;
        api('fs.delete', { paths: paths, recursive: true }).then(function (r) { flash('ok', 'Deleted.' + (r.backup ? ' Backup: ' + r.backup_dir + '/' + r.backup : ' No backup (too large).')); load(); }).catch(fail);
      });
    }
    function extract(path) {
      var dest = input({ value: state.path, cls: 'form-control form-control-sm wsm-mono' });
      dialog('Extract ' + path, field('Into folder', dest), [btn('Extract', 'bi-file-zip', 'btn-fw-primary', function () {
        if (!needWrites()) return;
        job('fs.extract', { path: path, dest: dest.value }, { title: 'Extract ' + path }).then(function (r) { modal('wsm-dialog').hide(); flash('ok', 'Extracted ' + r.result.files + ' file(s).'); load(); }).catch(fail);
      })], false);
    }
    function upload(files) {
      if (!needWrites()) return;
      Array.prototype.forEach.call(files, function (f) {
        if (f.size > 8 * 1024 * 1024) return flash('err', f.name + ' is larger than 8 MB.');
        var rd = new FileReader();
        rd.onload = function () {
          var b64 = String(rd.result).split(',')[1] || '';
          api('fs.write', { path: (state.path === '/' ? '' : state.path) + '/' + f.name, content_b64: b64 }).then(function () { flash('ok', 'Uploaded ' + f.name); load(); }).catch(fail);
        };
        rd.readAsDataURL(f);
      });
    }
    drop.addEventListener('dragover', function (e) { e.preventDefault(); drop.classList.add('over'); });
    drop.addEventListener('dragleave', function () { drop.classList.remove('over'); });
    drop.addEventListener('drop', function (e) { e.preventDefault(); drop.classList.remove('over'); upload(e.dataTransfer.files); });
    drop.querySelector('.wsm-up').addEventListener('click', function (e) { e.preventDefault(); fileIn.click(); });
    fileIn.addEventListener('change', function () { upload(fileIn.files); fileIn.value = ''; });
    pathIn.addEventListener('keydown', function (e) { if (e.key === 'Enter') go(pathIn.value.trim() || '/'); });
    hiddenBox.input.addEventListener('change', load);
    var tb = el('div', { cls: 'wsm-toolbar' }, [
      btn('', 'bi-arrow-up', null, function () { var p = state.path.replace(/\/[^/]*$/, '') || '/'; go(p); }, 'Up'),
      btn('', 'bi-house', null, function () { go('/var/www'); }, '/var/www'),
      pathIn, btn('Go', 'bi-arrow-right', null, function () { go(pathIn.value.trim() || '/'); }),
      btn('', 'bi-arrow-repeat', null, load, 'Reload'), hiddenBox,
      btn('New file', 'bi-file-earmark-plus', null, function () {
        var n = input({ placeholder: 'index.html' });
        dialog('New file in ' + state.path, field('Name', n), [btn('Create', 'bi-check', 'btn-fw-primary', function () {
          if (!needWrites()) return; api('fs.write', { path: state.path.replace(/\/$/, '') + '/' + n.value, content: '', create_only: true }).then(function () { modal('wsm-dialog').hide(); load(); }).catch(fail);
        })], false);
      }),
      btn('New folder', 'bi-folder-plus', null, function () {
        var n = input({ placeholder: 'images' });
        dialog('New folder in ' + state.path, field('Name', n), [btn('Create', 'bi-check', 'btn-fw-primary', function () {
          if (!needWrites()) return; api('fs.mkdir', { path: state.path.replace(/\/$/, '') + '/' + n.value }).then(function () { modal('wsm-dialog').hide(); load(); }).catch(fail);
        })], false);
      }),
      btn('Compress', 'bi-file-zip', null, function () {
        var s = selected(); if (!s.length) return flash('warn', 'Tick the items to compress.');
        var d = input({ value: state.path.replace(/\/$/, '') + '/archive.zip', cls: 'form-control form-control-sm wsm-mono' });
        var fm = select([['zip', 'ZIP'], ['tar.gz', 'TAR.GZ']], 'zip');
        dialog('Compress ' + s.length + ' item(s)', el('div', {}, [field('Archive path', d), field('Format', fm)]), [btn('Compress', 'bi-file-zip', 'btn-fw-primary', function () {
          if (!needWrites()) return; job('fs.archive', { paths: s, dest: d.value, format: fm.value }, { title: 'Compress' }).then(function () { modal('wsm-dialog').hide(); flash('ok', 'Archive created.'); load(); }).catch(fail);
        })], false);
      }),
      btn('Permissions', 'bi-shield-lock', null, function () { var s = selected(); if (!s.length) return flash('warn', 'Tick items first.'); perms(s, null); }),
      btn('Delete', 'bi-trash', 'btn-outline-danger', function () { var s = selected(); if (!s.length) return flash('warn', 'Tick items first.'); del(s); }),
      btn('Search', 'bi-search', null, function () {
        var nm = input({ value: '*' }), ct = input({ placeholder: 'text inside the files (optional)' });
        var out = el('div');
        dialog('Search under ' + state.path, el('div', {}, [el('div', { cls: 'row g-2' }, [el('div', { cls: 'col-6' }, [field('Name (wildcards * ?)', nm)]), el('div', { cls: 'col-6' }, [field('Containing', ct)])]), out]), [btn('Search', 'bi-search', 'btn-fw-primary', function () {
          out.innerHTML = ''; out.appendChild(loading('Searching…'));
          job('fs.search', { path: state.path, name: nm.value || '*', content: ct.value }, { title: 'Search' }).then(function (r) {
            var res = r.result; out.innerHTML = '';
            out.appendChild(table(['Path', 'Line'], res.hits.map(function (x) { return [el('span', { cls: 'wsm-name-link wsm-mono', text: x.path, onclick: function () { modal('wsm-dialog').hide(); x.type === 'dir' ? go(x.path) : openFile(x.path); } }), el('span', { cls: 'wsm-mono', text: x.line })]; }), { empty: 'Nothing found.' }));
            if (res.truncated) out.appendChild(el('div', { cls: 'wsm-small text-muted', text: 'More results exist: narrow the search.' }));
          }).catch(function (e) { out.innerHTML = ''; fail(e); });
        })]);
      })
    ]);
    setPage([tb, drop, fileIn, info, listBox]);
    load();
  }

  // ======================================================================
  //  DOMAINS & VHOSTS
  // ======================================================================
  function pageSites() {
    var listBox = el('div');
    var info = null;
    function load() {
      listBox.innerHTML = ''; listBox.appendChild(loading());
      Promise.all([api('info', {}), api('vhosts.list', {})]).then(function (x) {
        info = x[0];
        var rows = x[1].vhosts.map(function (v) {
          var acts = el('div', { cls: 'd-flex gap-1 flex-wrap' }, [
            btn('', 'bi-file-earmark-code', null, function () { edit(v); }, 'Edit configuration'),
            v.enabled ? btn('', 'bi-toggle-on', null, function () { toggle(v, false); }, 'Disable') : btn('', 'bi-toggle-off', null, function () { toggle(v, true); }, 'Enable'),
            v.docroots[0] ? el('a', { cls: 'btn btn-sm btn-outline-secondary', href: CFG.base + 'files', title: 'Files', onclick: function () { localStorage.setItem(KEY + '.path', v.docroots[0]); } }, [el('i', { cls: 'bi bi-folder2-open' })]) : null,
            btn('', 'bi-sliders', null, function () { localStorage.setItem(KEY + '.htaccess', JSON.stringify(v)); location.href = CFG.base + 'htaccess'; }, '.htaccess / rules'),
            btn('', 'bi-activity', null, function () { checkSite(v); }, 'Check it responds'),
            btn('', 'bi-trash', 'btn-outline-danger', function () { remove(v); }, 'Delete')]);
          return [el('div', {}, [el('strong', { text: v.server_names[0] || v.name }), el('div', { cls: 'text-muted wsm-small', text: v.server_names.slice(1).join(' ') })]),
            v.server, el('span', { cls: 'wsm-mono', text: v.name }), el('span', { cls: 'wsm-mono', text: v.docroots.join(' ') }),
            el('div', {}, [v.enabled ? badge('on', 'wsm-ok') : badge('off', 'wsm-muted'), v.ssl ? badge('HTTPS', 'wsm-info') : null]), acts];
        });
        listBox.innerHTML = ''; listBox.appendChild(table(['Site', 'Server', 'File', 'Document root', 'State', ''], rows, { empty: 'No virtual host found.' }));
      }).catch(function (e) { listBox.innerHTML = ''; listBox.appendChild(el('div', { cls: 'wsm-msg err', text: e.message })); });
    }
    function result(r, what) {
      if (r.restored) { flash('err', what + ': the server\'s configuration test failed, the previous configuration was restored and nothing was reloaded.\n' + (r.test_output || '')); return false; }
      flash('ok', what + (r.applied ? ' — tested and reloaded.' : '.')); return true;
    }
    function edit(v) {
      apiFull('vhost.get', { server: v.server, name: v.name }).then(function (d) {
        var r = d.result, host = el('div');
        var ed = WsmEditor.create(host, { text: r.content, lang: v.server === 'nginx' ? 'nginx' : 'apache' });
        dialog(v.server + ' · ' + v.name, el('div', {}, [el('p', { cls: 'wsm-small text-muted', text: 'Saving backs the file up, runs the server\'s own test and reloads only if it passes; otherwise the previous file comes back.' }), host]), [
          btn('Test only', 'bi-check2-circle', null, function () { api('vhost.test', { server: v.server }).then(function (t) { flash(t.ok ? 'ok' : 'err', (t.ok ? 'Configuration test passed. ' : 'Test failed: ') + t.output); }).catch(fail); }),
          btn('Save and reload', 'bi-save', 'btn-fw-primary', function () {
            if (!needWrites()) return;
            api('vhost.put', { server: v.server, name: v.name, content: ed.value(), base_sha256: r.sha256 }).then(function (w) { if (result(w, 'Saved')) { modal('wsm-dialog').hide(); load(); } }).catch(fail);
          })]);
      }).catch(fail);
    }
    function toggle(v, on) { if (!needWrites()) return; api(on ? 'vhost.enable' : 'vhost.disable', { server: v.server, name: v.name }).then(function (r) { result(r, on ? 'Enabled' : 'Disabled'); load(); }).catch(fail); }
    function remove(v) {
      confirmBox({ title: 'Delete site', text: 'Delete the virtual host ' + v.name + '? A backup of the file is kept on the server; the website files are NOT deleted.', danger: true, typed: v.name, ok: 'Delete' }).then(function (ok) {
        if (ok && needWrites()) api('vhost.delete', { server: v.server, name: v.name }).then(function (r) { result(r, 'Deleted'); load(); }).catch(fail);
      });
    }
    function checkSite(v) {
      var h = v.server_names[0] || 'localhost';
      Promise.all([api('http.check', { host: h, port: 80 }), v.ssl ? api('http.check', { host: h, port: 443, scheme: 'https' }) : Promise.resolve(null)]).then(function (x) {
        var t = 'http://' + h + ' → ' + x[0].status + ' ' + x[0].reason + (x[0].location ? ' (→ ' + x[0].location + ')' : '') + ' in ' + x[0].ms + ' ms';
        if (x[1]) t += '\nhttps://' + h + ' → ' + x[1].status + ' ' + x[1].reason + ' in ' + x[1].ms + ' ms';
        flash(x[0].status && x[0].status < 500 ? 'ok' : 'err', t);
      }).catch(fail);
    }
    function create() {
      var servers = info ? Object.keys(info.servers) : ['nginx', 'apache'];
      var f = {
        server: select(servers, servers[0]), names: input({ placeholder: 'example.com www.example.com' }),
        kind: select([['static', 'Static website (HTML)'], ['php', 'PHP application'], ['proxy', 'Forward to an application (reverse proxy)']], 'static'),
        docroot: input({ placeholder: '/var/www/example.com/public', cls: 'form-control form-control-sm wsm-mono' }),
        proxy: input({ placeholder: 'http://127.0.0.1:3000' }), php: input({ placeholder: 'auto-detected PHP-FPM socket' }),
        index: input({ placeholder: 'index.php index.html' }),
        https: check('HTTPS', false), certName: input({ placeholder: 'certificate name (SSL Certificates page)' }),
        redirect: check('Send HTTP visitors to HTTPS', true), upload: input({ type: 'number', min: 0, max: 10240, placeholder: 'e.g. 64' }),
        timeout: input({ type: 'number', min: 0, max: 3600, placeholder: 'e.g. 60' }), secHeaders: check('Add security headers (nosniff, frame, referrer)', true),
        logs: check('Own log files for this site', true), htaccess: check('Apache: read .htaccess files (AllowOverride All)', true),
        owner: input({ placeholder: 'e.g. eric (owner of the new folder)' })
      };
      function sync() { f.proxy.parentNode.classList.toggle('d-none', f.kind.value !== 'proxy'); f.php.parentNode.classList.toggle('d-none', f.kind.value !== 'php'); }
      f.kind.addEventListener('change', sync);
      var body = el('div', {}, [
        el('div', { cls: 'row g-2' }, [el('div', { cls: 'col-md-4' }, [field('Web server', f.server)]), el('div', { cls: 'col-md-8' }, [field('Domains (first = main name)', f.names)])]),
        field('Type of site', f.kind), field('Document root', f.docroot, 'Created if it does not exist, with a placeholder page.'),
        field('Application address', f.proxy), field('PHP-FPM socket (empty = detect)', f.php),
        el('div', { cls: 'row g-2' }, [el('div', { cls: 'col-md-4' }, [field('Index files', f.index)]), el('div', { cls: 'col-md-4' }, [field('Upload limit (MB)', f.upload)]), el('div', { cls: 'col-md-4' }, [field('Time limit (s)', f.timeout)])]),
        f.https, field('Certificate', f.certName), f.redirect, f.secHeaders, f.logs, f.htaccess, field('Owner of a new document root', f.owner)]);
      sync();
      dialog('New website', body, [btn('Create', 'bi-plus-lg', 'btn-fw-primary', function () {
        if (!needWrites()) return;
        var names = f.names.value.split(/[\s,]+/).filter(Boolean);
        var args = { server: f.server.value, name: (names[0] || '').replace(/\*/g, 'wildcard'), server_names: names, kind: f.kind.value,
          docroot: f.docroot.value || ('/var/www/' + (names[0] || 'site') + '/public'), proxy_to: f.proxy.value, php_socket: f.php.value,
          index: f.index.value, https: f.https.input.checked, cert_name: f.certName.value, redirect_https: f.redirect.input.checked,
          upload_mb: +f.upload.value || 0, timeout_s: +f.timeout.value || 0, security_headers: f.secHeaders.input.checked,
          own_logs: f.logs.input.checked, htaccess: f.htaccess.input.checked, owner: f.owner.value };
        api('vhost.create', args).then(function (r) {
          if (result(r, 'Site ' + names[0] + ' created')) { modal('wsm-dialog').hide(); load(); }
          if (r.content) $('#wsm-trace-body').textContent = r.content;
        }).catch(fail);
      })]);
    }
    setPage([el('div', { cls: 'wsm-toolbar' }, [btn('New website', 'bi-plus-lg', 'btn-fw-primary', create), btn('', 'bi-arrow-repeat', null, load, 'Reload'),
      btn('Test configuration', 'bi-check2-circle', null, function () { Object.keys((info || { servers: {} }).servers).forEach(function (s) { api('vhost.test', { server: s }).then(function (t) { flash(t.ok ? 'ok' : 'err', s + ': ' + (t.ok ? 'configuration test passed' : 'test failed') + '\n' + t.output); }).catch(fail); }); })]), listBox]);
    load();
  }

  // ======================================================================
  //  SSL CERTIFICATES
  // ======================================================================
  function pageCerts() {
    var listBox = el('div'), acmeBox = el('div');
    var vhosts = [];
    function load() {
      listBox.innerHTML = ''; listBox.appendChild(loading());
      Promise.all([api('certs.list', {}), api('vhosts.list', {}).catch(function () { return { vhosts: [] }; })]).then(function (x) {
        vhosts = x[1].vhosts;
        var rows = x[0].certs.map(function (c) {
          var st = { valid: 'wsm-ok', expiring: 'wsm-warn', expired: 'wsm-bad', requested: 'wsm-info', missing: 'wsm-bad', unreadable: 'wsm-muted' }[c.status];
          var acts = el('div', { cls: 'd-flex gap-1 flex-wrap' }, [
            c.managed && c.status !== 'requested' ? btn('', 'bi-link', null, function () { assign(c); }, 'Use on a site') : null,
            c.managed && c.pending ? btn('', 'bi-upload', null, function () { install(c); }, 'Install the signed certificate') : null,
            c.managed ? btn('', 'bi-arrow-repeat', null, function () { request(c); }, 'Renew') : null,
            btn('', 'bi-shield-check', null, function () { tls(c); }, 'Check TLS on a site'),
            c.managed && !c.used_by.length ? btn('', 'bi-trash', 'btn-outline-danger', function () { delCert(c); }, 'Delete') : null]);
          return [el('div', {}, [el('strong', { text: c.name || c.subject || c.path }), el('div', { cls: 'text-muted wsm-small wsm-mono', text: c.path })]),
            el('div', { cls: 'wsm-small', text: c.sans.slice(0, 6).join(', ') + (c.sans.length > 6 ? '…' : '') }), c.issuer,
            el('div', {}, [badge(c.status, st), c.not_after ? el('div', { cls: 'wsm-small', text: when(c.not_after).slice(0, 10) + ' (' + c.days_left + ' d)' }) : null]),
            el('div', { cls: 'wsm-small', text: c.used_by.map(function (u) { return u.server + '/' + u.vhost + (u.enabled ? '' : ' (off)'); }).join(', ') || '—' }), acts];
        });
        listBox.innerHTML = ''; listBox.appendChild(table(['Certificate', 'Names', 'Issuer', 'Expires', 'Used by', ''], rows, { empty: 'No certificate found.' }));
        var soon = x[0].certs.filter(function (c) { return c.status === 'expiring' || c.status === 'expired'; });
        if (soon.length) flash('warn', soon.length + ' certificate(s) expire soon or have expired: ' + soon.map(function (c) { return c.name || c.subject; }).join(', '));
      }).catch(function (e) { listBox.innerHTML = ''; listBox.appendChild(el('div', { cls: 'wsm-msg err', text: e.message })); });
      acmeBox.innerHTML = ''; acmeBox.appendChild(loading('Asking certbot…'));
      api('acme.status', {}).then(function (a) {
        acmeBox.innerHTML = '';
        if (!a.certbot) { acmeBox.append(el('p', { cls: 'wsm-small', text: 'certbot is not installed on this server.' }), el('a', { cls: 'btn btn-sm btn-outline-secondary', href: CFG.base + 'packages?q=certbot', text: 'Install certbot (Packages)' })); return; }
        acmeBox.append(el('div', { cls: 'wsm-small mb-1', text: a.certbot + ' · renewal timer: ' + (a.timer || 'none') }),
          table(['Name', 'Domains', 'Expiry'], a.certs.map(function (c) { return [c.name, (c.domains || []).join(' '), c.expiry]; }), { empty: 'No Let\'s Encrypt certificate (or not readable without root).' }),
          el('div', { cls: 'wsm-toolbar mt-2' }, [btn('Request', 'bi-plus-lg', 'btn-fw-primary', acmeIssue), btn('Renew all', 'bi-arrow-repeat', null, function () { acmeRenew(false); }), btn('Test renewal', 'bi-check2-circle', null, function () { acmeRenew(true); }),
            btn('Automatic renewal on', 'bi-alarm', null, function () { api('acme.autorenew', { enable: true }).then(function (r) { flash(r.ok ? 'ok' : 'err', r.timer + ': ' + (r.ok ? 'enabled' : r.output)); load(); }).catch(fail); })]));
      }).catch(function (e) { acmeBox.innerHTML = ''; acmeBox.appendChild(el('div', { cls: 'wsm-msg err', text: e.message })); });
    }
    function vhostOptions() { return vhosts.filter(function (v) { return v.ssl; }).map(function (v) { return [v.server + '|' + v.name, v.server + ' · ' + (v.server_names[0] || v.name)]; }); }
    function assign(c) {
      var opts = vhostOptions(); if (!opts.length) return flash('warn', 'No HTTPS site yet: create one with HTTPS on Domains & VHosts.');
      var s = select(opts, opts[0][0]);
      dialog('Use ' + c.name + ' on a site', field('Site', s), [btn('Apply', 'bi-link', 'btn-fw-primary', function () {
        if (!needWrites()) return; var p = s.value.split('|');
        api('cert.assign', { server: p[0], name: p[1], cert: c.name }).then(function (r) { if (r.restored) flash('err', 'Test failed, restored: ' + r.test_output); else { flash('ok', 'The site now uses ' + c.name + ' (tested and reloaded).'); modal('wsm-dialog').hide(); load(); } }).catch(fail);
      })], false);
    }
    function request(c) {
      var f = { name: input({ value: c ? c.name : '', placeholder: 'example-com' }), cn: input({ value: c ? (c.subject || '') : '', placeholder: 'example.com' }),
        sans: input({ value: c ? c.sans.join(' ') : '', placeholder: 'example.com www.example.com' }), kt: select([['ec256', 'ECDSA P-256'], ['ec384', 'ECDSA P-384'], ['rsa2048', 'RSA 2048'], ['rsa4096', 'RSA 4096']], 'ec256'),
        prov: select([['', 'Only make the request (I sign it elsewhere)']].concat((CFG.providers || []).map(function (p) { return [p, 'Sign with SATOM Certificate Manager: ' + p]; })), CFG.providers && CFG.providers[0] && CFG.can_sign ? CFG.providers[0] : '') };
      dialog(c ? 'Renew ' + c.name : 'New certificate request', el('div', {}, [el('p', { cls: 'wsm-small text-muted', text: 'The private key is generated ON the server and never leaves it. The request is signed by your internal CA (Certificate Manager) and installed, or you download the request.' }),
        field('Name', f.name), field('Common name', f.cn), field('All names (SAN)', f.sans), field('Key', f.kt), field('Signing', f.prov)]), [btn('Continue', 'bi-check', 'btn-fw-primary', function () {
        if (!needWrites()) return;
        var args = { name: f.name.value, common_name: f.cn.value, sans: f.sans.value.split(/[\s,]+/).filter(Boolean), key_type: f.kt.value };
        if (f.prov.value) {
          call(CFG.base + 'certs/sign', 'cert.sign', Object.assign({ provider: f.prov.value }, args)).then(function (d) { modal('wsm-dialog').hide(); flash('ok', 'Signed and installed (' + d.result.days_left + ' days).'); load(); }).catch(fail);
        } else api('cert.csr', args).then(function (r) { modal('wsm-dialog').hide(); dialog('Certificate request for ' + r.name, el('div', {}, [el('p', { text: 'Have it signed, then press Install on the certificate row.' }), pre(r.csr, true)]), [btn('Download', 'bi-download', null, function () { download(r.name + '.csr', r.csr); })]); load(); }).catch(fail);
      })], false);
    }
    function install(c) {
      var t = el('textarea', { cls: 'form-control wsm-mono', rows: 10, placeholder: '-----BEGIN CERTIFICATE-----' });
      dialog('Install signed certificate for ' + c.name, field('Certificate and chain (PEM)', t), [btn('Install', 'bi-upload', 'btn-fw-primary', function () {
        if (!needWrites()) return; api('cert.install', { name: c.name, certificate: t.value }).then(function () { modal('wsm-dialog').hide(); flash('ok', 'Installed.'); load(); }).catch(fail);
      })], false);
    }
    function importCert() {
      var n = input({ placeholder: 'example-com' }), cert = el('textarea', { cls: 'form-control wsm-mono', rows: 6, placeholder: '-----BEGIN CERTIFICATE-----' }),
        key = el('textarea', { cls: 'form-control wsm-mono', rows: 5, placeholder: '-----BEGIN PRIVATE KEY-----', autocomplete: 'off' }), chain = el('textarea', { cls: 'form-control wsm-mono', rows: 4, placeholder: 'intermediate CA certificates (optional)' });
      dialog('Import an existing certificate', el('div', {}, [el('p', { cls: 'wsm-small text-muted', text: 'The private key goes straight to the server (0600, root only). SATOM checks it matches the certificate, never stores it, never logs it and never shows it again.' }),
        field('Name', n), field('Certificate', cert), field('Private key', key), field('CA chain', chain)]), [btn('Import', 'bi-upload', 'btn-fw-primary', function () {
        if (!needWrites()) return; api('cert.import', { name: n.value, certificate: cert.value, private_key: key.value, chain: chain.value }, { runAs: 'root' }).then(function (r) { key.value = ''; modal('wsm-dialog').hide(); flash('ok', 'Imported ' + r.name + ' (' + r.days_left + ' days).'); load(); }).catch(fail);
      })], false);
    }
    function acmeIssue() {
      var d = input({ placeholder: 'example.com www.example.com' }), m = select([['webroot', 'Webroot (the site keeps running)'], ['nginx', 'nginx plugin'], ['apache', 'Apache plugin'], ['standalone', 'Standalone (port 80 must be free)']], 'webroot'),
        w = input({ placeholder: '/var/www/example.com/public', cls: 'form-control form-control-sm wsm-mono' }), e = input({ type: 'email', placeholder: 'admin@example.com' }), kt = select([['ecdsa', 'ECDSA'], ['rsa', 'RSA']], 'ecdsa'), st = check('Test (staging, not trusted by browsers)', false);
      var bar = progressBar();
      dialog('Let\'s Encrypt certificate', el('div', {}, [field('Domains', d), field('Method', m), field('Webroot', w), field('Email for expiry notices', e), field('Key type', kt), st, bar]), [btn('Request', 'bi-patch-check', 'btn-fw-primary', function () {
        if (!needWrites()) return;
        job('acme.issue', { domains: d.value.split(/[\s,]+/).filter(Boolean), method: m.value, webroot: w.value, email: e.value, key_type: kt.value, staging: st.input.checked }, { title: 'Let\'s Encrypt ' + d.value, progress: bar.bar }).then(function (r) {
          var res = r.result; dialog(res.ok ? 'Certificate issued' : 'certbot failed', pre(res.output), [], true); if (res.ok) load();
        }).catch(fail);
      })], false);
    }
    function acmeRenew(dry) { job('acme.renew', { dry_run: dry }, { title: 'certbot renew' }).then(function (r) { dialog('certbot renew' + (dry ? ' (test)' : ''), pre(r.result.output), [], true); load(); }).catch(fail); }
    function tls(c) {
      var host = input({ value: (c.sans[0] || c.subject || '').replace('*.', 'www.') }), port = input({ value: '443', type: 'number' });
      var out = el('div');
      dialog('TLS check', el('div', {}, [el('div', { cls: 'row g-2' }, [el('div', { cls: 'col-8' }, [field('Site name', host)]), el('div', { cls: 'col-4' }, [field('Port', port)])]), out]), [btn('Check', 'bi-shield-check', 'btn-fw-primary', function () {
        out.innerHTML = ''; out.appendChild(loading());
        api('tls.check', { host: host.value, port: +port.value }).then(function (r) {
          var kv = el('div', { cls: 'wsm-kv' });
          function row(k, v) { kv.append(el('div', { text: k }), v instanceof Node ? v : el('div', { text: v })); }
          row('Trusted chain', r.verify.trusted ? badge('yes', 'wsm-ok') : el('div', {}, [badge('no', 'wsm-bad'), ' ', r.verify.error]));
          row('Name matches', r.verify.hostname_ok ? badge('yes', 'wsm-ok') : badge('no', 'wsm-bad'));
          row('Expires', r.not_after ? when(r.not_after) + ' (' + r.days_left + ' days)' : '?');
          row('Names (SAN)', (r.sans || []).join(', '));
          Object.keys(r.protocols).forEach(function (p) { var v = r.protocols[p]; row(p, badge(v, v === 'accepted' ? (/1(\.1)?$/.test(p) && p !== 'TLSv1.2' && p !== 'TLSv1.3' ? 'wsm-bad' : 'wsm-ok') : 'wsm-muted')); });
          if (r.weak_protocols.length) row('Warning', badge('old TLS versions accepted: ' + r.weak_protocols.join(', '), 'wsm-warn'));
          out.innerHTML = ''; out.appendChild(kv);
        }).catch(function (e) { out.innerHTML = ''; fail(e); });
      })], false);
    }
    function delCert(c) { confirmBox({ text: 'Delete certificate ' + c.name + '? A backup is kept on the server.', danger: true, typed: c.name }).then(function (ok) { if (ok && needWrites()) api('cert.delete', { name: c.name }).then(function () { flash('ok', 'Deleted.'); load(); }).catch(fail); }); }
    setPage([el('div', { cls: 'wsm-toolbar' }, [btn('New request', 'bi-plus-lg', 'btn-fw-primary', function () { request(null); }), btn('Import', 'bi-upload', null, importCert), btn('', 'bi-arrow-repeat', null, load, 'Reload')]),
      listBox, card('Let\'s Encrypt (certbot)', 'bi-patch-check', [acmeBox], 'mt-3')]);
    load();
  }

  // ======================================================================
  //  SECURITY
  // ======================================================================
  function pageSecurity() {
    var out = el('div');
    function scan() {
      out.innerHTML = ''; var bar = progressBar(); out.append(el('p', { cls: 'wsm-small', text: 'Scanning document roots, web server and SSH configuration, ports, firewall and failed logins…' }), bar);
      job('security.scan', {}, { title: 'Security scan', progress: bar.bar }).then(function (r) {
        var s = r.result; out.innerHTML = '';
        var cls = s.score >= 80 ? 'good' : s.score >= 50 ? 'mid' : 'bad';
        var counts = {}; s.findings.forEach(function (f) { counts[f.severity] = (counts[f.severity] || 0) + 1; });
        out.appendChild(el('div', { cls: 'row g-3 mb-3' }, [
          el('div', { cls: 'col-md-3' }, [card('Security score', 'bi-speedometer', [el('div', { cls: 'wsm-score ' + cls, text: s.score }), el('div', { cls: 'wsm-small text-muted', text: s.complete ? 'complete scan' : 'partial: some checks need root (run as Administrator)' })])]),
          el('div', { cls: 'col-md-3' }, [card('Problems', 'bi-exclamation-triangle', ['critical', 'high', 'medium', 'low', 'info'].map(function (k) { return el('div', { cls: 'wsm-sev-' + k, text: k + ': ' + (counts[k] || 0) }); }))]),
          el('div', { cls: 'col-md-3' }, [card('Firewall', 'bi-bricks', [el('div', { text: (s.firewall.kind || 'none') + ' — ' + (s.firewall.active ? 'active' : s.firewall.active === false ? 'inactive' : 'unknown') }),
            s.firewall.kind ? el('div', { cls: 'mt-2 d-flex gap-1' }, [btn('Rules', 'bi-list', null, function () { fwDialog(s.firewall); })]) : null])]),
          el('div', { cls: 'col-md-3' }, [card('Failed SSH logins (24 h)', 'bi-person-x', [el('div', { cls: 'wsm-score ' + (s.failed_logins_24h > 50 ? 'bad' : 'good'), text: s.failed_logins_24h }), el('div', { cls: 'wsm-small', text: 'fail2ban: ' + (s.fail2ban.installed ? (s.fail2ban.jails.join(', ') || 'no jail') : 'not installed') }),
            s.fail2ban.installed ? btn('fail2ban', 'bi-shield', null, f2b) : null])])]));
        out.appendChild(table(['Severity', 'Problem', 'Details', 'What to do', ''], s.findings.map(function (f) {
          var fix = null;
          if (/World-writable/.test(f.title) && f.path) fix = btn('Fix', 'bi-wrench', null, function () { confirmBox({ text: 'Change ' + f.path + ' to 755 (folders) / 644 (files)?' }).then(function (ok) { if (ok && needWrites()) api('fs.chmod', { paths: [f.path], mode: '644', dir_mode: '755', recursive: true }).then(function () { flash('ok', 'Fixed.'); }).catch(fail); }); });
          if (/Sensitive file/.test(f.title) && f.path) fix = btn('Delete', 'bi-trash', 'btn-outline-danger', function () { confirmBox({ text: 'Delete ' + f.path + '? A backup is kept on the server.', danger: true }).then(function (ok) { if (ok && needWrites()) api('fs.delete', { paths: [f.path], recursive: true }).then(function () { flash('ok', 'Deleted.'); }).catch(fail); }); });
          return [el('span', { cls: 'wsm-sev-' + f.severity, text: f.severity }), f.title, el('span', { cls: 'wsm-small wsm-wrap', text: f.detail }), f.fix, fix];
        }), { empty: 'No problem found.' }));
        out.appendChild(card('Listening ports', 'bi-ethernet', [table(['Protocol', 'Address', 'Program'], s.ports.map(function (p) { return [p.proto, p.local, p.process]; }), { empty: 'Unknown (needs ss).' })], 'mt-3'));
        out.appendChild(el('div', { cls: 'wsm-advanced-only mt-3' }, [card('SSH server', 'bi-key', [pre(JSON.stringify(s.sshd, null, 1), true)])]));
      }).catch(function (e) { out.innerHTML = ''; fail(e); });
    }
    function fwDialog(fw) {
      var port = input({ placeholder: '443 or 8000-8100' }), proto = select(['tcp', 'udp'], 'tcp'), src = input({ placeholder: 'any, or 203.0.113.0/24' }), act = select([['allow', 'Allow'], ['deny', 'Block'], ['remove', 'Remove an allow rule']], 'allow');
      dialog('Firewall (' + fw.kind + ')', el('div', {}, [pre(fw.detail, true), el('hr'), el('div', { cls: 'row g-2' }, [el('div', { cls: 'col-3' }, [field('Action', act)]), el('div', { cls: 'col-3' }, [field('Port', port)]), el('div', { cls: 'col-2' }, [field('Protocol', proto)]), el('div', { cls: 'col-4' }, [field('From', src)])])]), [
        btn(fw.active ? 'Turn firewall off' : 'Turn firewall on', 'bi-power', 'btn-outline-danger', function () {
          confirmBox({ title: 'Firewall', text: fw.active ? 'Turn the firewall OFF? Every listening port becomes reachable.' : 'Turn the firewall ON? SATOM allows SSH first so you keep access; every other port not allowed is closed.', danger: true, typed: fw.active ? 'OFF' : 'ON' }).then(function (ok) {
            if (ok && needWrites()) api('fw.enable', { enable: !fw.active }, { runAs: 'root' }).then(function (r) { flash(r.ok ? 'ok' : 'err', r.output); modal('wsm-dialog').hide(); }).catch(fail);
          });
        }),
        btn('Apply rule', 'bi-check', 'btn-fw-primary', function () {
          confirmBox({ title: 'Firewall rule', text: act.value + ' ' + port.value + '/' + proto.value + (src.value ? ' from ' + src.value : '') + ' — changing the firewall can cut access to services. Continue?', typed: 'APPLY' }).then(function (ok) {
            if (ok && needWrites()) api('fw.rule', { action: act.value, port: port.value, proto: proto.value, source: src.value }, { runAs: 'root' }).then(function (r) { flash(r.ok ? 'ok' : 'err', r.output || 'done'); }).catch(fail);
          });
        })]);
    }
    function f2b() {
      api('f2b.status', {}, { runAs: 'root' }).then(function (r) {
        var jail = input({ value: 'sshd' }), ip = input({ placeholder: '203.0.113.7' });
        dialog('fail2ban', el('div', {}, [pre(r.output, true), el('div', { cls: 'row g-2 mt-2' }, [el('div', { cls: 'col-6' }, [field('Jail', jail)]), el('div', { cls: 'col-6' }, [field('Unban address', ip)])])]), [btn('Unban', 'bi-unlock', 'btn-fw-primary', function () {
          api('f2b.unban', { jail: jail.value, ip: ip.value }, { runAs: 'root' }).then(function (x) { flash(x.ok ? 'ok' : 'err', x.output || 'done'); }).catch(fail);
        })], false);
      }).catch(fail);
    }
    setPage([el('div', { cls: 'wsm-toolbar' }, [btn('Run security scan', 'bi-shield-check', 'btn-fw-primary', scan), el('span', { cls: 'wsm-small text-muted', text: 'Read-only: nothing changes until you press a Fix or firewall button and confirm.' })]), out]);
  }

  // ======================================================================
  //  .HTACCESS
  // ======================================================================
  function pageHtaccess() {
    var preset = null; try { preset = JSON.parse(localStorage.getItem(KEY + '.htaccess') || 'null'); } catch (e) { preset = null; }
    var vh = el('div'), work = el('div'), rules = [], vhosts = [], cur = null, current = null;
    function load() {
      vh.innerHTML = ''; vh.appendChild(loading());
      api('vhosts.list', {}).then(function (r) {
        vhosts = r.vhosts.filter(function (v) { return v.docroots.length; });
        var list = el('div', { cls: 'wsm-list fw-card' });
        vhosts.forEach(function (v) {
          var it = el('div', { cls: 'item', onclick: function () { Array.prototype.forEach.call(list.children, function (x) { x.classList.remove('active'); }); it.classList.add('active'); pick(v); } }, [el('strong', { text: v.server_names[0] || v.name }), el('div', { cls: 'wsm-small text-muted', text: v.server + ' · ' + v.docroots[0] })]);
          list.appendChild(it);
          if (preset && preset.name === v.name && preset.server === v.server) setTimeout(function () { it.click(); }, 0);
        });
        if (!vhosts.length) list.appendChild(el('div', { cls: 'p-3 text-muted wsm-small', text: 'No website with a document root on this server yet. Create one in Domains & VHosts.' }));
        vh.innerHTML = ''; vh.appendChild(list);
        localStorage.removeItem(KEY + '.htaccess');
      }).catch(function (e) { vh.innerHTML = ''; fail(e); });
    }
    function pick(v) {
      cur = v; rules = []; work.innerHTML = ''; work.appendChild(loading());
      var path = v.docroots[0].replace(/\/$/, '') + '/.htaccess';
      Promise.all([api('fs.read', { path: path, text: true }).catch(function (e) { if (e.data && /not_found/.test(e.data.error)) return { content: '', sha256: '' }; throw e; }),
        v.server === 'apache' ? api('apache.override', { path: v.docroots[0] }).catch(function () { return null; }) : Promise.resolve(null)]).then(function (x) {
        current = x[0]; draw(path, x[1]);
      }).catch(function (e) { work.innerHTML = ''; fail(e); });
    }
    function draw(path, override) {
      work.innerHTML = '';
      var isNginx = cur.server === 'nginx';
      var head = el('div', { cls: 'mb-2' }, [el('strong', { text: path }), ' ', isNginx ? badge('nginx: .htaccess is NOT read', 'wsm-warn') : override ? (override.enabled ? badge('Apache reads .htaccess here (AllowOverride ' + override.allow_override + ')', 'wsm-ok') : badge('Apache IGNORES .htaccess here (AllowOverride ' + override.allow_override + ')', 'wsm-bad')) : null]);
      if (isNginx) head.appendChild(el('p', { cls: 'wsm-small mt-1', text: 'nginx never reads .htaccess. Build the rules below: SATOM converts what nginx can do and applies it to the site\'s configuration (tested, restored on failure). Rules with no nginx equivalent are listed and NOT applied.' }));
      var ruleType = select(Object.keys(CFG.rules).map(function (k) { return [k, CFG.rules[k]]; }), 'force_https');
      var params = el('div', { cls: 'mb-2' }), ruleList = el('div');
      function paramFields() {
        params.innerHTML = ''; var t = ruleType.value, f = {};
        if (t === 'redirect') { f.from = input({ placeholder: '/old-page' }); f.to = input({ placeholder: '/new-page or https://other.site/page' }); f.permanent = check('Permanent (301)', true); params.append(field('From', f.from), field('To', f.to), f.permanent); }
        if (t === 'redirect_domain') { f.to = input({ placeholder: 'new-domain.com' }); params.append(field('New domain', f.to)); }
        if (t === 'block_ip' || t === 'allow_only') { f.ips = input({ placeholder: '203.0.113.7, 198.51.100.0/24' }); params.append(field('Addresses', f.ips)); }
        if (t === 'protect_dir') { f.htpasswd = input({ value: '/etc/apache2/.htpasswd' }); f.realm = input({ value: 'Restricted area' }); params.append(field('Password file (htpasswd)', f.htpasswd), field('Title shown', f.realm)); }
        if (t === 'deny_files') { f.files = input({ value: '.env *.sql *.bak *.log .git* composer.* *.ini' }); params.append(field('File patterns', f.files)); }
        if (t === 'error_page') { f.code = select(['404', '403', '500', '503'], '404'); f.page = input({ value: '/404.html' }); params.append(field('Error', f.code), field('Page', f.page)); }
        if (t === 'block_bots') { f.agents = input({ value: 'AhrefsBot, SemrushBot, MJ12bot, DotBot' }); params.append(field('Bot names', f.agents)); }
        if (t === 'rewrite') { f.pattern = input({ placeholder: '^blog/(.*)$' }); f.target = input({ placeholder: '/news/$1' }); f.flags = input({ value: 'L,R=301' }); params.append(field('Pattern', f.pattern), field('Target', f.target), field('Flags', f.flags)); }
        params.fields = f;
      }
      ruleType.addEventListener('change', paramFields); paramFields();
      function drawRules() {
        ruleList.innerHTML = '';
        rules.forEach(function (r, i) { ruleList.appendChild(el('div', { cls: 'wsm-rule d-flex justify-content-between' }, [el('span', { text: CFG.rules[r.type] + (r.from ? ': ' + r.from + ' → ' + r.to : r.to ? ': ' + r.to : r.ips ? ': ' + r.ips : '') }), btn('', 'bi-x', null, function () { rules.splice(i, 1); drawRules(); preview(); })])); });
      }
      var editorHost = el('div'), conv = el('div', { cls: 'mt-2' });
      var ed = WsmEditor.create(editorHost, { text: current.content || '', lang: 'apache', height: '300px' });
      function preview() {
        post(CFG.base.replace(/[^/]+\/$/, '') + 'htaccess/render', { rules: rules, existing: ed.value() }).then(function (d) {
          if (!d.ok) return fail(new Error(d.error));
          if (rules.length) ed.setValue(d.text);
          showConv(d.nginx);
        });
      }
      function showConv(n) {
        conv.innerHTML = '';
        if (!isNginx) return;
        conv.append(el('div', { cls: 'wsm-card-title' }, ['nginx equivalent']), pre(n.nginx || '(nothing to apply)', true));
        if (n.skipped.length) conv.append(el('div', { cls: 'wsm-msg warn mt-2' }, [el('div', {}, [el('strong', { text: 'Not converted — will NOT be applied on nginx:' }), el('ul', { cls: 'mb-0' }, n.skipped.map(function (s) { return el('li', {}, [el('code', { text: s.line }), ' — ' + s.why]); }))])]));
        conv.nginx = n;
      }
      ed.onChange(function () { if (isNginx) post(CFG.base.replace(/[^/]+\/$/, '') + 'htaccess/convert', { text: ed.value() }).then(function (d) { if (d.ok) showConv(d); }); });
      var tpl = select([['', 'Start from a template…']].concat(Object.keys(CFG.templates).map(function (k) { return [k, CFG.templates[k].label]; })), '');
      tpl.addEventListener('change', function () { if (tpl.value) { ed.setValue(CFG.templates[tpl.value].text); rules = []; drawRules(); preview(); } });
      var add = btn('Add rule', 'bi-plus', null, function () {
        var r = { type: ruleType.value }, f = params.fields || {};
        Object.keys(f).forEach(function (k) { r[k] = f[k].input ? f[k].input.checked : f[k].value; });
        rules.push(r); drawRules(); preview();
      });
      var apply = btn(isNginx ? 'Apply to the nginx site' : 'Save .htaccess', 'bi-save', 'btn-fw-primary', function () {
        if (!needWrites()) return;
        if (isNginx) {
          var n = conv.nginx || { nginx: '' };
          confirmBox({ text: 'Apply ' + (n.converted || []).length + ' converted line(s) to ' + cur.name + '? The server configuration is tested and restored if it fails.' + ((n.skipped || []).length ? ' ' + n.skipped.length + ' line(s) cannot be converted and are NOT applied.' : '') }).then(function (ok) {
            if (ok) api('vhost.snippet', { server: 'nginx', name: cur.name, marker: 'htaccess', content: n.nginx || '' }).then(function (r) { if (r.restored) flash('err', 'nginx -t failed, restored: ' + r.test_output); else flash('ok', 'Applied to the nginx site (tested and reloaded).'); }).catch(fail);
          });
        } else {
          api('htaccess.apply', { path: path, content: ed.value(), host: cur.server_names[0] || '', port: 80 }).then(function (r) {
            if (r.restored) flash('err', 'The site answered ' + r.check.status + ' with the new rules: the previous .htaccess was restored.');
            else flash('ok', 'Saved.' + (r.check ? ' The site answers ' + r.check.status + '.' : '') + (override && !override.enabled ? ' Note: Apache ignores .htaccess in this folder (AllowOverride None).' : ''));
          }).catch(fail);
        }
      });
      work.append(head, el('div', { cls: 'row g-3' }, [
        el('div', { cls: 'col-lg-5' }, [card('Wizard', 'bi-magic', [field('Rule', ruleType), params, add, el('hr'), ruleList, field('Templates', tpl)])]),
        el('div', { cls: 'col-lg-7' }, [card(isNginx ? 'Rules (Apache syntax, converted for nginx)' : '.htaccess', 'bi-file-earmark-code', [editorHost, conv, el('div', { cls: 'mt-2' }, [apply])])])]));
      if (isNginx) ed.textarea.dispatchEvent(new Event('input'));
    }
    setPage([el('div', { cls: 'wsm-split' }, [vh, work])]);
    work.appendChild(el('div', { cls: 'text-muted p-3', text: 'Pick a site on the left.' }));
    load();
  }

  // ======================================================================
  //  SCRIPTS
  // ======================================================================
  function pageScripts() {
    var list = el('div', { cls: 'wsm-list fw-card' }), work = el('div'), runs = el('div');
    var scripts = CFG.scripts || [];
    function drawList() {
      list.innerHTML = '';
      list.appendChild(el('div', { cls: 'item', onclick: function () { edit(null); } }, [el('i', { cls: 'bi bi-plus-lg' }), ' New script']));
      scripts.forEach(function (s) { list.appendChild(el('div', { cls: 'item', onclick: function () { edit(s); } }, [el('strong', { text: s.name }), ' ', badge(s.interpreter), s.shared ? badge('template', 'wsm-info') : null, el('div', { cls: 'wsm-small text-muted', text: s.description })])); });
    }
    function edit(s) {
      s = s || { name: '', interpreter: 'bash', content: '#!/bin/bash\nset -eu\necho "Hello from $(whoami) on $(hostname)"\n', args: [], cwd: '', timeout: 300, shared: false, mine: true };
      work.innerHTML = '';
      var name = input({ value: s.name }), desc = input({ value: s.description || '' }), interp = select([['bash', 'Bash'], ['sh', 'sh'], ['python', 'Python 3'], ['php', 'PHP'], ['perl', 'Perl'], ['custom', 'Custom (#! line)']], s.interpreter);
      var args = el('textarea', { cls: 'form-control form-control-sm wsm-mono', rows: 2, placeholder: 'one argument per line' }); args.value = (s.args || []).join('\n');
      var cwd = input({ value: s.cwd || '', placeholder: 'home folder of the account' }), tmo = input({ type: 'number', value: s.timeout || 300, min: 1, max: 3600 }), shared = check('Template: other operators can see and run it', s.shared);
      var host = el('div'), up = el('input', { type: 'file', cls: 'd-none' });
      var ed = WsmEditor.create(host, { text: s.content, lang: { python: 'python', php: 'php', perl: 'perl' }[s.interpreter] || 'bash', height: '340px' });
      interp.addEventListener('change', function () { ed.setLang({ python: 'python', php: 'php', perl: 'perl' }[interp.value] || 'bash'); });
      up.addEventListener('change', function () { var f = up.files[0]; if (!f) return; var rd = new FileReader(); rd.onload = function () { ed.setValue(String(rd.result)); if (!name.value) name.value = f.name; if (/\.py$/.test(f.name)) interp.value = 'python'; else if (/\.php$/.test(f.name)) interp.value = 'php'; else if (/\.pl$/.test(f.name)) interp.value = 'perl'; interp.dispatchEvent(new Event('change')); }; rd.readAsText(f); });
      function data() { return { name: name.value, description: desc.value, interpreter: interp.value, content: ed.value(), args: args.value.split('\n').filter(function (x) { return x !== ''; }), cwd: cwd.value, timeout: +tmo.value || 300, shared: shared.input.checked }; }
      var out = el('div', { cls: 'mt-2' });
      var save = btn('Save to library', 'bi-save', null, function () {
        post(CFG.base.replace(/[^/]+\/$/, '') + 'scripts' + (s.id ? '/' + s.id : ''), data()).then(function (d) { if (!d.ok) return fail(new Error(d.error)); scripts = d.scripts; s = d.script; drawList(); flash('ok', 'Saved.'); });
      });
      var del = s.id && s.mine ? btn('Delete', 'bi-trash', 'btn-outline-danger', function () { confirmBox({ text: 'Delete script ' + s.name + '?', danger: true }).then(function (ok) { if (ok) post(CFG.base.replace(/[^/]+\/$/, '') + 'scripts/' + s.id, { delete: true }).then(function (d) { if (!d.ok) return fail(new Error(d.error)); scripts = scripts.filter(function (x) { return x.id !== s.id; }); drawList(); work.innerHTML = ''; }); }); }) : null;
      var run = btn('Run…', 'bi-play-fill', 'btn-fw-primary', function () {
        if (!needWrites()) return;
        var c = currentCred(); if (!c) return fail(new Error('Pick a credential.'));
        var d = data(), r = runSel.value;
        var who = r === 'root' ? 'root (through sudo, as ' + c.ssh_user + ')' : r === 'auto' ? c.ssh_user + ' (sudo only if refused — scripts are not retried: pick Administrator to run as root)' : c.ssh_user;
        var kv = el('div', { cls: 'wsm-kv' });
        [['Server', CFG.name + ' (' + CFG.host + ')'], ['Signs in as', c.ssh_user + ' — credential ' + c.name], ['Runs as', who], ['Authentication', c.store_secret ? 'stored ' + c.auth_type : c.auth_type + ' asked now'],
          ['Working folder', d.cwd || 'home folder of ' + c.ssh_user], ['Command', ({ bash: 'bash', sh: 'sh', python: 'python3', php: 'php', perl: 'perl', custom: '(the #! line)' })[d.interpreter] + ' <script> ' + d.args.join(' ')], ['Parameters', d.args.length ? d.args.join(' | ') : 'none'], ['Time limit', d.timeout + ' s']].forEach(function (x) { kv.append(el('div', { text: x[0] }), el('div', { cls: 'wsm-mono', text: x[1] })); });
        confirmBox({ title: 'Run this script?', node: el('div', {}, [kv, el('div', { cls: 'mt-2' }, [el('div', { cls: 'fw-form-label', text: 'Script' }), pre(d.content.slice(0, 4000))])]), ok: 'Run', danger: r === 'root' }).then(function (ok) {
          if (!ok) return;
          out.innerHTML = ''; var bar = progressBar(); out.appendChild(bar);
          job('script.run', { interpreter: d.interpreter, content: d.content, args: d.args, cwd: d.cwd, timeout: d.timeout }, { title: 'Script ' + (d.name || 'ad hoc'), progress: bar.bar }).then(function (res) {
            var x = res.result; out.innerHTML = '';
            out.append(el('div', { cls: 'mb-1' }, [badge('exit ' + x.exit_code, x.exit_code === 0 ? 'wsm-ok' : 'wsm-bad'), ' ', badge('ran as ' + res.who.user, res.sudo ? 'wsm-root' : 'wsm-info'), ' ', el('span', { cls: 'wsm-small text-muted', text: x.seconds + ' s in ' + x.cwd + (x.timed_out ? ' — TIME LIMIT REACHED' : '') })]),
              el('div', { cls: 'fw-form-label', text: 'Output (STDOUT)' }), pre(x.stdout || '(empty)'), el('div', { cls: 'fw-form-label mt-2', text: 'Errors (STDERR)' }), pre(x.stderr || '(empty)'));
            loadRuns();
          }).catch(function (e) { out.innerHTML = ''; fail(e); });
        });
      });
      work.append(card(s.id ? s.name : 'New script', 'bi-terminal', [
        el('div', { cls: 'row g-2' }, [el('div', { cls: 'col-md-5' }, [field('Name', name)]), el('div', { cls: 'col-md-3' }, [field('Language', interp)]), el('div', { cls: 'col-md-4' }, [field('Description', desc)])]),
        host, el('div', { cls: 'row g-2 mt-1' }, [el('div', { cls: 'col-md-5' }, [field('Arguments', args)]), el('div', { cls: 'col-md-4' }, [field('Working folder', cwd)]), el('div', { cls: 'col-md-3' }, [field('Time limit (s)', tmo)])]),
        shared, el('div', { cls: 'wsm-toolbar mt-2' }, [run, CFG.perms.system ? save : null, btn('Upload a file', 'bi-upload', null, function () { up.click(); }), del, up]), out]));
    }
    function loadRuns() {
      fetch(location.href, { credentials: 'same-origin' }).then(function () {});
      runs.innerHTML = '';
      var rows = (CFG.runs || []).map(function (r) { return [r.started, r.title, r.by, r.effective_user + (r.sudo ? ' (sudo)' : ''), badge(r.status + (r.exit_code != null ? ' ' + r.exit_code : ''), r.status === 'ok' ? 'wsm-ok' : r.status === 'running' ? 'wsm-info' : 'wsm-bad'), btn('', 'bi-eye', null, function () { fetch(CFG.base + 'runs/' + r.id, { credentials: 'same-origin' }).then(function (x) { return x.json(); }).then(function (d) { dialog(d.title, el('div', {}, [el('div', { cls: 'fw-form-label', text: 'STDOUT' }), pre(d.stdout || '(empty)'), el('div', { cls: 'fw-form-label mt-2', text: 'STDERR' }), pre(d.stderr || '(empty)')]), [], true); }); }, 'Output')]; });
      runs.appendChild(card('Run history (this server)', 'bi-clock-history', [table(['Started (UTC)', 'What', 'By', 'Ran as', 'Result', ''], rows, { empty: 'No runs yet.' }), el('div', { cls: 'wsm-small text-muted', text: 'Reload the page to see runs started since it opened.' })], 'mt-3'));
    }
    drawList(); edit(null); loadRuns();
    setPage([el('div', { cls: 'wsm-split' }, [list, work]), runs]);
  }

  // ======================================================================
  //  CRON
  // ======================================================================
  function pageCron() {
    var who = input({ placeholder: 'user (empty = the signed-in account)', style: 'width:300px' });
    var box = el('div'), sched = el('div');
    var rows = [], sha = '';
    function load() {
      box.innerHTML = ''; box.appendChild(loading());
      call(CFG.base + 'cron/load', 'cron.get', { user: who.value }).then(function (d) {
        rows = d.rows; sha = d.result.sha256; draw(d.result.user);
      }).catch(function (e) { box.innerHTML = ''; fail(e); });
    }
    function draw(user) {
      box.innerHTML = '';
      var jobs = rows.filter(function (r) { return r.kind === 'job'; });
      box.append(el('div', { cls: 'wsm-small mb-1' }, ['Crontab of ', el('strong', { text: user }), ' — these jobs run on the server as ' + user + ', even when SATOM is off.']),
        table(['On', 'When', 'Command', 'Comment', ''], jobs.map(function (j) {
          var on = el('input', { type: 'checkbox', cls: 'form-check-input', onchange: function () { j.enabled = on.checked; save(); } }); on.checked = j.enabled;
          return [on, el('div', {}, [el('div', { text: j.human }), el('code', { cls: 'wsm-advanced-only', text: j.schedule })]), el('code', { text: j.command }), j.comment || '',
            el('div', { cls: 'd-flex gap-1' }, [btn('', 'bi-pencil', null, function () { form(j); }, 'Edit'), btn('', 'bi-files', null, function () { var c = Object.assign({}, j, { id: null }); delete c.id; form(c, true); }, 'Duplicate'), btn('', 'bi-trash', 'btn-outline-danger', function () { confirmBox({ text: 'Delete this job?\n' + j.schedule + ' ' + j.command, danger: true }).then(function (ok) { if (ok) { rows.splice(rows.indexOf(j), 1); save(); } }); }, 'Delete')])];
        }), { empty: 'No scheduled job in this crontab.' }));
      var env = rows.filter(function (r) { return r.kind === 'env'; });
      if (env.length) box.appendChild(el('div', { cls: 'wsm-small mt-1' }, ['Variables: '].concat(env.map(function (e) { return el('span', { cls: 'wsm-chip', text: e.name + '=' + e.value }); }))));
    }
    function scheduleBuilder(initial) {
      var kind = select([['minute', 'Every minute'], ['5min', 'Every 5 minutes'], ['hourly', 'Every hour'], ['daily', 'Every day'], ['weekly', 'Every week'], ['monthly', 'Every month'], ['custom', 'Custom (cron expression)']], initial ? 'custom' : 'daily');
      var hour = input({ type: 'number', min: 0, max: 23, value: 2 }), minute = input({ type: 'number', min: 0, max: 59, value: 0 });
      var dow = select([[1, 'Monday'], [2, 'Tuesday'], [3, 'Wednesday'], [4, 'Thursday'], [5, 'Friday'], [6, 'Saturday'], [0, 'Sunday']], 1), dom = input({ type: 'number', min: 1, max: 31, value: 1 });
      var expr = input({ value: initial || '0 2 * * *', cls: 'form-control form-control-sm wsm-mono' }), human = el('div', { cls: 'wsm-small text-muted' });
      var w = el('div', {}, [field('Frequency', kind), el('div', { cls: 'row g-2' }, [el('div', { cls: 'col-3' }, [field('Hour', hour)]), el('div', { cls: 'col-3' }, [field('Minute', minute)]), el('div', { cls: 'col-3' }, [field('Weekday', dow)]), el('div', { cls: 'col-3' }, [field('Day of month', dom)])]), field('Cron expression', expr), human]);
      function upd() {
        var k = kind.value; hour.parentNode.classList.toggle('d-none', ['daily', 'weekly', 'monthly'].indexOf(k) < 0); minute.parentNode.classList.toggle('d-none', ['daily', 'weekly', 'monthly'].indexOf(k) < 0);
        dow.parentNode.classList.toggle('d-none', k !== 'weekly'); dom.parentNode.classList.toggle('d-none', k !== 'monthly'); expr.readOnly = k !== 'custom';
        post(CFG.base.replace(/[^/]+\/$/, '') + 'cron/preset', { kind: k, hour: hour.value, minute: minute.value, dow: dow.value, dom: dom.value, expr: expr.value }).then(function (d) { if (d.ok) { expr.value = d.expr; human.textContent = d.human; } else human.textContent = d.error; });
      }
      [kind, hour, minute, dow, dom].forEach(function (x) { x.addEventListener('change', upd); }); expr.addEventListener('change', upd);
      upd(); w.value = function () { return expr.value; }; return w;
    }
    function form(j, dup) {
      var isNew = !j || dup; j = j || { kind: 'job', command: '', enabled: true, comment: '' };
      var sb = scheduleBuilder(j.schedule), cmd = input({ value: j.command || '', cls: 'form-control form-control-sm wsm-mono', placeholder: '/home/eric/scripts/backup.sh' }), cm = input({ value: j.comment || '' });
      var cwd = input({ placeholder: 'optional: run from this folder' }), outSel = select([['keep', 'Leave output as is (mailed to the user if mail works)'], ['log', 'Append output and errors to a log file'], ['quiet', 'Discard output, keep errors'], ['discard', 'Discard everything']], 'keep'), logf = input({ placeholder: '/home/eric/cron.log', cls: 'form-control form-control-sm wsm-mono' });
      var mailto = input({ placeholder: 'email for errors (MAILTO, optional)' });
      dialog(isNew ? 'New scheduled job' : 'Edit scheduled job', el('div', {}, [sb, field('Command or script', cmd), field('Working folder', cwd), field('Output', outSel), field('Log file', logf), field('Notify errors to', mailto, 'Sets MAILTO for this crontab (needs a mail system on the server).'), field('Comment', cm)]), [btn('Save', 'bi-save', 'btn-fw-primary', function () {
        var c = cmd.value.trim(); if (!c) return fail(new Error('A command is required.'));
        if (cwd.value && isNew) c = 'cd ' + cwd.value.replace(/[^A-Za-z0-9._\/-]/g, '') + ' && ' + c;
        if (outSel.value === 'log' && logf.value) c += ' >> ' + logf.value.replace(/[^A-Za-z0-9._\/-]/g, '') + ' 2>&1';
        if (outSel.value === 'quiet') c += ' > /dev/null';
        if (outSel.value === 'discard') c += ' > /dev/null 2>&1';
        if (mailto.value && !rows.some(function (r) { return r.kind === 'env' && r.name === 'MAILTO'; })) rows.unshift({ kind: 'env', name: 'MAILTO', value: mailto.value.replace(/[^A-Za-z0-9.@+_,-]/g, ''), enabled: true });
        var nj = Object.assign({}, j, { kind: 'job', schedule: sb.value(), command: c, comment: cm.value, enabled: j.enabled !== false });
        if (isNew) rows.push(nj); else rows[rows.indexOf(j)] = nj;
        save(function () { modal('wsm-dialog').hide(); });
      })], false);
    }
    function save(after) {
      if (!needWrites()) return;
      call(CFG.base + 'cron/save', 'cron.put', { user: who.value, base_sha256: sha }, { extra: { rows: rows } }).then(function () { flash('ok', 'Crontab saved.'); if (after) after(); load(); }).catch(function (e) { fail(e); load(); });
    }
    function drawSchedules() {
      sched.innerHTML = '';
      var list = CFG.schedules || [];
      var st = { ok: 'wsm-ok', failed: 'wsm-bad', pending_auth: 'wsm-warn', never: 'wsm-muted' };
      sched.appendChild(card('Scheduled by SATOM', 'bi-calendar-check', [
        el('p', { cls: 'wsm-small text-muted', text: 'SATOM runs a library script on this server with a stored service credential. Revoking or disabling the credential stops these jobs (they wait for authentication and the administrators are notified); the jobs themselves are kept.' }),
        table(['Name', 'When (UTC)', 'Script', 'Credential', 'Run as', 'State', 'Last run', ''], list.map(function (s) {
          return [s.name, s.human, s.script, s.credential, s.run_as, el('div', {}, [badge(s.state.replace('_', ' '), st[s.state]), s.problem ? el('div', { cls: 'wsm-small text-muted', text: s.problem }) : (s.detail ? el('div', { cls: 'wsm-small text-muted', text: s.detail }) : null)]), s.last_run + (s.last_exit != null ? ' (exit ' + s.last_exit + ')' : ''),
            el('div', { cls: 'd-flex gap-1' }, [btn('', s.enabled ? 'bi-pause-circle' : 'bi-play-circle', null, function () { post(CFG.base + 'schedules/' + s.id, { enabled: !s.enabled }).then(function (d) { if (d.ok) { Object.assign(s, d.schedule); drawSchedules(); } else fail(new Error(d.error)); }); }, s.enabled ? 'Pause' : 'Resume'),
              btn('', 'bi-pencil', null, function () { schedForm(s); }, 'Edit'),
              btn('', 'bi-trash', 'btn-outline-danger', function () { confirmBox({ text: 'Delete ' + s.name + '?', danger: true }).then(function (ok) { if (ok) post(CFG.base + 'schedules/' + s.id, { delete: true }).then(function () { CFG.schedules = list.filter(function (x) { return x.id !== s.id; }); drawSchedules(); }); }); }, 'Delete')])];
        }), { empty: 'Nothing scheduled by SATOM on this server.' }),
        CFG.perms.system ? btn('New', 'bi-plus-lg', 'btn-fw-primary', function () { schedForm(null); }) : null], 'mt-3'));
    }
    function schedForm(s) {
      s = s || {};
      var name = input({ value: s.name || '' }), sb = scheduleBuilder(s.cron), script = select((CFG.scripts || []).map(function (x) { return [x.id, x.name]; }), s.script_id);
      var cr = select(creds().filter(function (c) { return c.usable && c.auth_type !== 'agent'; }).map(function (c) { return [c.id, c.name + ' (' + c.ssh_user + (c.store_secret ? '' : ', asks every time — cannot run unattended') + ')']; }), s.credential_id);
      var ra = select([['self', 'The credential\'s account'], ['root', 'root (sudo)']], s.run_as || 'self');
      if (!(CFG.scripts || []).length) return flash('warn', 'Save a script in the Scripts library first.');
      dialog(s.id ? 'Edit SATOM schedule' : 'New SATOM schedule', el('div', {}, [field('Name', name), sb, field('Script', script), field('Service credential', cr), field('Run as', ra)]), [btn('Save', 'bi-save', 'btn-fw-primary', function () {
        post(CFG.base + 'schedules' + (s.id ? '/' + s.id : ''), { name: name.value, cron: sb.value(), script_id: script.value, credential_id: cr.value, run_as: ra.value, enabled: true }).then(function (d) {
          if (!d.ok) return fail(new Error(d.error));
          var l = CFG.schedules || []; var i = l.findIndex(function (x) { return x.id === d.schedule.id; }); if (i >= 0) l[i] = d.schedule; else l.push(d.schedule); CFG.schedules = l;
          modal('wsm-dialog').hide(); drawSchedules(); flash(d.warning ? 'warn' : 'ok', d.warning ? 'Saved, but it cannot run yet: ' + d.warning : 'Saved.');
        });
      })], false);
    }
    var logBtn = btn('Cron log', 'bi-journal-text', null, function () { api('cron.log', { lines: 300 }).then(function (r) { dialog('Cron log — ' + r.source, pre(r.lines.join('\n') || '(empty)'), [], true); }).catch(fail); });
    var usersBtn = btn('Users with a crontab', 'bi-people', null, function () { api('cron.users', {}, { runAs: 'root' }).then(function (r) { dialog('Crontabs on this server', el('div', {}, [el('p', { text: 'Users: ' + (r.users.join(', ') || 'none') }), el('p', { text: 'System files: ' + r.system_files.join(', ') })]), [], false); }).catch(fail); });
    who.addEventListener('keydown', function (e) { if (e.key === 'Enter') load(); });
    setPage([el('div', { cls: 'wsm-toolbar' }, [who, btn('Open', 'bi-arrow-right', null, load), btn('New job', 'bi-plus-lg', 'btn-fw-primary', function () { form(null); }), logBtn, usersBtn,
      el('span', { cls: 'wsm-small text-muted', text: 'Another user\'s crontab needs administrator rights.' })]), box, sched]);
    load(); drawSchedules();
  }

  // ======================================================================
  //  PACKAGES
  // ======================================================================
  function pagePackages() {
    var q = input({ placeholder: 'search packages, e.g. nginx, php, certbot', value: new URLSearchParams(location.search).get('q') || '' });
    var out = el('div'), side = el('div');
    function search() {
      if (q.value.trim().length < 2) return;
      out.innerHTML = ''; out.appendChild(loading('Searching…'));
      api('pkg.search', { q: q.value.trim() }).then(function (r) {
        out.innerHTML = '';
        out.appendChild(table(['Package', 'Description', 'State', ''], r.results.map(function (p) {
          return [el('span', { cls: 'wsm-name-link', text: p.name, onclick: function () { show(p.name); } }), p.summary, p.installed ? badge('installed', 'wsm-ok') : '',
            el('div', { cls: 'd-flex gap-1' }, [p.installed ? btn('Remove', 'bi-dash-circle', 'btn-outline-danger', function () { change('remove', [p.name]); }) : btn('Install', 'bi-download', 'btn-fw-primary', function () { change('install', [p.name]); }),
              p.installed ? btn('Update', 'bi-arrow-up-circle', null, function () { change('upgrade', [p.name]); }) : null])];
        }), { empty: 'No package found.' }));
      }).catch(function (e) { out.innerHTML = ''; fail(e); });
    }
    function show(n) { api('pkg.show', { name: n }).then(function (r) { dialog(n, pre(r.text), [], true); }).catch(fail); }
    function change(action, names) {
      if (!needWrites()) return;
      var box = el('div', {}, [loading('Asking the package manager what would change…')]);
      var m = dialog((action === 'upgrade' ? 'Update ' : action === 'install' ? 'Install ' : 'Remove ') + (names.join(', ') || 'everything'), box, [], true);
      job('pkg.plan', { action: action, names: names }, { title: 'Plan ' + action }).then(function (res) {
        var r = res.result; box.innerHTML = '';
        var p = r.plan, total = p.install.length + p.upgrade.length + p.remove.length;
        box.append(el('p', {}, ['The ', el('strong', { text: r.manager }), ' package manager would:']));
        [['install', 'install', 'wsm-ok'], ['upgrade', 'upgrade', 'wsm-info'], ['remove', 'REMOVE', 'wsm-bad']].forEach(function (k) {
          if (p[k[0]].length) box.append(el('div', { cls: 'mb-2' }, [badge(k[1] + ' ' + p[k[0]].length, k[2]), ' '].concat(p[k[0]].map(function (x) { return el('span', { cls: 'wsm-chip', text: x.name + (x.version ? ' ' + x.version : '') }); }))));
        });
        if (!total) box.append(el('div', { cls: 'wsm-msg warn', text: 'Nothing to do, or the plan could not be read (see the output).' }));
        if (p.remove.length && action !== 'remove') box.append(el('div', { cls: 'wsm-msg err', text: 'Careful: this also REMOVES packages other services may need.' }));
        box.append(el('details', { cls: 'wsm-advanced-only mt-2' }, [el('summary', { text: 'Package manager output' }), pre(r.output)]));
        box.append(el('p', { cls: 'wsm-small mt-2', text: 'Runs with administrator rights through sudo as ' + (currentCred() || {}).ssh_user + '. Services may restart.' }));
        var bar = progressBar(); box.append(bar);
        var go = btn('Confirm and ' + action, 'bi-check', action === 'remove' ? 'btn-danger' : 'btn-fw-primary', function () {
          go.disabled = true;
          job('pkg.apply', { action: action, names: names }, { title: action + ' ' + names.join(' '), progress: bar.bar }).then(function (x) {
            var a = x.result; box.append(el('div', { cls: 'wsm-msg ' + (a.ok ? 'ok' : 'err'), text: a.ok ? 'Done (as ' + x.who.user + ').' : 'The package manager failed (exit ' + a.exit_code + ').' }), pre(a.output));
            if (a.ok) search();
          }).catch(function (e) { go.disabled = false; fail(e); });
        });
        $('#wsm-dialog-foot').prepend(go);
      }).catch(function (e) { box.innerHTML = ''; box.appendChild(el('div', { cls: 'wsm-msg err', text: e.message })); });
    }
    function installed() {
      side.innerHTML = ''; side.appendChild(loading());
      var f = input({ placeholder: 'filter' });
      api('pkg.installed', {}).then(function (r) {
        function draw() { var v = f.value.toLowerCase(); tb.innerHTML = ''; tb.appendChild(table(['Package', 'Version', 'Description'], r.packages.filter(function (p) { return !v || p.name.toLowerCase().indexOf(v) >= 0; }).slice(0, 500).map(function (p) { return [el('span', { cls: 'wsm-name-link', text: p.name, onclick: function () { show(p.name); } }), el('span', { cls: 'wsm-mono', text: p.version }), p.summary]; }))); }
        var tb = el('div'); f.addEventListener('input', draw);
        side.innerHTML = ''; side.append(el('div', { cls: 'wsm-toolbar' }, [el('strong', { text: r.total + ' installed (' + r.manager + ')' }), f]), tb); draw();
      }).catch(function (e) { side.innerHTML = ''; fail(e); });
    }
    function updates() {
      side.innerHTML = ''; side.appendChild(loading('Checking for updates…'));
      job('pkg.updates', {}, { title: 'Pending updates' }).then(function (x) {
        var r = x.result; side.innerHTML = '';
        side.append(el('div', { cls: 'wsm-toolbar' }, [el('strong', { text: r.total + ' update(s) pending' }), btn('Refresh package lists', 'bi-arrow-repeat', null, function () { job('pkg.refresh', {}, { title: 'Refresh lists' }).then(function (y) { flash(y.result.ok ? 'ok' : 'err', y.result.ok ? 'Lists refreshed.' : y.result.output); updates(); }).catch(fail); }),
          r.total ? btn('Update all', 'bi-arrow-up-circle', 'btn-fw-primary', function () { change('upgrade', []); }) : null]),
        table(['Package', 'Installed', 'New'], r.updates.map(function (u) { return [u.name, u.old || '—', u.new]; }), { empty: 'Everything is up to date (as of the last list refresh).' }));
      }).catch(function (e) { side.innerHTML = ''; fail(e); });
    }
    q.addEventListener('keydown', function (e) { if (e.key === 'Enter') search(); });
    setPage([el('div', { cls: 'wsm-toolbar' }, [q, btn('Search', 'bi-search', 'btn-fw-primary', search), btn('Installed', 'bi-box-seam', null, installed), btn('Updates', 'bi-arrow-up-circle', null, updates)]), out, el('div', { cls: 'mt-3' }, [side])]);
    if (q.value) search(); else updates();
  }

  // ======================================================================
  //  SERVICES
  // ======================================================================
  function pageServices() {
    var f = input({ placeholder: 'filter, e.g. nginx, php, mariadb' }), onlyActive = check('Only running', false), box = el('div'), all = [];
    var common = /^(nginx|apache2|httpd|php.*fpm|mariadb|mysql|mysqld|postgresql.*|redis.*|certbot.*|cron|crond|sshd?|fail2ban|firewalld|ufw|docker|memcached|varnish|postfix)\.service$/;
    function load() {
      box.innerHTML = ''; box.appendChild(loading());
      api('svc.list', {}).then(function (r) { all = r.services; draw(); }).catch(function (e) { box.innerHTML = ''; fail(e); });
    }
    function draw() {
      var v = f.value.toLowerCase();
      var rows = all.filter(function (s) { return (!v || s.name.toLowerCase().indexOf(v) >= 0 || s.description.toLowerCase().indexOf(v) >= 0) && (!onlyActive.input.checked || s.active === 'active') && (v || common.test(s.name) || onlyActive.input.checked); });
      box.innerHTML = '';
      if (!v && !onlyActive.input.checked) box.appendChild(el('div', { cls: 'wsm-small text-muted mb-1', text: 'Showing the usual web-server services. Type in the filter to see all ' + all.length + '.' }));
      box.appendChild(table(['Service', 'Description', 'State', 'At boot', ''], rows.map(function (s) {
        var st = s.active === 'active' ? 'wsm-ok' : s.active === 'failed' ? 'wsm-bad' : 'wsm-muted';
        return [el('span', { cls: 'wsm-name-link', text: s.name, onclick: function () { status(s.name); } }), s.description, badge(s.active + ' (' + s.sub + ')', st), s.enabled || '—',
          el('div', { cls: 'd-flex gap-1 flex-wrap' }, [s.active === 'active' ? btn('', 'bi-stop-circle', null, function () { act(s, 'stop'); }, 'Stop') : btn('', 'bi-play-circle', null, function () { act(s, 'start'); }, 'Start'),
            btn('', 'bi-arrow-clockwise', null, function () { act(s, 'restart'); }, 'Restart'), btn('', 'bi-arrow-repeat', null, function () { act(s, 'reload'); }, 'Reload'),
            s.enabled === 'enabled' ? btn('', 'bi-toggle-on', null, function () { act(s, 'disable'); }, 'Do not start at boot') : btn('', 'bi-toggle-off', null, function () { act(s, 'enable'); }, 'Start at boot'),
            btn('', 'bi-journal-text', null, function () { logs(s.name); }, 'Logs')])];
      }), { empty: 'No service matches.' }));
    }
    function act(s, a) {
      if (!needWrites()) return;
      var risky = /^sshd?\.service$/.test(s.name) && /stop|disable/.test(a);
      confirmBox({ text: a + ' ' + s.name + '?' + (risky ? ' Stopping SSH cuts SATOM\'s access to this server.' : ''), danger: /stop|disable/.test(a), typed: risky ? s.name : null }).then(function (ok) {
        if (ok) api('svc.action', { name: s.name, action: a }).then(function (r) { flash(r.ok ? 'ok' : 'err', s.name + ': ' + a + (r.ok ? ' done' : ' failed') + ' — now ' + r.active + ', boot ' + r.enabled + (r.output ? '\n' + r.output : '')); load(); }).catch(fail);
      });
    }
    function status(n) { Promise.all([api('svc.status', { name: n }), api('svc.deps', { name: n })]).then(function (x) { dialog(n, el('div', {}, [pre(x[0].status, true), el('details', { cls: 'mt-2' }, [el('summary', { text: 'Dependencies' }), el('div', { cls: 'row' }, [el('div', { cls: 'col-6' }, [el('strong', { text: 'Needs' }), pre(x[1].requires, true)]), el('div', { cls: 'col-6' }, [el('strong', { text: 'Needed by' }), pre(x[1].required_by, true)])])])]), [], true); }).catch(fail); }
    function logs(n) { api('svc.logs', { name: n, lines: 300 }).then(function (r) { dialog('Logs of ' + n, pre(r.lines.join('\n') || r.error || '(empty — reading the system journal may need administrator rights)'), [], true); }).catch(fail); }
    f.addEventListener('input', draw); onlyActive.input.addEventListener('change', draw);
    setPage([el('div', { cls: 'wsm-toolbar' }, [f, onlyActive, btn('', 'bi-arrow-repeat', null, load, 'Reload')]), box]);
    load();
  }

  // ======================================================================
  //  LOGS
  // ======================================================================
  function pageLogs() {
    var srcSel = el('select', { cls: 'form-select form-select-sm' }), lines = input({ type: 'number', value: 200, min: 10, max: 5000, style: 'width:90px' }), grep = input({ placeholder: 'filter text' }),
      since = input({ placeholder: 'journal: e.g. 2 hours ago, 2026-11-06' }), prio = select([['', 'any severity'], ['err', 'errors'], ['warning', 'warnings+'], ['info', 'info+']], ''), unit = input({ placeholder: 'journal unit (optional)' }),
      live = check('Live (refresh every 5 s)', false), out = pre(''), timer = null, last = [];
    function read() {
      var v = srcSel.value; if (!v) return;
      var p = v === '__journal__' ? api('journal.read', { lines: +lines.value, grep: grep.value, since: since.value, priority: prio.value, unit: unit.value })
        : api('logs.read', { path: v, lines: +lines.value, grep: grep.value });
      p.then(function (r) { last = r.lines; out.innerHTML = ''; last.forEach(function (l) { var s = el('span', { text: l + '\n' }); if (/\b(error|crit|alert|emerg|fail(ed)?|denied)\b/i.test(l)) s.className = 'wsm-err-line'; out.appendChild(s); }); out.scrollTop = out.scrollHeight; if (r.error) flash('warn', r.error); })
        .catch(function (e) { out.textContent = e.message; });
    }
    live.input.addEventListener('change', function () { clearInterval(timer); if (live.input.checked) timer = setInterval(read, 5000); });
    srcSel.addEventListener('change', read);
    api('logs.sources', {}).then(function (r) {
      srcSel.appendChild(el('option', { value: '', text: 'Pick a log…' }));
      if (r.journal) srcSel.appendChild(el('option', { value: '__journal__', text: 'System journal (journalctl)' }));
      r.files.forEach(function (f) { srcSel.appendChild(el('option', { value: f.path, text: f.label + ' — ' + f.path + ' (' + size(f.size) + ')' + (f.readable ? '' : ' [needs root]') })); });
    }).catch(fail);
    setPage([el('div', { cls: 'wsm-toolbar' }, [srcSel, lines, grep, btn('Show', 'bi-eye', 'btn-fw-primary', read), live,
      btn('Download', 'bi-download', null, function () { download('log-' + (srcSel.value.split('/').pop() || 'journal') + '.txt', last.join('\n') + '\n'); })]),
      el('div', { cls: 'wsm-toolbar' }, [el('span', { cls: 'wsm-small text-muted', text: 'Journal filters:' }), since, prio, unit]), out,
      el('p', { cls: 'wsm-small text-muted mt-2' }, ['The log of what SATOM did on this server, with users and sudo: ', el('a', { href: CFG.base.replace(/[^/]+\/$/, '') + 'audit?slug=' + CFG.slug, text: 'Operations log' })])]);
  }

  // ======================================================================
  //  USERS & PERMISSIONS
  // ======================================================================
  function pageUsers() {
    var box = el('div'), all = check('Show system accounts', false), data = null;
    function load() {
      box.innerHTML = ''; box.appendChild(loading());
      api('users.list', { all: all.input.checked }).then(function (r) { data = r; draw(); }).catch(function (e) { box.innerHTML = ''; fail(e); });
    }
    function draw() {
      box.innerHTML = '';
      if (!data.complete) box.appendChild(el('div', { cls: 'wsm-msg warn', text: 'Locked/unlocked state needs administrator rights (Run as: Administrator).' }));
      box.appendChild(table(['Account', 'UID', 'Groups', 'Shell', 'Home', 'State', ''], data.users.map(function (u) {
        return [el('div', {}, [el('strong', { text: u.name }), u.admin ? badge('admin', 'wsm-root') : null, el('div', { cls: 'wsm-small text-muted', text: u.comment })]), u.uid, el('span', { cls: 'wsm-small', text: [u.primary_group].concat(u.groups).join(', ') }), el('span', { cls: 'wsm-mono', text: u.shell }), el('span', { cls: 'wsm-mono', text: u.home }),
          u.locked == null ? '?' : u.locked ? badge('locked', 'wsm-bad') : badge('active', 'wsm-ok'),
          u.uid === 0 ? '' : el('div', { cls: 'd-flex gap-1' }, [btn('', 'bi-pencil', null, function () { edit(u); }, 'Edit'), btn('', 'bi-trash', 'btn-outline-danger', function () { delUser(u); }, 'Delete')])];
      })));
      box.appendChild(card('Groups', 'bi-collection', [table(['Group', 'GID', 'Members', ''], data.groups.map(function (g) { return [g.name, g.gid, g.members.join(', '), g.gid >= 1000 ? btn('', 'bi-trash', 'btn-outline-danger', function () { confirmBox({ text: 'Delete group ' + g.name + '?', danger: true, typed: g.name }).then(function (ok) { if (ok && needWrites()) api('group.del', { name: g.name }, { runAs: 'root' }).then(function () { flash('ok', 'Deleted.'); load(); }).catch(fail); }); }) : '']; })),
        btn('New group', 'bi-plus-lg', null, function () { var n = input({}); dialog('New group', field('Name', n), [btn('Create', 'bi-check', 'btn-fw-primary', function () { if (needWrites()) api('group.add', { name: n.value }, { runAs: 'root' }).then(function () { modal('wsm-dialog').hide(); load(); }).catch(fail); })], false); })], 'mt-3'));
    }
    function edit(u) {
      var isNew = !u; u = u || { name: '', shell: '/bin/bash', groups: [] };
      var name = input({ value: u.name, disabled: !isNew }), shell = select(data.shells.length ? data.shells : ['/bin/bash', '/bin/sh', '/usr/sbin/nologin'], u.shell), groups = input({ value: (u.groups || []).join(', '), placeholder: 'e.g. www-data, sudo' }),
        pw = input({ type: 'password', autocomplete: 'new-password', placeholder: isNew ? 'initial password (8+ characters)' : 'new password (leave empty to keep)' }), lock = select([['', 'leave as is'], ['1', 'lock (cannot sign in)'], ['0', 'unlock']], ''), comment = input({ value: u.comment || '' });
      dialog(isNew ? 'New account' : 'Account ' + u.name, el('div', {}, [field('Name', name), field('Full name / comment', comment), field('Shell', shell), field('Groups (comma-separated)', groups, 'sudo / wheel make the account an administrator.'), field('Password', pw), isNew ? null : field('Sign-in', lock)]), [btn('Save', 'bi-save', 'btn-fw-primary', function () {
        if (!needWrites()) return;
        var g = groups.value.split(/[\s,]+/).filter(Boolean), p;
        if (isNew) p = api('user.add', { name: name.value, shell: shell.value, groups: g, password: pw.value, comment: comment.value }, { runAs: 'root' });
        else p = api('user.mod', { name: u.name, shell: shell.value !== u.shell ? shell.value : '', add_groups: g.filter(function (x) { return u.groups.indexOf(x) < 0; }), remove_groups: u.groups.filter(function (x) { return g.indexOf(x) < 0; }), password: pw.value, lock: lock.value === '' ? null : lock.value === '1' }, { runAs: 'root' });
        p.then(function () { pw.value = ''; modal('wsm-dialog').hide(); flash('ok', 'Saved.'); load(); }).catch(fail);
      })], false);
    }
    function delUser(u) {
      var home = check('Also delete the home folder ' + u.home, false);
      confirmBox({ title: 'Delete account', node: el('div', {}, [el('p', { text: 'Delete the account ' + u.name + '?' }), home]), danger: true, typed: u.name }).then(function (ok) {
        if (ok && needWrites()) api('user.del', { name: u.name, remove_home: home.input.checked }, { runAs: 'root' }).then(function () { flash('ok', 'Deleted.'); load(); }).catch(fail);
      });
    }
    all.input.addEventListener('change', load);
    setPage([el('div', { cls: 'wsm-toolbar' }, [btn('New account', 'bi-person-plus', 'btn-fw-primary', function () { edit(null); }), all, btn('', 'bi-arrow-repeat', null, load, 'Reload'), el('span', { cls: 'wsm-small text-muted', text: 'Changes to accounts always run as root (sudo).' })]), box]);
    load();
  }

  // ======================================================================
  //  SSH CONFIGURATION
  // ======================================================================
  function pageSsh() {
    var box = el('div'), keysBox = el('div'), who = input({ placeholder: 'account (empty = the signed-in account)', style: 'width:320px' });
    var LABELS = { Port: 'Port', PermitRootLogin: 'Root can sign in', PasswordAuthentication: 'Passwords accepted', PubkeyAuthentication: 'Keys accepted', KbdInteractiveAuthentication: 'Keyboard-interactive', ChallengeResponseAuthentication: 'Challenge-response', MaxAuthTries: 'Attempts per connection', LoginGraceTime: 'Time to sign in', AllowUsers: 'Only these users', AllowGroups: 'Only these groups', DenyUsers: 'Never these users', DenyGroups: 'Never these groups', X11Forwarding: 'X11 forwarding', AllowTcpForwarding: 'TCP forwarding', ClientAliveInterval: 'Keep-alive (s)', ClientAliveCountMax: 'Keep-alive misses', PermitEmptyPasswords: 'Empty passwords', UsePAM: 'Use PAM', Banner: 'Banner file' };
    var CHOICES = { PermitRootLogin: ['yes', 'prohibit-password', 'without-password', 'forced-commands-only', 'no'], PasswordAuthentication: ['yes', 'no'], PubkeyAuthentication: ['yes', 'no'], KbdInteractiveAuthentication: ['yes', 'no'], ChallengeResponseAuthentication: ['yes', 'no'], X11Forwarding: ['yes', 'no'], AllowTcpForwarding: ['yes', 'no', 'local', 'remote'], PermitEmptyPasswords: ['no', 'yes'], UsePAM: ['yes', 'no'] };
    function load() {
      box.innerHTML = ''; box.appendChild(loading());
      api('sshd.get', {}, { runAs: 'root' }).then(function (r) {
        box.innerHTML = '';
        var ctrls = {};
        var grid = el('div', { cls: 'row g-2' });
        Object.keys(LABELS).forEach(function (k) {
          var v = r.effective[k] || ''; var c = CHOICES[k] ? select([['', '(default)']].concat(CHOICES[k]), v) : input({ value: v });
          ctrls[k] = [c, v]; grid.appendChild(el('div', { cls: 'col-md-4' }, [field(LABELS[k] + ' (' + k + ')', c)]));
        });
        box.append(card('SSH server (sshd)', 'bi-key', [el('p', { cls: 'wsm-small text-muted', text: 'Values shown are what sshd uses now. Saving backs up sshd_config, tests it with sshd -t, restores it if the test fails and reloads sshd (open sessions stay).' }), grid,
          el('details', { cls: 'wsm-advanced-only mt-2' }, [el('summary', { text: '/etc/ssh/sshd_config' }), pre(r.content, true)]),
          btn('Save', 'bi-save', 'btn-fw-primary', function () {
            var changes = {}; Object.keys(ctrls).forEach(function (k) { if (ctrls[k][0].value !== ctrls[k][1] && ctrls[k][0].value !== '') changes[k] = ctrls[k][0].value; });
            if (!Object.keys(changes).length) return flash('warn', 'Nothing changed.');
            var c = currentCred(), warn = '';
            if (changes.PasswordAuthentication === 'no' && c && c.auth_type === 'password') warn += ' Your credential signs in with a PASSWORD: after this, SATOM (and you) can no longer sign in with it. Add a key first.';
            if (changes.Port) warn += ' Changing the port: update the server port in SATOM and the firewall, or you lose access.';
            if (changes.AllowUsers && c && changes.AllowUsers.split(/\s+/).indexOf(c.ssh_user) < 0) warn += ' ' + c.ssh_user + ' is not in AllowUsers: you would lock yourself out.';
            confirmBox({ title: 'Change the SSH server', node: el('div', {}, [pre(JSON.stringify(changes, null, 1), true), warn ? el('div', { cls: 'wsm-msg err mt-2', text: warn }) : null]), danger: true, typed: 'SSH' }).then(function (ok) {
              if (ok && needWrites()) api('sshd.set', { settings: changes, base_sha256: r.sha256 }, { runAs: 'root' }).then(function (x) { if (x.restored) flash('err', 'sshd -t failed, restored: ' + x.test_output); else flash('ok', 'Saved, tested and sshd reloaded.'); load(); }).catch(fail);
            });
          })]));
      }).catch(function (e) { box.innerHTML = ''; box.appendChild(el('div', { cls: 'wsm-msg err', text: e.message })); });
    }
    function keys() {
      keysBox.innerHTML = ''; keysBox.appendChild(loading());
      api('authkeys.get', { user: who.value }).then(function (r) {
        var lines = r.keys.map(function (k) { return k.line; });
        keysBox.innerHTML = '';
        var add = el('textarea', { cls: 'form-control form-control-sm wsm-mono', rows: 2, placeholder: 'ssh-ed25519 AAAA... comment' });
        keysBox.append(card('Authorized keys of ' + r.user, 'bi-key-fill', [table(['Type', 'Fingerprint', 'Comment', ''], r.keys.map(function (k, i) { return [k.type, el('span', { cls: 'wsm-mono', text: k.fingerprint }), k.comment + (k.options ? ' (with options)' : ''), btn('', 'bi-trash', 'btn-outline-danger', function () { confirmBox({ text: 'Remove this key? If it is the key you sign in with, you lose access.', danger: true }).then(function (ok) { if (ok && needWrites()) { lines.splice(i, 1); api('authkeys.put', { user: who.value, keys: lines, base_sha256: r.sha256 }).then(function () { flash('ok', 'Removed.'); keys(); }).catch(fail); } }); })]; }), { empty: 'No key.' }),
          field('Add a public key', add), btn('Add', 'bi-plus-lg', 'btn-fw-primary', function () { if (!needWrites()) return; lines.push(add.value.trim()); api('authkeys.put', { user: who.value, keys: lines, base_sha256: r.sha256 }).then(function () { flash('ok', 'Added.'); keys(); }).catch(fail); })], 'mt-3'));
      }).catch(function (e) { keysBox.innerHTML = ''; fail(e); });
    }
    setPage([box, el('div', { cls: 'wsm-toolbar mt-3' }, [who, btn('Show keys', 'bi-arrow-right', null, keys)]), keysBox]);
    load(); keys();
  }

  // ---------- boot -------------------------------------------------------------
  fillCreds();
  var PAGES = { home: pageHome, files: pageFiles, sites: pageSites, certs: pageCerts, security: pageSecurity, htaccess: pageHtaccess, scripts: pageScripts, cron: pageCron, packages: pagePackages, services: pageServices, logs: pageLogs, users: pageUsers, ssh: pageSsh };
  if (PAGES[PAGE]) {
    if (PAGE !== 'home' && !currentCred()) setPage([el('div', { cls: 'wsm-msg warn' }, [el('div', {}, ['No credential to sign in with. ', el('a', { href: CFG.base, text: 'Add your SSH account on the Overview' }), '.'])])]);
    else if (PAGE !== 'home' && !CFG.trusted) setPage([el('div', { cls: 'wsm-msg err' }, [el('div', {}, ['SATOM has not trusted this server\'s host key yet. ', el('a', { href: CFG.base, text: 'Trust it on the Overview' }), '.'])])]);
    else PAGES[PAGE]();
  }
})();
