// HTTP Observatory — the PAGE at /observatory/ (Troubleshooting).
//
// Lists the sites an appliance publishes (FortiWeb server policies, FortiADC
// virtual servers) in a searchable checkbox picker — an appliance can publish
// hundreds, so the table only holds the ticked ones — grades them through /observatory/api/scan, renders each
// test with WHO produced it (FortiWeb / application / certificate) and lets an
// operator with config_write tick FortiWeb fixes, preview the writes and the
// grade they would give, and apply them (the site is graded again after).
//
// Light chrome ONLY (docs/safeguards.md §9m). CSP-safe: no inline handlers,
// everything the server returns goes through esc() or textContent.
// Turbo Drive re-runs this script on every visit: the definitions run once,
// init() runs on every visit that lands on the page.
(function () {
  if (!window.FWObservatory) {
    function esc(s) {
      return String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }
    function $(id) { return document.getElementById(id); }

    let state = { appliance: null, targets: [], picked: new Set(), current: null, busy: false };

    function req(method, url, body) {
      const opts = { method: method, headers: { Accept: 'application/json' } };
      if (body !== undefined) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
      }
      const meta = document.querySelector('meta[name="csrf-token"]');
      if (meta && meta.content) opts.headers['X-CSRFToken'] = meta.content;
      return fetch(url, opts).then(r => r.json().catch(() => ({ ok: false, error: 'HTTP ' + r.status }))
        .then(d => ({ status: r.status, d: d })));
    }

    function gradeClass(g) {
      if (!g) return 'fw-badge-secondary';
      if (g.charAt(0) === 'A') return 'fw-badge-success';
      if (g.charAt(0) === 'B') return 'fw-badge-info';
      if (g.charAt(0) === 'C') return 'fw-badge-warning';
      return 'fw-badge-danger';
    }
    function gradeBadge(g, big) {
      return '<span class="fw-badge ' + gradeClass(g) + ' fw-badge-nowrap"' +
        (big ? ' style="font-size:22px;padding:6px 14px;font-weight:700"' : ' style="font-weight:700"') +
        '>' + esc(g || '—') + '</span>';
    }
    const WHO = {
      fortiweb: ['fw-badge-primary', 'FortiWeb'],
      application: ['fw-badge-secondary', 'Application'],
      certificate: ['fw-badge-warning', 'Certificate'],
      missing: ['fw-badge-danger', 'Not sent']
    };
    function whoBadge(w) {
      const m = WHO[w];
      return m ? '<span class="fw-badge ' + m[0] + ' fw-badge-nowrap">' + esc(m[1]) + '</span>' : '';
    }
    function modBadge(m) {
      if (m > 0) return '<span class="fw-badge fw-badge-success">+' + esc(m) + '</span>';
      if (m < 0) return '<span class="fw-badge fw-badge-danger">' + esc(m) + '</span>';
      return '<span class="fw-badge fw-badge-secondary">0</span>';
    }
    function when(iso) {
      if (!iso) return '';
      const d = new Date(iso);
      return isNaN(d) ? esc(iso) : esc(d.toLocaleString());
    }

    // ------------------------------------------------------------------ sites
    function loadTargets() {
      const sel = $('fw-obs-appliance');
      if (!sel) return;
      state.appliance = sel.value;
      $('fw-obs-err').textContent = '';
      $('fw-obs-targets').innerHTML = '<div class="text-muted small"><span class="spinner-border spinner-border-sm me-2"></span>Reading the appliance…</div>';
      req('GET', '/observatory/api/targets?appliance_id=' + encodeURIComponent(state.appliance)).then(r => {
        if (!r.d.ok) {
          $('fw-obs-targets').innerHTML = '';
          $('fw-obs-err').textContent = r.d.error || 'Could not list the sites.';
          return;
        }
        state.targets = r.d.targets || [];
        const known = new Set(state.targets.map(t => t.policy));
        state.picked = new Set(loadPicked().filter(x => known.has(x)));
        const pre = $('fw-obs-page').dataset.prefillPolicy;
        if (pre && known.has(pre)) state.picked.add(pre);
        savePicked();
        $('fw-obs-picksearch').value = '';
        renderPicker();
        renderTargets();
        if (pre) {
          $('fw-obs-page').dataset.prefillPolicy = '';
          const t = state.targets.find(x => x.policy === pre);
          if (t && t.last) view(t.last.id);
        }
      });
    }

    // ----------------------------------------------------------------- picker
    // The ticked set is state.picked — never read back from the DOM — so the
    // search can hide items freely without unticking them. Kept per
    // appliance in localStorage: the operator's working set survives a visit.
    function pickKey() { return 'satom.observatory.picked.' + state.appliance; }
    function loadPicked() {
      try { const v = JSON.parse(localStorage.getItem(pickKey()) || '[]'); return Array.isArray(v) ? v.map(String) : []; }
      catch (e) { return []; }
    }
    function savePicked() {
      try { localStorage.setItem(pickKey(), JSON.stringify(Array.from(state.picked))); } catch (e) { /* private mode */ }
    }

    function renderPicker() {
      const btn = $('fw-obs-pickbtn');
      btn.disabled = !state.targets.length;
      $('fw-obs-picklist').innerHTML = state.targets.map((t, i) => {
        const id = 'fw-obs-pk-' + i;
        const text = [t.policy, t.default_host, t.vip].concat(t.hosts || []).join(' ').toLowerCase();
        const last = t.last && t.last.grade ? ' ' + gradeBadge(t.last.grade) : '';
        return '<div class="form-check fw-obs-pickitem py-1" data-text="' + esc(text) + '">' +
          '<input type="checkbox" class="form-check-input" id="' + id + '" data-policy="' + esc(t.policy) + '"' +
          (state.picked.has(t.policy) ? ' checked' : '') + '>' +
          '<label class="form-check-label small w-100 d-flex align-items-center gap-2" for="' + id + '">' +
          '<span class="fw-mono text-truncate">' + esc(t.policy) + '</span>' +
          '<span class="text-muted text-truncate">' + esc(t.default_host || '') + '</span>' +
          '<span class="ms-auto text-nowrap">' + (t.scannable ? '' : '<span class="text-muted">not scannable</span>') + last + '</span>' +
          '</label></div>';
      }).join('') + '<div class="text-muted small py-1" id="fw-obs-picknomatch" style="display:none">No site matches.</div>';
      filterPicker();
    }

    function filterPicker() {
      const f = ($('fw-obs-picksearch').value || '').trim().toLowerCase();
      let shown = 0;
      document.querySelectorAll('#fw-obs-picklist .fw-obs-pickitem').forEach(el => {
        const hit = !f || el.getAttribute('data-text').indexOf(f) >= 0;
        el.style.display = hit ? '' : 'none';
        if (hit) shown++;
      });
      const nm = $('fw-obs-picknomatch');
      if (nm) nm.style.display = shown || !state.targets.length ? 'none' : '';
      updatePickSummary(shown);
    }

    function updatePickSummary(shown) {
      const n = state.picked.size, total = state.targets.length;
      let sum;
      if (!total) sum = 'No published sites';
      else if (!n) sum = 'Select sites (' + total + ')';
      else if (n === 1) sum = Array.from(state.picked)[0];
      else sum = n + ' of ' + total + ' sites selected';
      $('fw-obs-picksum').textContent = sum;
      $('fw-obs-pickcount').textContent = n + ' selected' +
        (shown !== undefined && shown !== total ? ' · ' + shown + ' shown' : '');
      const todo = state.targets.filter(t => t.scannable && state.picked.has(t.policy)).length;
      const all = $('fw-obs-scanall');
      if (!state.busy) {
        all.disabled = !todo;
        all.innerHTML = '<i class="bi bi-play-fill me-1"></i>Grade selected' + (todo ? ' (' + todo + ')' : '');
      }
    }

    function setPicked(policy, on) {
      if (on) state.picked.add(policy); else state.picked.delete(policy);
      const cb = Array.from(document.querySelectorAll('#fw-obs-picklist input[data-policy]'))
        .find(x => x.getAttribute('data-policy') === policy);
      if (cb) cb.checked = on;
    }

    function pickChanged() {
      savePicked();
      filterPicker();
      renderTargets();
    }

    function renderTargets() {
      // Only the ticked sites, in the appliance's order.
      const rows = state.targets.filter(t => state.picked.has(t.policy));
      if (!state.targets.length) {
        $('fw-obs-targets').innerHTML = '<div class="text-muted small">This appliance publishes no sites.</div>';
        return;
      }
      if (!rows.length) {
        $('fw-obs-targets').innerHTML = '<div class="text-muted small"><i class="bi bi-check2-square me-1"></i>' +
          esc(state.targets.length) + ' published site' + (state.targets.length === 1 ? '' : 's') +
          '. Tick the ones to grade in <strong>Select sites</strong>; they appear here.</div>';
        return;
      }
      let h = '<div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr>' +
        '<th>Policy</th><th style="min-width:200px">Site name</th><th>Ports</th><th>Grade</th><th>Last graded</th><th></th></tr></thead><tbody>';
      rows.forEach(t => {
        const ports = [];
        if (t.http_port) ports.push('HTTP ' + t.http_port);
        if (t.https_port) ports.push('HTTPS ' + t.https_port);
        const last = t.last;
        h += '<tr data-policy="' + esc(t.policy) + '">' +
          '<td class="fw-mono small">' + esc(t.policy) + (t.vip ? '<div class="text-muted small">VIP ' + esc(t.vip) + '</div>' : '') + '</td>' +
          '<td><input class="form-control form-control-sm fw-obs-host" value="' + esc(t.host_edit !== undefined ? t.host_edit : (t.default_host || '')) + '"' +
          (t.scannable ? '' : ' disabled') + ' list="fw-obs-hosts-' + esc(t.policy) + '">' +
          '<datalist id="fw-obs-hosts-' + esc(t.policy) + '">' + (t.hosts || []).map(x => '<option value="' + esc(x) + '">').join('') + '</datalist></td>' +
          '<td class="small">' + esc(ports.join(' · ') || '—') + '</td>' +
          '<td class="fw-obs-grade">' + (last ? (last.grade ? gradeBadge(last.grade) + ' <span class="small text-muted">' + esc(last.score) + '</span>'
            : '<span class="small text-danger" title="' + esc(last.error) + '">not graded</span>') : '<span class="text-muted small">—</span>') + '</td>' +
          '<td class="small text-muted fw-obs-when">' + (last ? when(last.started_at) : '') + '</td>' +
          '<td class="text-end text-nowrap">' +
          (t.scannable ? '<button type="button" class="btn btn-sm btn-fw-outline fw-obs-scan"><i class="bi bi-play-fill"></i> Grade</button> '
            : '<span class="small text-muted">' + esc(t.note || 'not scannable') + '</span> ') +
          (last ? '<button type="button" class="btn btn-sm btn-fw-outline fw-obs-view" data-scan="' + esc(last.id) + '"><i class="bi bi-eye"></i></button> ' : '') +
          '<button type="button" class="btn btn-sm btn-fw-outline fw-obs-unpick" title="Remove from the selection"><i class="bi bi-x-lg"></i></button>' +
          '</td></tr>';
      });
      h += '</tbody></table></div>';
      $('fw-obs-targets').innerHTML = h;
    }

    function rowOf(policy) {
      return Array.from(document.querySelectorAll('#fw-obs-targets tr[data-policy]'))
        .find(tr => tr.getAttribute('data-policy') === policy);
    }

    function scan(policy, quiet) {
      const tr = rowOf(policy);
      const host = tr ? (tr.querySelector('.fw-obs-host') || {}).value || '' : '';
      if (tr) tr.querySelector('.fw-obs-grade').innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
      return req('POST', '/observatory/api/scan', {
        appliance_id: state.appliance, policy: policy, host: host
      }).then(r => {
        if (!r.d.ok) {
          if (tr) tr.querySelector('.fw-obs-grade').innerHTML = '<span class="small text-danger">' + esc(r.d.error) + '</span>';
          return r.d;
        }
        const t = state.targets.find(x => x.policy === policy);
        if (t) t.last = r.d.scan;
        if (tr) {
          tr.querySelector('.fw-obs-grade').innerHTML = r.d.scan.grade
            ? gradeBadge(r.d.scan.grade) + ' <span class="small text-muted">' + esc(r.d.scan.score) + '</span>'
            : '<span class="small text-danger" title="' + esc(r.d.scan.error) + '">not graded</span>';
          tr.querySelector('.fw-obs-when').innerHTML = when(r.d.scan.started_at);
        }
        if (!quiet) renderResult(r.d);
        return r.d;
      });
    }

    function scanAll() {
      if (state.busy) return;
      state.busy = true;
      const btn = $('fw-obs-scanall');
      const todo = state.targets.filter(t => t.scannable && state.picked.has(t.policy)).map(t => t.policy);
      if (!todo.length) { state.busy = false; return; }
      btn.disabled = true;
      let i = 0;
      function next() {
        if (i >= todo.length) {
          state.busy = false;
          renderPicker();
          renderTargets();
          return;
        }
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>' + (i + 1) + ' / ' + todo.length;
        scan(todo[i++], true).then(next, next);
      }
      next();
    }

    function view(id) {
      req('GET', '/observatory/api/scan/' + encodeURIComponent(id)).then(r => {
        if (r.d.ok) renderResult(r.d);
        else $('fw-obs-err').textContent = r.d.error || 'Could not load the scan.';
      });
    }

    // ----------------------------------------------------------------- result
    function renderResult(v) {
      state.current = v;
      const card = $('fw-obs-resultcard');
      card.style.display = '';
      const s = v.scan;
      const tgt = v.target || {};
      $('fw-obs-resultsite').textContent = (tgt.appliance || '') + ' · ' + s.policy + ' · ' + (s.host || '');
      const autoUrl = ((v.retrieval || {}).auto_url) || '';
      $('fw-obs-trace').href = '/txn-trace/?vip=' + encodeURIComponent(autoUrl || ('https://' + (tgt.vip || '')));
      let h = '<div class="d-flex align-items-center gap-3 flex-wrap">' + gradeBadge(s.grade, true);
      if (s.grade) {
        h += '<div><div class="fw-bold">' + esc(s.score) + ' / 100</div><div class="small text-muted">' +
          esc(s.tests_passed) + ' of ' + esc((s.tests_passed || 0) + (s.tests_failed || 0)) + ' tests passed · ' + when(s.started_at) +
          ' · ' + esc(s.trigger) + '</div></div>';
      } else {
        h += '<div class="text-danger">' + esc(s.error || 'Not graded.') + '</div>';
      }
      if (v.previous && v.previous.grade && s.grade) {
        h += '<div class="small text-muted">previous: ' + gradeBadge(v.previous.grade) + ' ' + esc(v.previous.score) + '</div>';
      }
      if (v.if_certificate_trusted) {
        h += '<div class="small"><span class="fw-badge fw-badge-warning">Certificate</span> with a trusted certificate this site would score ' +
          gradeBadge(v.if_certificate_trusted.grade) + ' ' + esc(v.if_certificate_trusted.score) + '</div>';
      }
      h += '</div>';
      const ret = v.retrieval || {};
      const tls = ret.tls || null;
      const notes = [];
      if (tls && tls.verified === false) notes.push('Certificate not trusted by this node: ' + (tls.verify_error || '?') + (tls.cn ? ' (CN ' + tls.cn + ')' : ''));
      ['http', 'https'].forEach(k => {
        const route = ret[k + '_route'] || [];
        if (route.length) notes.push(k.toUpperCase() + ': ' + route.map(x => x.url + (x.status ? ' [' + x.status + ']' : ' [not followed: outside this policy]')).join(' → '));
        if ((ret.errors || {})[k]) notes.push(k.toUpperCase() + ' error: ' + ret.errors[k]);
      });
      if (v.context_error) notes.push(v.context_error);
      if (v.context) notes.push('Web Protection Profile: ' + (v.context.wpp || 'none') + ' · HTTP Header Security: ' + (v.context.hhs || 'none') +
        ' · Cookie Security: ' + (v.context.cks || 'none') + ' · FortiWeb ' + (v.context.version || '?'));
      if (notes.length) h += '<ul class="small text-muted mt-2 mb-0">' + notes.map(n => '<li>' + esc(n) + '</li>').join('') + '</ul>';
      $('fw-obs-summary').innerHTML = h;
      renderTests(v);
      const fixcard = $('fw-obs-fixcard');
      if (fixcard) {
        const any = (v.findings || []).some(f => (f.fixes || []).some(x => x.available && !x.link));
        fixcard.style.display = any ? '' : 'none';
        $('fw-obs-plan').innerHTML = '';
        $('fw-obs-applyout').innerHTML = '';
        $('fw-obs-apply').disabled = true;
        $('fw-obs-ackwrap').style.display = 'none';
        updateFixCount();
      }
      card.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function optionsHtml(fx) {
      const o = fx.option || {};
      const id = 'fw-obs-o-' + fx.id.replace(/[^a-z0-9]/gi, '-');
      if (fx.id === 'header:content-security-policy') {
        return '<textarea class="form-control form-control-sm fw-mono mt-1 fw-obs-opt" data-k="value" id="' + id + '" rows="2">' + esc(o.default || '') + '</textarea>';
      }
      if (o.choices && o.choices.length) {
        return '<select class="form-select form-select-sm mt-1 fw-obs-opt" data-k="value" style="width:auto">' +
          o.choices.map(c => '<option' + (c === o.default ? ' selected' : '') + '>' + esc(c) + '</option>').join('') + '</select>';
      }
      if (fx.id === 'hsts') {
        return '<div class="d-flex gap-2 align-items-center mt-1 flex-wrap small">max-age <input type="number" min="1" class="form-control form-control-sm fw-obs-opt" data-k="max_age" style="width:130px" value="' + esc(o.max_age) + '">' +
          '<label><input type="checkbox" class="form-check-input fw-obs-opt" data-k="include_subdomains"' + (o.include_subdomains ? ' checked' : '') + '> includeSubDomains</label>' +
          '<label><input type="checkbox" class="form-check-input fw-obs-opt" data-k="preload"' + (o.preload ? ' checked' : '') + '> preload</label></div>';
      }
      if (fx.id === 'cookie-security') {
        return '<div class="d-flex gap-2 align-items-center mt-1 flex-wrap small">' +
          '<label><input type="checkbox" class="form-check-input fw-obs-opt" data-k="secure"' + (o.secure ? ' checked' : '') + '> Secure</label>' +
          '<label><input type="checkbox" class="form-check-input fw-obs-opt" data-k="http_only"' + (o.http_only ? ' checked' : '') + '> HttpOnly</label>' +
          'SameSite <select class="form-select form-select-sm fw-obs-opt" data-k="samesite" style="width:auto">' +
          ['Lax', 'Strict', 'None'].map(c => '<option' + (c === o.samesite ? ' selected' : '') + '>' + c + '</option>').join('') + '</select></div>';
      }
      return '';
    }

    function renderTests(v) {
      const mayFix = $('fw-obs-page').dataset.mayFix === '1';
      const findings = v.findings && v.findings.length ? v.findings
        : ((v.analysis || {}).tests || []).map(t => ({ test: t.name, title: t.title, result: t.result, modifier: t.modifier, pass: t.pass, fixes: [] }));
      const byName = {};
      ((v.analysis || {}).tests || []).forEach(t => { byName[t.name] = t; });
      if (!findings.length) { $('fw-obs-tests').innerHTML = ''; return; }
      let h = '<div class="table-responsive"><table class="table table-sm align-top mb-0"><thead><tr>' +
        '<th>Test</th><th></th><th>Result</th><th>Who</th><th style="min-width:300px">Why and what to do</th></tr></thead><tbody>';
      findings.forEach(f => {
        const t = byName[f.test] || {};
        h += '<tr><td class="text-nowrap"><a href="' + esc(t.link || '#') + '" target="_blank" rel="noopener noreferrer">' + esc(f.title || f.test) + '</a>' +
          '<div class="small">' + (f.pass ? '<span class="text-success"><i class="bi bi-check-circle"></i> pass</span>' : '<span class="text-danger"><i class="bi bi-x-circle"></i> fail</span>') + '</div></td>' +
          '<td>' + modBadge(f.modifier) + '</td>' +
          '<td class="small">' + esc(t.description || f.result) + (t.recommendation ? '<div class="text-muted">' + esc(t.recommendation) + '</div>' : '') + '</td>' +
          '<td>' + whoBadge(f.who) + '</td><td class="small">' + esc(f.explain || '');
        (f.fixes || []).forEach(fx => {
          if (fx.link) {
            h += '<div class="mt-1"><a class="btn btn-sm btn-fw-outline" href="' + esc(fx.link) + '"><i class="bi bi-patch-check me-1"></i>' + esc(fx.label) + '</a></div>';
          } else if (!fx.available) {
            h += '<div class="mt-1 text-muted"><i class="bi bi-slash-circle me-1"></i>' + esc(fx.label) + ': ' + esc(fx.why_not) + '</div>';
          } else if (mayFix) {
            h += '<div class="mt-2 p-2 border rounded fw-obs-fix" data-fix="' + esc(fx.id) + '">' +
              '<label class="fw-bold"><input type="checkbox" class="form-check-input me-1 fw-obs-pick"> ' + esc(fx.label) + '</label>' +
              optionsHtml(fx) + (fx.risk ? '<div class="text-muted mt-1"><i class="bi bi-exclamation-triangle me-1"></i>' + esc(fx.risk) + '</div>' : '') + '</div>';
          } else {
            h += '<div class="mt-1 text-muted"><i class="bi bi-wrench me-1"></i>' + esc(fx.label) + ' (needs config write)</div>';
          }
        });
        h += '</td></tr>';
      });
      h += '</tbody></table></div>';
      $('fw-obs-tests').innerHTML = h;
    }

    // -------------------------------------------------------------------- fix
    function pickedItems() {
      return Array.from(document.querySelectorAll('.fw-obs-fix')).filter(d => d.querySelector('.fw-obs-pick').checked).map(d => {
        const opts = {};
        d.querySelectorAll('.fw-obs-opt').forEach(el => {
          const k = el.getAttribute('data-k');
          if (el.type === 'checkbox') opts[k] = el.checked;
          else if (el.type === 'number') opts[k] = parseInt(el.value, 10) || 0;
          else opts[k] = el.value;
        });
        return { fix: d.getAttribute('data-fix'), options: opts };
      });
    }
    function updateFixCount() {
      const n = pickedItems().length;
      const c = $('fw-obs-fixcount');
      if (c) c.textContent = n ? n + ' selected' : '';
      const ap = $('fw-obs-apply');
      if (ap) ap.disabled = true;
    }

    function preview() {
      const items = pickedItems();
      if (!items.length) { $('fw-obs-plan').innerHTML = '<div class="text-danger small">Tick at least one fix in the result.</div>'; return; }
      $('fw-obs-plan').innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
      req('POST', '/observatory/api/plan', { scan_id: state.current.scan.id, items: items }).then(r => {
        if (!r.d.ok) {
          $('fw-obs-plan').innerHTML = '<div class="text-danger small">' + esc(r.d.error) + '</div>';
          $('fw-obs-apply').disabled = true;
          return;
        }
        const p = r.d.plan, pr = r.d.projection || {};
        let h = '<div class="mb-2">Grade now ' + gradeBadge(r.d.current.grade) + ' ' + esc(r.d.current.score) +
          ' → after these fixes ' + gradeBadge(pr.grade) + ' ' + esc(pr.score) + '</div>';
        h += '<div class="small fw-bold">Writes, in order</div><ol class="small mb-2">' +
          p.writes.map(w => '<li>' + esc(w.describe) + '</li>').join('') + '</ol>';
        h += '<div class="small">Server policies affected: ' + p.affected_policies.map(x => '<code>' + esc(x) + '</code>').join(' ') + '</div>';
        (p.risks || []).forEach(x => { h += '<div class="small text-muted mt-1"><i class="bi bi-exclamation-triangle me-1"></i>' + esc(x) + '</div>'; });
        $('fw-obs-plan').innerHTML = h;
        $('fw-obs-ackwrap').style.display = p.shared ? '' : 'none';
        $('fw-obs-ack').checked = false;
        $('fw-obs-acklabel').textContent = 'This also changes ' + (p.others || []).join(', ') +
          ' (they share the profile). Apply to all of them.';
        $('fw-obs-apply').disabled = false;
      });
    }

    function apply() {
      const items = pickedItems();
      const ack = $('fw-obs-ack').checked;
      $('fw-obs-apply').disabled = true;
      $('fw-obs-applyout').innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Applying and grading again…';
      req('POST', '/observatory/api/apply', { scan_id: state.current.scan.id, items: items, ack_shared: ack }).then(r => {
        const d = r.d;
        let h = '';
        (d.results || []).forEach(x => {
          h += '<div class="small">' + (x.ok ? '<i class="bi bi-check-circle text-success me-1"></i>' : '<i class="bi bi-x-circle text-danger me-1"></i>') +
            esc(x.describe) + (x.verify ? ' <span class="text-muted">(' + esc(x.verify) + ')</span>' : '') + (x.error ? ' — ' + esc(x.error) : '') + '</div>';
        });
        if (!d.ok) h += '<div class="text-danger small mt-1">' + esc(d.error) + '</div>';
        $('fw-obs-applyout').innerHTML = h;
        if (d.after) {
          const t = state.targets.find(x => x.policy === d.after.scan.policy);
          if (t) t.last = d.after.scan;
          renderTargets();
          const keep = $('fw-obs-applyout').innerHTML;
          renderResult(d.after);
          $('fw-obs-fixcard').style.display = '';
          $('fw-obs-applyout').innerHTML = keep + '<div class="mt-1">Graded again: ' + gradeBadge(d.after.scan.grade) + ' ' + esc(d.after.scan.score) + '</div>';
        }
      });
    }

    function history() {
      const s = state.current && state.current.scan;
      if (!s) return;
      $('fw-obs-histtitle').textContent = s.policy;
      $('fw-obs-histbody').innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
      const m = bootstrap.Modal.getOrCreateInstance($('fw-obs-histmodal'));
      m.show();
      req('GET', '/observatory/api/history?appliance_id=' + encodeURIComponent(s.appliance_id) + '&policy=' + encodeURIComponent(s.policy)).then(r => {
        if (!r.d.ok) { $('fw-obs-histbody').textContent = r.d.error || 'error'; return; }
        let h = '<table class="table table-sm mb-0"><thead><tr><th>When</th><th>Grade</th><th>Score</th><th>Site</th><th>By</th><th></th></tr></thead><tbody>';
        r.d.scans.forEach(x => {
          h += '<tr><td class="small">' + when(x.started_at) + '</td><td>' + gradeBadge(x.grade) + '</td><td>' + esc(x.score === null ? '' : x.score) +
            '</td><td class="small">' + esc(x.host) + '</td><td class="small">' + esc(x.trigger) + (x.username ? ' · ' + esc(x.username) : '') +
            '</td><td><button type="button" class="btn btn-sm btn-fw-outline fw-obs-histview" data-scan="' + esc(x.id) + '">Open</button></td></tr>';
        });
        $('fw-obs-histbody').innerHTML = h + '</tbody></table>';
      });
    }

    function init() {
      const root = $('fw-obs-page');
      if (!root || root.dataset.obsBound) return;
      root.dataset.obsBound = '1';
      state = { appliance: null, targets: [], picked: new Set(), current: null, busy: false };
      if (!$('fw-obs-appliance')) return;
      $('fw-obs-appliance').addEventListener('change', loadTargets);
      $('fw-obs-reload').addEventListener('click', loadTargets);
      $('fw-obs-picksearch').addEventListener('input', filterPicker);
      $('fw-obs-pick').addEventListener('shown.bs.dropdown', () => $('fw-obs-picksearch').focus());
      $('fw-obs-picklist').addEventListener('change', function (ev) {
        const cb = ev.target.closest('input[data-policy]');
        if (!cb) return;
        setPicked(cb.getAttribute('data-policy'), cb.checked);
        pickChanged();
      });
      $('fw-obs-pickall').addEventListener('click', function () {
        // "All matches" = the items the search leaves visible, added to what
        // is already ticked (a hidden tick is never dropped).
        document.querySelectorAll('#fw-obs-picklist .fw-obs-pickitem').forEach(el => {
          if (el.style.display === 'none') return;
          setPicked(el.querySelector('input').getAttribute('data-policy'), true);
        });
        pickChanged();
      });
      $('fw-obs-picknone').addEventListener('click', function () {
        Array.from(state.picked).forEach(x => setPicked(x, false));
        pickChanged();
      });
      $('fw-obs-scanall').addEventListener('click', scanAll);
      $('fw-obs-history').addEventListener('click', history);
      if ($('fw-obs-preview')) {
        $('fw-obs-preview').addEventListener('click', preview);
        $('fw-obs-apply').addEventListener('click', apply);
      }
      root.addEventListener('click', function (ev) {
        const b = ev.target.closest('.fw-obs-scan');
        if (b) { scan(b.closest('tr').getAttribute('data-policy')); return; }
        const up = ev.target.closest('.fw-obs-unpick');
        if (up) { setPicked(up.closest('tr').getAttribute('data-policy'), false); pickChanged(); return; }
        const vw = ev.target.closest('.fw-obs-view');
        if (vw) { view(vw.getAttribute('data-scan')); return; }
        const hv = ev.target.closest('.fw-obs-histview');
        if (hv) {
          bootstrap.Modal.getOrCreateInstance($('fw-obs-histmodal')).hide();
          view(hv.getAttribute('data-scan'));
        }
      });
      root.addEventListener('change', function (ev) {
        if (ev.target.closest('.fw-obs-fix')) updateFixCount();
      });
      root.addEventListener('input', function (ev) {
        const hi = ev.target.closest('.fw-obs-host');
        if (!hi) return;
        const t = state.targets.find(x => x.policy === hi.closest('tr').getAttribute('data-policy'));
        if (t) t.host_edit = hi.value;
      });
      loadTargets();
    }

    window.FWObservatory = { init: init };
  }
  window.FWObservatory.init();
})();
