/* Operations > Automation > Mass Deploy (views/mass_deploy.py).
 * Preview -> Deploy. The Deploy button is enabled only by a preview of the SAME
 * selection: changing a device, a secret or the limit box disables it again.
 * Secrets are sent with the request and cleared from the form after a deploy. */
(function () {
  'use strict';
  var form = document.getElementById('md-form');
  if (!form) return;
  var deployBtn = form.querySelector('[data-js="md-deploy"]');
  var previewBtn = form.querySelector('[data-js="md-preview"]');
  var result = document.getElementById('md-result');
  var compatBox = document.getElementById('md-compat');
  var overrideBox = document.getElementById('md-override');
  var last = null;   // the selection the shown preview was made for
  var canOverride = false;

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
    });
  }
  function boxes() { return Array.prototype.slice.call(form.querySelectorAll('input[name="device_ids"]')); }
  function checkedIds() { return boxes().filter(function (b) { return b.checked; }).map(function (b) { return b.value; }); }
  function fingerprint() {
    var parts = checkedIds();
    form.querySelectorAll('input[name^="secret:"]').forEach(function (i) { parts.push(i.name + '=' + (i.value ? '1' : '0') + i.value.length); });
    var lim = document.getElementById('md-limit');
    parts.push('limit=' + (lim && lim.checked ? 1 : 0));
    return parts.join('|');
  }
  function invalidate() {
    deployBtn.disabled = true;
    var n = checkedIds().length;
    document.getElementById('md-count').textContent = n + ' selected';
    if (last !== null && last !== fingerprint()) {
      result.innerHTML = '<span class="text-muted">Selection changed — preview again.</span>';
      compatBox.innerHTML = '';
      last = null;
    }
  }
  function body(extra) {
    var fd = new FormData(form);
    Object.keys(extra || {}).forEach(function (k) { fd.append(k, extra[k]); });
    return fd;
  }
  function post(url, fd) {
    return fetch(url, {method: 'POST', body: fd, credentials: 'same-origin',
                       headers: {'Accept': 'application/json',
                                 'X-CSRFToken': form.querySelector('input[name=csrf_token]').value}})
      .then(function (r) { return r.json().then(function (j) { return {status: r.status, j: j}; }); });
  }

  function renderPreview(j) {
    var h = '<div class="mb-2 text-muted">' + j.item_count + ' push item(s) per device · ' + j.preview.length + ' device(s)</div>';
    if (j.scope) {
      h += '<div class="mb-2">' + esc(j.scope.text) + '.';
      if (j.scope.will_bind && j.scope.will_bind.length) h += ' Will bind: <strong>' + esc(j.scope.will_bind.join(', ')) + '</strong>.';
      if (j.scope.limit) h += ' The template will govern bound devices only from now on.';
      h += '</div>';
    }
    var s = j.secrets || {sent: [], kept: []};
    if (s.sent.length) h += '<div class="mb-1"><i class="bi bi-key me-1"></i>Secrets set from what you typed: ' + esc(s.sent.join(', ')) + '</div>';
    if (s.kept.length) h += '<div class="mb-2 text-muted"><i class="bi bi-key me-1"></i>Not sent (each device keeps its own): ' + esc(s.kept.join(', ')) + '</div>';
    j.preview.forEach(function (d) {
      h += '<div class="mb-2"><strong>' + esc(d.appliance || ('device ' + d.appliance_id)) + '</strong><ul style="margin:.25rem 0 .25rem 1rem;padding:0;">';
      (d.results || []).forEach(function (r) {
        var req = r.request || {};
        h += '<li><span class="mono">' + esc(r.action) + ' ' + esc(req.method || '') + ' ' + esc(req.path || r.endpoint || '') + '</span>' +
             (r.error ? ' <span class="text-danger">' + esc(r.error) + '</span>' : '') + '</li>';
      });
      h += '</ul></div>';
    });
    return h;
  }

  previewBtn.addEventListener('click', function () {
    if (!checkedIds().length) { result.innerHTML = '<span class="text-danger">Select at least one device.</span>'; return; }
    previewBtn.disabled = true;
    result.innerHTML = '<span class="text-muted">Previewing…</span>';
    compatBox.innerHTML = '';
    var fp = fingerprint();
    post(form.dataset.previewUrl, body()).then(function (res) {
      previewBtn.disabled = false;
      if (res.status !== 200 || !res.j.ok) {
        result.innerHTML = '<span class="text-danger">' + esc(res.j.error || 'Preview failed') + '</span>';
        return;
      }
      result.innerHTML = renderPreview(res.j);
      var c = res.j.compat || {};
      canOverride = !!res.j.can_override;
      compatBox.innerHTML = (window.TplCompat && TplCompat.applyPanel) ? TplCompat.applyPanel(c, canOverride) : '';
      overrideBox.style.display = (c.blocked && canOverride) ? '' : 'none';
      last = fp;
      deployBtn.disabled = !!(c.blocked && !canOverride);
    }).catch(function (e) { previewBtn.disabled = false; result.innerHTML = '<span class="text-danger">Preview failed: ' + esc(e.message) + '</span>'; });
  });

  deployBtn.addEventListener('click', function () {
    if (last !== fingerprint()) { invalidate(); return; }
    var n = checkedIds().length;
    if (!window.confirm('Deploy to ' + n + ' device(s)? The first device is the canary; the rest run only if it succeeds.')) return;
    deployBtn.disabled = true;
    previewBtn.disabled = true;
    post(form.dataset.deployUrl, body()).then(function (res) {
      previewBtn.disabled = false;
      form.querySelectorAll('input[name^="secret:"]').forEach(function (i) { i.value = ''; });
      if (res.status !== 202 || !res.j.ok) {
        result.innerHTML = '<span class="text-danger">' + esc(res.j.error || 'Deploy refused') + '</span>';
        last = null;
        return;
      }
      result.innerHTML = '<span class="fw-badge fw-badge-info">started</span> Job ' + esc(res.j.job_id) +
        ' — progress in the job dock (bottom right). The history below fills in when it ends.' +
        (res.j.bound && res.j.bound.length ? ' Bound ' + res.j.bound.length + ' device(s).' : '');
      compatBox.innerHTML = '';
      last = null;
      if (window.FwJobs && FwJobs.track) { try { FwJobs.track(res.j.job_id); } catch (e) { /* dock picks it up by itself */ } }
    }).catch(function (e) { previewBtn.disabled = false; result.innerHTML = '<span class="text-danger">Deploy failed: ' + esc(e.message) + '</span>'; });
  });

  form.addEventListener('change', invalidate);
  form.addEventListener('input', invalidate);
  form.querySelector('[data-js="md-all"]').addEventListener('click', function () {
    boxes().forEach(function (b) { if (!b.disabled && b.closest('tr').style.display !== 'none') b.checked = true; });
    invalidate();
  });
  form.querySelector('[data-js="md-none"]').addEventListener('click', function () {
    boxes().forEach(function (b) { b.checked = false; });
    invalidate();
  });
  document.getElementById('md-build').addEventListener('change', function () {
    var want = this.value;
    form.querySelectorAll('#md-devices tbody tr[data-build]').forEach(function (tr) {
      var show = !want || tr.dataset.build === want;
      tr.style.display = show ? '' : 'none';
      if (!show) { var b = tr.querySelector('input[name="device_ids"]'); if (b) b.checked = false; }
    });
    invalidate();
  });
  invalidate();
})();
