/* jobs.js — background-job dock + resilient uploads, powered by Turbo Drive.
 *
 * WHY THIS SHAPE (read before "simplifying"): five earlier designs tried to keep
 * a long upload alive across a full-page navigation (in-page XHR, Background
 * Fetch, Service Worker, SharedWorker, resumable OPFS chunking) — all fought the
 * browser tearing down the page mid-request. The real fix is upstream: Turbo
 * Drive (see turbo-boot.js) turns navigation into fetch+swap, so the document is
 * NEVER unloaded. Given that, the upload is dead simple again:
 *
 *   • A plain XHR POST, held in THIS module's scope. This module loads in <head>
 *     and runs ONCE, so `activeXhr` (and the whole toast state) persists across
 *     every Turbo visit — the upload just keeps running while the user navigates.
 *   • The bottom-right dock is moved into the incoming <body> on each Turbo render
 *     (turbo:before-render), so the live progress bar follows the user with NO cut.
 *   • On completion the server returns 202 {job_id}; we poll /jobs/<id> for the
 *     server-side sha256 "finalize" job (which already survives navigation).
 *
 * A running job whose server-side state is `cancelable` shows a Stop button in
 * its toast; clicking it POSTs /jobs/<id>/cancel (cooperative — the worker halts
 * at its next safe checkpoint) and the toast reflects `cancelling` → `cancelled`.
 *
 * MUST load in <head> (runs once, persists). Uses turbo:load / turbo:before-render
 * DIRECTLY — never DOMContentLoaded — so it is correct as a run-once head script
 * (the DOMContentLoaded→turbo:load shim in turbo-boot.js is for BODY scripts).
 */
(function () {
  'use strict';

  var POLL_MS = 1500;
  var DIAG = '/_updiag';

  var activeXhr = null;   // in-flight upload XHR — module scope ⇒ survives Turbo visits
  var toasts = {};        // key -> {el, bar, title, msg, stop, jobId}
  var dock = null;        // #job-toasts container — re-homed into each new <body>
  var tracked = {};       // finalize job ids currently being polled
  var booted = false;

  // ── tiny helpers ────────────────────────────────────────────────────────────
  function csrf() {
    var m = document.querySelector('meta[name="csrf-token"]');
    return m ? (m.getAttribute('content') || '') : '';
  }
  function diag(ev, extra) {
    try {
      var q = '?src=page&ev=' + encodeURIComponent(ev);
      if (extra) { for (var k in extra) q += '&' + k + '=' + encodeURIComponent(extra[k]); }
      if (navigator.sendBeacon) navigator.sendBeacon(DIAG + q);
      else fetch(DIAG + q, { method: 'GET', keepalive: true });
    } catch (e) { /* diagnostics must never throw */ }
  }
  function fmtBytes(n) {
    n = n || 0;
    if (n >= 1073741824) return (n / 1073741824).toFixed(1) + ' GB';
    if (n >= 1048576) return (n / 1048576).toFixed(0) + ' MB';
    if (n >= 1024) return (n / 1024).toFixed(0) + ' KB';
    return n + ' B';
  }

  // ── dock + toast UI (self-contained CSS; persists across Turbo visits) ───────
  function ensureStyles() {
    if (document.getElementById('jobs-toast-styles')) return;
    var css = document.createElement('style');
    css.id = 'jobs-toast-styles';
    // CSP: style-src-elem is nonce-gated — stamp the page nonce.
    css.nonce = (document.querySelector('meta[name=csp-nonce]')||{}).content || '';
    css.textContent =
      '#job-toasts{position:fixed;right:18px;bottom:18px;z-index:20000;display:flex;' +
      'flex-direction:column;gap:10px;max-width:340px;font-family:inherit;pointer-events:none}' +
      '.job-toast{pointer-events:auto;background:#0f172a;color:#e2e8f0;' +
      'border:1px solid rgba(148,163,184,.18);border-left:3px solid #3b82f6;' +
      'border-radius:12px;padding:12px 14px;box-shadow:0 10px 30px rgba(0,0,0,.45);' +
      'backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);animation:jobToastIn .18s ease}' +
      '@keyframes jobToastIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}' +
      '.job-toast.ok{border-left-color:#10b981}.job-toast.err{border-left-color:#ef4444}' +
      '.job-toast.stopped{border-left-color:#fbbf24}' +
      '.job-toast .jt-top{display:flex;align-items:center;gap:8px;justify-content:space-between}' +
      '.job-toast .jt-title{font-size:13px;font-weight:600;line-height:1.3;flex:1;' +
      'overflow:hidden;text-overflow:ellipsis;white-space:nowrap}' +
      '.job-toast .jt-stop{cursor:pointer;font-size:11px;font-weight:600;line-height:1;' +
      'border:1px solid rgba(148,163,184,.35);background:rgba(148,163,184,.08);color:#e2e8f0;' +
      'border-radius:7px;padding:3px 8px}' +
      '.job-toast .jt-stop:hover{background:rgba(239,68,68,.18);border-color:#ef4444}' +
      '.job-toast .jt-stop[disabled]{opacity:.5;cursor:default}' +
      '.job-toast .jt-x{cursor:pointer;opacity:.5;font-size:16px;line-height:1;border:0;' +
      'background:none;color:inherit;padding:0 2px}.job-toast .jt-x:hover{opacity:1}' +
      '.job-toast .jt-msg{font-size:11px;color:#94a3b8;margin-top:3px;min-height:14px}' +
      '.job-toast .jt-track{height:6px;background:rgba(148,163,184,.15);border-radius:6px;' +
      'margin-top:8px;overflow:hidden}' +
      '.job-toast .jt-bar{height:100%;width:0;border-radius:6px;transition:width .25s ease;' +
      'background:linear-gradient(90deg,#3b82f6,#8b5cf6)}' +
      '.job-toast.ok .jt-bar{background:#10b981}.job-toast.err .jt-bar{background:#ef4444}' +
      '.job-toast.stopped .jt-bar{background:#fbbf24}' +
      '.job-toast.ok .jt-title::before{content:"\\2713 ";color:#10b981}' +
      '.job-toast.err .jt-title::before{content:"\\26A0 ";color:#ef4444}' +
      '.job-toast.stopped .jt-title::before{content:"\\23F9 ";color:#fbbf24}';
    (document.head || document.documentElement).appendChild(css);
  }
  function ensureDock() {
    ensureStyles();
    if (!dock) { dock = document.createElement('div'); dock.id = 'job-toasts'; }
    if (document.body && dock.parentNode !== document.body) document.body.appendChild(dock);
    return dock;
  }
  function showToast(key, o) {
    o = o || {};
    var t = toasts[key];
    if (!t) {
      var el = document.createElement('div');
      el.className = 'job-toast';
      el.innerHTML =
        '<div class="jt-top"><div class="jt-title"></div>' +
        '<button class="jt-stop" hidden>Stop</button>' +
        '<button class="jt-x" title="Dismiss">&times;</button></div>' +
        '<div class="jt-msg"></div>' +
        '<div class="jt-track"><div class="jt-bar"></div></div>';
      ensureDock().appendChild(el);
      el.querySelector('.jt-x').addEventListener('click', function () { removeToast(key); });
      el.querySelector('.jt-stop').addEventListener('click', function () {
        var tt = toasts[key]; if (tt && tt.jobId) cancelJob(tt.jobId, key);
      });
      t = toasts[key] = { el: el, bar: el.querySelector('.jt-bar'),
                          title: el.querySelector('.jt-title'),
                          msg: el.querySelector('.jt-msg'),
                          stop: el.querySelector('.jt-stop'), jobId: null };
    }
    if (o.jobId != null) t.jobId = o.jobId;
    if (o.title != null) t.title.textContent = o.title;
    if (o.message != null) t.msg.textContent = o.message;
    if (o.percent != null) t.bar.style.width = Math.max(0, Math.min(100, o.percent)) + '%';
    t.el.classList.remove('ok', 'err', 'stopped');
    if (o.state === 'ok') t.el.classList.add('ok');
    else if (o.state === 'err') t.el.classList.add('err');
    else if (o.state === 'stopped' || o.state === 'cancelling') t.el.classList.add('stopped');
    // A Stop button only when the running job says it is cancelable (and not
    // already being stopped) — never promise a stop the server won't honour.
    if (t.stop && o.state != null) {
      var canStop = !!o.cancelable && o.state === 'run';
      t.stop.hidden = !canStop;
      if (canStop) { t.stop.disabled = false; t.stop.textContent = 'Stop'; }
    }
    return t;
  }
  function removeToast(key) {
    var t = toasts[key];
    if (t && t.el && t.el.parentNode) t.el.parentNode.removeChild(t.el);
    delete toasts[key];
  }
  function autoDismiss(key, ms) { setTimeout(function () { removeToast(key); }, ms || 6000); }

  // ── cooperative cancel ──────────────────────────────────────────────────────
  function cancelJob(jobId, key) {
    var t = toasts[key];
    if (t && t.stop) { t.stop.disabled = true; t.stop.textContent = 'Stopping…'; }
    fetch('/jobs/' + encodeURIComponent(jobId) + '/cancel',
          { method: 'POST',
            headers: { 'X-Requested-With': 'XMLHttpRequest', 'X-CSRFToken': csrf() } })
      .then(function (r) { return r.ok ? r.json() : r.json().catch(function () { return null; }); })
      .then(function (j) {
        if (j && j.error) {   // e.g. 409 — not cancelable
          if (t && t.stop) { t.stop.hidden = true; }
          showToast(key, { message: j.error });
          return;
        }
        showToast(key, { state: 'cancelling', message: 'Stopping — finishing the current step…' });
      })
      .catch(function () {
        if (t && t.stop) { t.stop.disabled = false; t.stop.textContent = 'Stop'; }
      });
  }

  // ── the upload: plain XHR, held in module scope ⇒ survives navigation ────────
  function uploadWithProgress(actionUrl, formData, opts) {
    opts = opts || {};
    var file = formData.get('image');
    if (!file || !file.name) return;                 // let native validation fire
    var name = file.name;
    var upTitle = opts.title || ('Uploading ' + name);
    var key = 'up:' + name + ':' + (file.size || 0);
    var total = file.size || 0;

    showToast(key, { title: upTitle, state: 'run', percent: 0, message: 'Starting…' });

    var xhr = new XMLHttpRequest();
    activeXhr = xhr;
    xhr.open('POST', actionUrl, true);
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
    xhr.setRequestHeader('X-CSRFToken', csrf());

    diag('xhr_start', { name: name, size: total });

    xhr.upload.onprogress = function (e) {
      if (e.lengthComputable) {
        showToast(key, { title: upTitle, state: 'run',
                         percent: Math.floor(e.loaded * 100 / e.total),
                         message: fmtBytes(e.loaded) + ' / ' + fmtBytes(e.total) });
      }
    };
    xhr.onload = function () {
      activeXhr = null;
      diag('xhr_done', { name: name, status: xhr.status });
      var j = {}; try { j = JSON.parse(xhr.responseText); } catch (e) {}
      removeToast(key);
      if (xhr.status === 202 && j.job_id) {
        trackJob(j.job_id, opts.serverTitle || ('Verifying ' + name));
      } else if (xhr.status >= 400) {
        showToast(key, { title: name + ' — upload failed', state: 'err',
                         message: (j.error || ('HTTP ' + xhr.status)) });
        autoDismiss(key, 10000);
      } else if (location.pathname.indexOf('/firmware') === 0) {
        location.reload();                            // non-JSON success (JS-off shape)
      }
    };
    xhr.onerror = function () {
      activeXhr = null;
      diag('xhr_err', { name: name });
      showToast(key, { title: name + ' — network error', state: 'err',
                       message: 'The upload connection dropped. Please try again.' });
      autoDismiss(key, 10000);
    };
    xhr.send(formData);
    return xhr;
  }

  // ── finalize-job polling (server-side sha256) ───────────────────────────────
  // Append a persistent link (e.g. a before/after report) into a toast's message.
  function addToastLink(key, href, text) {
    var t = toasts[key]; if (!t || !t.msg) return;
    if (t.msg.querySelector('a.jt-link[href="' + href + '"]')) return;
    var a = document.createElement('a');
    a.className = 'jt-link'; a.href = href; a.target = '_blank'; a.rel = 'noopener';
    a.textContent = text;
    a.style.cssText = 'display:inline-block;margin-top:6px;color:#8b5cf6;' +
                      'font-weight:600;text-decoration:none';
    t.msg.appendChild(document.createElement('br'));
    t.msg.appendChild(a);
  }
  function jobUrl(id) { return '/jobs/manager?focus=' + encodeURIComponent(id); }
  function reportLabel(url) {
    return (url && url.indexOf('clone-report') >= 0)
      ? 'View clone report \u2192' : 'View before/after report \u2192';
  }

  function trackJob(jobId, name) {
    if (tracked[jobId]) return;
    tracked[jobId] = true;
    var key = 'job:' + jobId;
    var label = name || 'Firmware';
    showToast(key, { title: label, state: 'run', percent: 0, message: 'Finalizing…',
                     jobId: jobId });
    function poll() {
      fetch('/jobs/' + encodeURIComponent(jobId),
            { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (j) {
          if (!j) { delete tracked[jobId]; removeToast(key); return; }
          if (j.status === 'success') {
            var res = j.result || {};
            showToast(key, { title: (res.filename || label) + ' ready', state: 'ok',
                             percent: 100, message: j.message || 'Done' });
            if (res.report_url) addToastLink(key, res.report_url, reportLabel(res.report_url));
            addToastLink(key, jobUrl(jobId), 'View job →');
            autoDismiss(key, res.report_url ? 60000 : 12000); delete tracked[jobId];
            if (res.reload &&
                location.pathname.indexOf(res.reload_path || '/firmware') === 0)
              setTimeout(function () {
                if (window.Turbo && window.Turbo.visit) window.Turbo.visit(location.href, { action: 'replace' });
                else location.reload();
              }, 1200);
            return;
          }
          if (j.status === 'cancelled') {
            var cres = j.result || {};
            var extra = '';
            if (cres.mid_change && cres.mid_change.length) {
              var n = cres.mid_change.reduce(function (a, m) {
                return a + ((m.committed || []).length); }, 0);
              extra = ' — ' + cres.mid_change.length + ' device(s) left mid-change, '
                      + n + ' write(s) to review';
            }
            showToast(key, { title: label + ' stopped', state: 'stopped',
                             percent: j.percent || 0,
                             message: (j.message || 'Stopped') + extra });
            addToastLink(key, jobUrl(jobId), 'View job →');
            autoDismiss(key, (cres.mid_change && cres.mid_change.length) ? 60000 : 15000);
            delete tracked[jobId]; return;
          }
          if (j.status === 'error') {
            var eres = j.result || {};
            showToast(key, { title: label + ' failed', state: 'err',
                             message: j.error || j.message || 'Error' });
            if (eres.report_url) addToastLink(key, eres.report_url, reportLabel(eres.report_url));
            addToastLink(key, jobUrl(jobId), 'View job →');
            autoDismiss(key, eres.report_url ? 60000 : 20000); delete tracked[jobId]; return;
          }
          // running, pausing/paused or cancelling
          var stopping = j.status === 'cancelling';
          var paused = j.status === 'paused' || j.status === 'pausing';
          showToast(key, { title: stopping ? ('Stopping ' + label)
                                  : (paused ? (label + ' — paused') : label),
                           state: stopping ? 'cancelling' : (paused ? 'stopped' : 'run'),
                           percent: j.percent || 0,
                           message: j.message || (stopping ? 'Stopping…'
                                    : (paused ? 'Paused — resume from the Jobs page' : 'Working…')),
                           cancelable: j.cancelable !== false && !stopping,
                           jobId: jobId });
          setTimeout(poll, POLL_MS);
        })
        .catch(function () { setTimeout(poll, POLL_MS * 2); });
    }
    poll();
  }

  // ── reconnect to jobs still running after a FULL reload (F5 / JS-off nav) ────
  function reconnectJobs() {
    fetch('/jobs/?active=1', { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        var list = (data && data.jobs) || data || [];
        list.forEach(function (j) {
          if (!j || !j.id) return;
          // Track ANY active job of this user (bulk applies, finalize, …);
          // tracked{} dedupes so calling this on every navigation is safe.
          var label = j.type === 'firmware_finalize'
            ? 'Verifying ' + ((j.meta && j.meta.filename) || j.title || '')
            : (j.title || j.type || 'Job');
          trackJob(j.id, label);
        });
      }).catch(function () {});
  }
  // Retire any Service/Shared workers left by the earlier (failed) upload designs
  // so they can't intercept fetches or confuse the flow.
  function cleanupOldWorkers() {
    try {
      if (navigator.serviceWorker && navigator.serviceWorker.getRegistrations)
        navigator.serviceWorker.getRegistrations().then(function (rs) {
          rs.forEach(function (r) { r.unregister(); });
        }).catch(function () {});
    } catch (e) {}
  }

  window.JobsUI = { uploadWithProgress: uploadWithProgress, trackJob: trackJob,
                    cancelJob: cancelJob };

  // ── Turbo lifecycle: keep the dock (and its live toasts) attached ───────────
  // Move the dock into the INCOMING body before the swap → seamless, no flicker.
  document.addEventListener('turbo:before-render', function (e) {
    if (dock && e.detail && e.detail.newBody) {
      try { e.detail.newBody.appendChild(dock); } catch (err) {}
    }
  });

  function onLoad() {
    ensureDock();
    diag('nav', { path: location.pathname, uploading: activeXhr ? 1 : 0 });
    if (!booted) { booted = true; cleanupOldWorkers(); }
    // Every navigation (a bulk apply ends in a redirect): pick up any active
    // job of this user; tracked{} inside trackJob dedupes repeat calls.
    reconnectJobs();
  }

  // Turbo fires turbo:load on the initial load AND after every visit.
  document.addEventListener('turbo:load', onLoad);
  // Fallback when Turbo isn't present (script still works as a plain toast host).
  if (!window.Turbo) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', onLoad);
    else onLoad();
  }
})();
