/* Plugin Studio > an app's VIEW -- the console's side of the bridge.
 *
 * apps/view.html embeds the view in <iframe sandbox="allow-scripts
 * allow-modals"> (an opaque origin, services/studio_view) and loads this
 * file. It answers the frame's messages (static/js/app_view_bridge.js) and
 * nothing else:
 *
 *   - only messages whose source IS the frame and that carry this load's
 *     token (a frame that navigated away does not have it);
 *   - run: only this app or one its view "uses" (the server checks again
 *     who may run it and every step its permission);
 *   - open / navigate: only a local path ("/x", never "//x", no scheme, no
 *     backslash);
 *   - copy, open_app (another app's form, apps_run.js), submit (run this
 *     app, then show the page with that run).
 *
 * The frame fills the content area down to the bottom of the window, so a
 * dialog of the view centres where the operator is looking.
 */
(function () {
  'use strict';
  var cfgEl = document.getElementById('app-view-config');
  var frame = document.getElementById('app-view-frame');
  if (!cfgEl || !frame) return;
  var C = JSON.parse(cfgEl.textContent);
  var meta = document.querySelector('meta[name="csrf-token"]');
  var CSRF = meta ? meta.getAttribute('content') : '';
  var allowed = [C.slug].concat(C.uses || []);

  function fit() {
    var top = frame.getBoundingClientRect().top;
    frame.style.height = Math.max(420, window.innerHeight - Math.max(0, top) - 12) + 'px';
  }
  window.addEventListener('resize', fit);
  fit();
  window.setTimeout(fit, 250);

  function local(url) {
    url = String(url || '');
    return url.charAt(0) === '/' && url.charAt(1) !== '/' && url.indexOf('\\') < 0 && !/[\u0000-\u001f]/.test(url);
  }
  function post(url, body) {
    return fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF, Accept: 'application/json' },
      body: JSON.stringify(body || {})
    }).then(function (r) {
      return r.json().catch(function () { return { ok: false, error: 'HTTP ' + r.status }; }).then(function (d) {
        if (!r.ok || d.ok === false) throw new Error(d.error || ('HTTP ' + r.status));
        return d;
      });
    });
  }
  function getJSON(url) {
    return fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); });
  }
  /* Start a run and wait until it is no longer running (or waits on a
     person): the frame gets the outputs by key. */
  function runApp(slug, inputs) {
    if (allowed.indexOf(slug) < 0) return Promise.reject(new Error('this view does not use the app ' + slug));
    return post('/apps/' + encodeURIComponent(slug) + '/run', { inputs: inputs || {} }).then(function (d) {
      var n = 0;
      return new Promise(function (resolve, reject) {
        (function tick() {
          getJSON(d.status_url).then(function (s) {
            if (s.status === 'running' && n++ < 900) { window.setTimeout(tick, n < 15 ? 350 : 1500); return; }
            var outputs = {};
            (s.outputs || []).forEach(function (o) { if (o.key && !(o.key in outputs)) outputs[o.key] = o.value; });
            resolve({ run_id: d.run_id, status: s.status, error: s.error || '', outputs: outputs,
                      waiting: !!s.waiting, url: d.url });
          }).catch(reject);
        })();
      });
    });
  }
  function copy(text) {
    var legacy = function () {
      var ta = document.createElement('textarea');
      ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (x) { ok = false; }
      document.body.removeChild(ta);
      if (!ok) throw new Error('the browser did not let SATOM copy');
      return true;
    };
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(function () { return true; }, legacy);
    }
    return Promise.resolve().then(legacy);
  }
  function show(runId) {
    var u = new URL(window.location.href);
    u.searchParams.set('run', runId);
    window.history.pushState({ run: runId }, '', u.pathname + u.search);
    frame.src = C.frameUrl + (C.frameUrl.indexOf('?') < 0 ? '?' : '&') + 'run=' + encodeURIComponent(runId) +
      '&t=' + encodeURIComponent(C.token);
  }
  window.addEventListener('popstate', function () {
    var run = new URL(window.location.href).searchParams.get('run');
    frame.src = C.frameUrl + (C.frameUrl.indexOf('?') < 0 ? '?' : '&') + (run ? 'run=' + encodeURIComponent(run) + '&' : '') +
      't=' + encodeURIComponent(C.token);
  });

  var HANDLERS = {
    submit: function (a) {
      return runApp(C.slug, a.inputs).then(function (r) { show(r.run_id); return { run_id: r.run_id }; });
    },
    run: function (a) { return runApp(String(a.slug || ''), a.inputs); },
    open: function (a) {
      if (!local(a.url)) return Promise.reject(new Error('only a SATOM page can be opened'));
      var feats = 'noopener';
      if (a.popup) {
        var w = Math.min(+a.width || 1500, screen.availWidth - 40), h = Math.min(+a.height || 950, screen.availHeight - 40);
        feats += ',popup,width=' + w + ',height=' + h;
      }
      window.open(a.url, '_blank', feats);
      return Promise.resolve(true);
    },
    navigate: function (a) {
      if (!local(a.url)) return Promise.reject(new Error('only a SATOM page can be opened'));
      if (window.Turbo && window.Turbo.visit) window.Turbo.visit(a.url); else window.location.assign(a.url);
      return Promise.resolve(true);
    },
    copy: function (a) { return copy(String(a.text == null ? '' : a.text)); },
    open_app: function (a) {
      if (!window.AppRun || !window.AppRun.openApp) return Promise.reject(new Error('cannot open an app here'));
      window.AppRun.openApp(String(a.slug || ''), a.inputs || {});
      return Promise.resolve(true);
    }
  };

  window.addEventListener('message', function (e) {
    if (e.source !== frame.contentWindow) return;
    var m = e.data;
    if (!m || m.satomView !== 1 || m.token !== C.token || typeof m.cmd !== 'string') return;
    var h = Object.prototype.hasOwnProperty.call(HANDLERS, m.cmd) ? HANDLERS[m.cmd] : null;
    var reply = function (ok, result, error) {
      frame.contentWindow.postMessage({ satomView: 1, token: C.token, id: m.id, ok: ok, result: result, error: error || '' }, '*');
    };
    if (!h) { reply(false, null, 'unknown command ' + m.cmd); return; }
    Promise.resolve().then(function () { return h(m.args || {}); })
      .then(function (r) { reply(true, r); }, function (err) { reply(false, null, err && err.message ? err.message : String(err)); });
  });
})();
