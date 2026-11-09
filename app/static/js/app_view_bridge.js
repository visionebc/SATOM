/* Plugin Studio > an app's VIEW -- the frame's side of the bridge.
 *
 * Inlined into the view's document (services/studio_view.document) before
 * the view's own script. The frame is an opaque origin: it cannot fetch
 * SATOM, open a window or write the clipboard, so this file turns the few
 * things a page does into messages the console answers
 * (static/js/apps_view_host.js) -- only from this frame, only with this
 * load's token:
 *
 *   SATOM.submit(inputs)      run THIS app and show the page with its result
 *   SATOM.call(slug, inputs)  run this app or one its view uses; resolves to
 *                             {run_id, status, error, outputs: {key: value}}
 *   SATOM.open(url, {popup})  a SATOM page in a new window (local paths only)
 *   SATOM.navigate(url)       the console goes to a SATOM page
 *   SATOM.copy(text)          the clipboard
 *   SATOM.openApp(slug, inputs)  another app's form over the console
 *
 * and, so a page's script keeps working as written: window.open,
 * navigator.clipboard.writeText, a click on a local link and the submit of a
 * <form data-satom-submit> go through the same calls.
 */
(function () {
  'use strict';
  var island = document.getElementById('satom-view');
  var cfg = island ? JSON.parse(island.textContent || '{}') : {};
  var token = cfg.token || '', seq = 0, waits = {};

  function send(cmd, args) {
    return new Promise(function (resolve, reject) {
      var id = ++seq;
      waits[id] = { resolve: resolve, reject: reject };
      window.parent.postMessage({ satomView: 1, token: token, id: id, cmd: cmd, args: args || {} }, '*');
    });
  }
  window.addEventListener('message', function (e) {
    if (e.source !== window.parent) return;
    var m = e.data;
    if (!m || m.satomView !== 1 || m.token !== token || !waits[m.id]) return;
    var w = waits[m.id];
    delete waits[m.id];
    if (m.ok) w.resolve(m.result); else w.reject(new Error(m.error || 'the console refused'));
  });

  function formValues(form) {
    var out = {};
    Array.prototype.forEach.call(form.elements, function (el) {
      if (!el.name || el.disabled || el.type === 'button' || el.type === 'submit') return;
      if (el.type === 'checkbox') { if (el.checked) out[el.name] = el.value === 'on' ? true : el.value; return; }
      if (el.type === 'radio') { if (el.checked) out[el.name] = el.value; return; }
      out[el.name] = el.value;
    });
    return out;
  }

  var SATOM = {
    data: cfg.data || {}, form: cfg.form || {}, outputs: cfg.outputs || {}, run: cfg.run || null,
    submit: function (inputs) { return send('submit', { inputs: inputs || {} }); },
    call: function (slug, inputs) { return send('run', { slug: String(slug || ''), inputs: inputs || {} }); },
    open: function (url, opts) {
      opts = opts || {};
      return send('open', { url: String(url || ''), popup: !!opts.popup, width: opts.width || 0, height: opts.height || 0 });
    },
    navigate: function (url) { return send('navigate', { url: String(url || '') }); },
    copy: function (text) { return send('copy', { text: text == null ? '' : String(text) }); },
    openApp: function (slug, inputs) { return send('open_app', { slug: String(slug || ''), inputs: inputs || {} }); },
    formValues: formValues
  };
  window.SATOM = SATOM;

  /* window.open('/x', '_blank', 'popup,width=..,height=..') -> the console opens it. */
  window.open = function (url, _name, features) {
    var f = String(features || ''), w = /width=(\d+)/.exec(f), h = /height=(\d+)/.exec(f);
    SATOM.open(url, { popup: /popup/.test(f), width: w ? +w[1] : 0, height: h ? +h[1] : 0 });
    return null;
  };
  /* The clipboard is the console's. */
  var clip = { writeText: function (t) { return SATOM.copy(t); } };
  try { Object.defineProperty(navigator, 'clipboard', { value: clip, configurable: true }); } catch (x) { /* read-only: keep the browser's */ }

  /* A link never leaves the frame: a local path opens in the console (a new
     window with target=_blank or a modifier key), anything else is refused. */
  document.addEventListener('click', function (e) {
    var a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
    if (!a || e.defaultPrevented) return;
    var href = a.getAttribute('href') || '';
    if (!href || href.charAt(0) === '#' || /^javascript:/i.test(href)) return;
    e.preventDefault();
    if (a.target === '_blank' || e.ctrlKey || e.metaKey || e.shiftKey || e.button === 1) {
      SATOM.open(href, { popup: a.hasAttribute('data-popup') });
    } else {
      SATOM.navigate(href);
    }
  });
  /* <form data-satom-submit>: Search / Run runs this app with the form. */
  document.addEventListener('submit', function (e) {
    var form = e.target;
    e.preventDefault();
    if (!form || !form.hasAttribute || !form.hasAttribute('data-satom-submit')) return;
    var btns = form.querySelectorAll('button[type=submit], input[type=submit]');
    Array.prototype.forEach.call(btns, function (b) { b.disabled = true; });
    SATOM.submit(formValues(form)).catch(function (err) {
      Array.prototype.forEach.call(btns, function (b) { b.disabled = false; });
      var box = form.querySelector('[data-satom-error]');
      if (box) { box.textContent = err.message; box.hidden = false; } else { window.alert(err.message); }
    });
  });
})();
