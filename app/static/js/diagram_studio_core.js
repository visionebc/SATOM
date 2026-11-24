/* diagram_studio_core.js — Diagram Studio shared core.
 *
 * The one source of truth of every Diagram Studio page is a `satom.diagram/1`
 * document (app/services/diagram_engine/model.py). This file holds what every
 * page needs around it: DOM builders (no HTML strings), the CSRF-aware JSON
 * client, dialogs and toasts, the model defaults (mirror of model.py), the
 * geometry helpers and the command Store (undo/redo with coalescing).
 *
 * CSP-safe: no eval, no Function(), no inline handlers, no innerHTML.
 * Exposes window.DS (extended by the _render, _routing, _layout, _export files).
 */
(function () {
  'use strict';

  var DS = window.DS = window.DS || {};
  var SVGNS = 'http://www.w3.org/2000/svg';
  DS.SVGNS = SVGNS;

  // ------------------------------------------------------------------ text

  var ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  /* The ONE escaping helper: any string that must ever go into markup text
   * (an SVG file, an attribute in a serialised document) passes through it. */
  DS.esc = function (v) {
    return String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, function (c) { return ESC[c]; });
  };

  DS.fmtDate = function (iso) {
    if (!iso) return '';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  };

  DS.fmtBytes = function (n) {
    n = Number(n) || 0;
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KiB';
    return (n / 1048576).toFixed(1) + ' MiB';
  };

  // ------------------------------------------------------------------- DOM

  /* h('div', {class: 'x', text: 'y', 'aria-label': '…', dataset: {id: 1}}, [children])
   * Never accepts on* attributes: behaviour is bound with addEventListener. */
  DS.h = function (tag, attrs, children) {
    var e = document.createElement(tag);
    applyAttrs(e, attrs);
    appendKids(e, children);
    return e;
  };
  DS.s = function (tag, attrs, parent) {
    var e = document.createElementNS(SVGNS, tag);
    applyAttrs(e, attrs);
    if (parent) parent.appendChild(e);
    return e;
  };
  function applyAttrs(e, attrs) {
    if (!attrs) return;
    Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === undefined || v === null || v === false) return;
      if (/^on/i.test(k)) throw new Error('inline handlers are not allowed');
      if (k === 'text') e.textContent = v;
      else if (k === 'class') e.setAttribute('class', v);
      else if (k === 'dataset') Object.keys(v).forEach(function (d) { e.dataset[d] = v[d]; });
      else if (k === 'value' && 'value' in e) e.value = v;
      else if (k === 'checked' || k === 'disabled' || k === 'selected' || k === 'hidden') e[k] = !!v;
      else e.setAttribute(k, v === true ? '' : String(v));
    });
  }
  function appendKids(e, kids) {
    if (kids === undefined || kids === null) return;
    if (!Array.isArray(kids)) kids = [kids];
    kids.forEach(function (c) {
      if (c === null || c === undefined || c === false) return;
      e.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
    });
  }
  DS.icon = function (name, extra) {
    return DS.h('i', { class: 'bi bi-' + name + (extra ? ' ' + extra : ''), 'aria-hidden': 'true' });
  };
  DS.clear = function (e) { while (e && e.firstChild) e.removeChild(e.firstChild); return e; };
  DS.$ = function (sel, root) { return (root || document).querySelector(sel); };
  DS.$$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  /* Page-scoped document/window listeners (Turbo keeps `document` alive). */
  DS.on = function (target, type, fn, opts) {
    var o = opts || {};
    if (window.fwPageSignal && !o.signal) { var sig = window.fwPageSignal(); if (sig) o.signal = sig; }
    target.addEventListener(type, fn, o);
  };

  DS.debounce = function (fn, ms) {
    var t = null;
    var f = function () {
      var a = arguments, self = this;
      clearTimeout(t);
      t = setTimeout(function () { t = null; fn.apply(self, a); }, ms);
    };
    f.cancel = function () { clearTimeout(t); t = null; };
    return f;
  };

  DS.clone = function (o) { return o === undefined ? undefined : JSON.parse(JSON.stringify(o)); };

  // ---------------------------------------------------------------- config

  /* Parse the page's JSON island and resolve every endpoint. API paths are
   * the contract's (/diagram-studio/api/...), built from `base`, unless the
   * view supplies endpoints.<key>. */
  DS.config = function (id) {
    var node = document.getElementById(id || 'dsConfig');
    var cfg = {};
    if (node) { try { cfg = JSON.parse(node.textContent || '{}') || {}; } catch (e) { cfg = {}; } }
    var urls = document.getElementById('dsUrls');
    if (urls) { try { var u = JSON.parse(urls.textContent || '{}'); Object.keys(u).forEach(function (k) { if (cfg[k] === undefined) cfg[k] = u[k]; }); } catch (e) { /* ignore */ } }
    cfg.base = cfg.base || '/diagram-studio/';
    if (cfg.base.slice(-1) !== '/') cfg.base += '/';
    cfg.endpoints = cfg.endpoints || {};
    cfg.limits = cfg.limits || {};
    return cfg;
  };

  DS.Api = function (cfg) {
    var b = cfg.base + 'api/';
    var ep = cfg.endpoints || {};
    function pick(key, def) { return ep[key] || def; }
    function enc(v) { return encodeURIComponent(String(v)); }
    return {
      diagrams: function () { return pick('diagrams', b + 'diagrams'); },
      diagram: function (id) { return pick('diagrams', b + 'diagrams').replace(/\/$/, '') + '/' + enc(id); },
      list: function () { return pick('list', b + 'diagrams'); },
      duplicate: function (id) { return this.diagram(id) + '/duplicate'; },
      versions: function (id) { return this.diagram(id) + '/versions'; },
      version: function (id, n) { return this.diagram(id) + '/versions/' + enc(n); },
      restore: function (id, n) { return this.diagram(id) + '/versions/' + enc(n) + '/restore'; },
      diff: function (id, a, bb) { return this.diagram(id) + '/diff?a=' + enc(a) + '&b=' + enc(bb); },
      publish: function (id) { return this.diagram(id) + '/publish'; },
      folders: function () { return pick('folders', b + 'folders'); },
      folder: function (id) { return pick('folders', b + 'folders').replace(/\/$/, '') + '/' + enc(id); },
      imports: function () { return pick('imports', b + 'imports'); },
      importPages: function () { return pick('importPages', b + 'imports/pages'); },
      job: function (id) { return pick('imports', b + 'imports').replace(/\/$/, '') + '/' + enc(id); },
      jobResult: function (id) { return this.job(id) + '/result'; },
      jobAccept: function (id) { return this.job(id) + '/accept'; },
      jobThumb: function (id, page) { return this.job(id) + '/thumbnail/' + enc(page); },
      exportUrl: function (fmt) { return pick('export', b + 'export').replace(/\/$/, '') + '/' + enc(fmt); },
      libraries: function () { return pick('libraries', b + 'libraries'); },
      library: function (id) { return pick('libraries', b + 'libraries').replace(/\/$/, '') + '/' + enc(id); },
      symbolSvg: function (lib, sym) {
        var base = cfg.symbolsUrl || pick('libraries', b + 'libraries');
        return base.replace(/\/$/, '') + '/' + enc(lib) + '/' + enc(sym) + '.svg';
      },
      categories: function () { return pick('categories', b + 'categories'); },
      editorPage: function (id) { return cfg.base + enc(id) + '/edit'; },
      reviewPage: function (job) { return cfg.base + 'import/' + enc(job) + '/review'; }
    };
  };

  // ------------------------------------------------------------------ HTTP

  DS.csrf = function () {
    var m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.getAttribute('content') : '';
  };

  /* JSON request. Resolves {ok, status, data, response}; rejects only on a
   * network failure, with a plain-English message. */
  DS.http = function (method, url, body, opts) {
    opts = opts || {};
    var init = { method: method, credentials: 'same-origin', headers: { 'Accept': 'application/json' } };
    if (method !== 'GET' && method !== 'HEAD') init.headers['X-CSRFToken'] = DS.csrf();
    if (body instanceof FormData) init.body = body;
    else if (body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
    if (opts.signal) init.signal = opts.signal;
    return fetch(url, init).then(function (r) {
      if (opts.raw) return { ok: r.ok, status: r.status, data: null, response: r };
      var ct = r.headers.get('Content-Type') || '';
      var p = ct.indexOf('json') >= 0 ? r.json().catch(function () { return null; }) : r.text().then(function (t) { return { error: t && t.length < 300 ? t : null }; });
      return p.then(function (d) { return { ok: r.ok, status: r.status, data: d, response: r }; });
    }, function (err) {
      if (err && err.name === 'AbortError') throw err;
      throw new Error('The server could not be reached. Check the connection and try again.');
    });
  };

  /* Plain-English message of a failed response. */
  DS.errorText = function (res, what) {
    var m = res && res.data && res.data.error;
    var s = res ? res.status : 0;
    if (m && !(s === 403 && /^forbidden$/i.test(String(m)))) return String(m);
    var pre = what ? what + ': ' : '';
    if (s === 403) return pre + 'you do not have permission to do this.';
    if (s === 404) return pre + 'it no longer exists.';
    if (s === 409) return pre + 'someone else changed it first.';
    if (s === 413) return pre + 'the upload is larger than the server accepts.';
    if (s >= 500) return pre + 'the server failed (HTTP ' + s + '). Try again or check the logs.';
    return pre + 'the request failed (HTTP ' + s + ').';
  };

  DS.download = function (blob, name) {
    var href = URL.createObjectURL(blob);
    var a = DS.h('a', { href: href, download: name || 'download', rel: 'noopener', 'data-turbo': 'false' });
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(href); a.remove(); }, 1500);
  };

  /* A file-name-safe form of a diagram or page name, the same rule as the
   * server's exporters: ß -> ss, NFKD, combining marks dropped (Prüfung ->
   * Prufung, Zürich -> Zurich), then every run outside [A-Za-z0-9._-]
   * becomes one "-", trimmed of "-" and ".". */
  DS.safeName = function (name, max, fallback) {
    var s = String(name === null || name === undefined ? '' : name).replace(/\u00DF/g, 'ss').replace(/\u1E9E/g, 'SS');
    if (s.normalize) s = s.normalize('NFKD');
    s = s.replace(/[\u0300-\u036f\u1AB0-\u1AFF\u1DC0-\u1DFF\u20D0-\u20FF\uFE20-\uFE2F]/g, '');
    s = s.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^[-.]+|[-.]+$/g, '');
    s = s.slice(0, max || 100).replace(/[-.]+$/g, '');
    return s || (fallback === undefined ? 'diagram' : fallback);
  };

  DS.filenameFrom = function (resp, fallback) {
    var cd = resp && resp.headers ? (resp.headers.get('Content-Disposition') || '') : '';
    var m = /filename\*=UTF-8''([^;]+)/i.exec(cd) || /filename="?([^";]+)"?/i.exec(cd);
    if (m) { try { return decodeURIComponent(m[1]); } catch (e) { return m[1]; } }
    return fallback;
  };

  // --------------------------------------------------------- toasts, dialogs

  function toastHost() {
    var host = document.getElementById('dsToasts');
    if (!host) {
      host = DS.h('div', { id: 'dsToasts', class: 'ds-toasts', role: 'status', 'aria-live': 'polite' });
      document.body.appendChild(host);
    }
    return host;
  }
  var TOAST_ICON = { success: 'check-circle-fill', danger: 'x-octagon-fill', warning: 'exclamation-triangle-fill', info: 'info-circle-fill' };
  /* Status is never colour-only: icon + word + text. */
  DS.toast = function (msg, kind, ms) {
    kind = kind || 'info';
    var word = { success: 'Done', danger: 'Error', warning: 'Warning', info: 'Note' }[kind] || 'Note';
    var t = DS.h('div', { class: 'ds-toast ds-toast-' + kind, role: kind === 'danger' ? 'alert' : 'status' }, [
      DS.icon(TOAST_ICON[kind] || 'info-circle-fill'),
      DS.h('strong', { text: word + ':' }), ' ', DS.h('span', { text: msg })
    ]);
    var close = DS.h('button', { type: 'button', class: 'btn-close btn-sm ms-auto', 'aria-label': 'Dismiss' });
    close.addEventListener('click', function () { t.remove(); });
    t.appendChild(close);
    var host = toastHost();
    host.appendChild(t);
    while (host.children.length > 3) host.removeChild(host.firstChild);
    setTimeout(function () { t.remove(); }, ms || (kind === 'danger' ? 9000 : 4000));
    return t;
  };

  /* Screen-reader announcement without a visible toast. */
  DS.announce = function (msg) {
    var r = document.getElementById('dsAnnounce');
    if (!r) { r = DS.h('div', { id: 'dsAnnounce', class: 'visually-hidden', role: 'status', 'aria-live': 'polite' }); document.body.appendChild(r); }
    r.textContent = '';
    setTimeout(function () { r.textContent = msg; }, 30);
  };

  /* A light modal built on Bootstrap's Modal (vendored). Resolves with the
   * pressed button's value; `body` is a node or text. */
  DS.dialog = function (opts) {
    return new Promise(function (resolve) {
      var id = 'dsDlg' + Math.random().toString(36).slice(2, 8);
      var footer = DS.h('div', { class: 'modal-footer' });
      var bodyNode = typeof opts.body === 'string' ? DS.h('p', { class: 'mb-0', text: opts.body }) : opts.body;
      var dlg = DS.h('div', { class: 'modal fade ds-modal', id: id, tabindex: '-1', 'aria-labelledby': id + 't', 'aria-modal': 'true', role: 'dialog' }, [
        DS.h('div', { class: 'modal-dialog modal-dialog-centered' + (opts.size ? ' modal-' + opts.size : '') + (opts.scroll ? ' modal-dialog-scrollable' : '') }, [
          DS.h('div', { class: 'modal-content' }, [
            DS.h('div', { class: 'modal-header' }, [
              DS.h('h2', { class: 'modal-title h5', id: id + 't', text: opts.title || '' }),
              DS.h('button', { type: 'button', class: 'btn-close', 'data-bs-dismiss': 'modal', 'aria-label': 'Close' })
            ]),
            DS.h('div', { class: 'modal-body' }, bodyNode),
            footer
          ])
        ])
      ]);
      var result = null;
      (opts.buttons || [{ label: 'OK', value: true, primary: true }]).forEach(function (b) {
        var btn = DS.h('button', { type: 'button', class: 'btn btn-sm ' + (b.danger ? 'btn-fw-danger' : b.primary ? 'btn-fw-primary' : 'btn-fw-secondary'), text: b.label });
        if (b.primary) btn.dataset.primary = '1';
        btn.addEventListener('click', function () {
          if (b.validate && !b.validate()) return;
          result = typeof b.value === 'function' ? b.value() : b.value;
          hide();
        });
        footer.appendChild(btn);
      });
      document.body.appendChild(dlg);
      var bs = window.bootstrap && window.bootstrap.Modal ? new window.bootstrap.Modal(dlg) : null;
      function hide() { if (bs) bs.hide(); else done(); }
      function done() { dlg.remove(); resolve(result); }
      dlg.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter' && ev.target.tagName === 'INPUT') {
          var p = dlg.querySelector('[data-primary]');
          if (p) { ev.preventDefault(); p.click(); }
        }
      });
      if (bs) {
        dlg.addEventListener('hidden.bs.modal', done);
        dlg.addEventListener('shown.bs.modal', function () {
          var f = dlg.querySelector('input,select,textarea') || dlg.querySelector('[data-primary]');
          if (f) { f.focus(); if (f.select) f.select(); }
        });
        bs.show();
      } else {
        dlg.classList.add('show'); dlg.style.display = 'block';
      }
      if (opts.onOpen) opts.onOpen(dlg);
    });
  };

  DS.confirm = function (title, text, okLabel, danger) {
    return DS.dialog({ title: title, body: text, buttons: [
      { label: 'Cancel', value: false },
      { label: okLabel || 'OK', value: true, primary: !danger, danger: !!danger }
    ] });
  };

  DS.prompt = function (title, label, value, opts) {
    opts = opts || {};
    var inp = DS.h('input', { type: 'text', class: 'form-control', value: value || '', maxlength: opts.max || 200, 'aria-label': label });
    var err = DS.h('div', { class: 'invalid-feedback' });
    var body = DS.h('div', null, [DS.h('label', { class: 'form-label', text: label }), inp, err]);
    return DS.dialog({ title: title, body: body, buttons: [
      { label: 'Cancel', value: null },
      { label: opts.ok || 'OK', primary: true, value: function () { return inp.value.trim(); },
        validate: function () {
          var v = inp.value.trim();
          var msg = !v ? 'A name is required.' : (opts.validate ? opts.validate(v) : '');
          inp.classList.toggle('is-invalid', !!msg);
          err.textContent = msg || '';
          return !msg;
        } }
    ] });
  };

  DS.badge = function (kind, text, iconName) {
    return DS.h('span', { class: 'fw-badge fw-badge-' + kind + ' ds-badge' }, [iconName ? DS.icon(iconName) : null, iconName ? ' ' : null, text]);
  };

  // ----------------------------------------------------------------- model

  var M = DS.model = {};
  M.SCHEMA = 'satom.diagram/1';
  M.SHAPES = ['rect', 'round', 'ellipse', 'diamond', 'hexagon', 'parallelogram', 'trapezoid', 'triangle',
    'cylinder', 'cloud', 'document', 'note', 'process', 'terminator', 'actor', 'pill', 'zone', 'swimlane',
    'table', 'polygon', 'path', 'symbol', 'line'];
  M.KINDS = ['shape', 'text', 'image', 'container'];
  M.ARROWS = ['none', 'arrow', 'open', 'diamond', 'diamond_open', 'circle', 'circle_open', 'crowfoot', 'bar'];
  M.ROUTINGS = ['straight', 'orthogonal', 'curved'];
  M.LOW_CONFIDENCE = 0.6;
  M.STYLE = { fill: '#FFFFFF', stroke: '#1F2937', stroke_width: 1, dashed: false, opacity: 1, rounded: false,
    font_color: '#111827', font_size: 12, font_family: '', bold: false, italic: false, align: 'center', valign: 'middle',
    fill_opacity: 1, stroke_opacity: 1, dash_pattern: 'solid', gradient: { type: 'none', color: '#FFFFFF', angle: 90 },
    shadow: false, shadow_color: '#000000' };
  M.CSTYLE = { stroke: '#1F2937', stroke_width: 1, dashed: false, font_color: '#111827', opacity: 1,
    stroke_opacity: 1, dash_pattern: 'solid', shadow: false, shadow_color: '#000000' };
  M.DASH_PATTERNS = ['solid', 'dashed', 'dotted', 'dash-dot'];
  M.GRADIENT_TYPES = ['none', 'linear', 'radial'];
  /* The style's dash pattern: the server's rule (model._style) -- `dashed`
   * decides on/off, `dash_pattern` refines an "on". */
  M.dashPattern = function (st) {
    var p = st && st.dash_pattern;
    if (!st || !st.dashed) return 'solid';
    return p && p !== 'solid' && M.DASH_PATTERNS.indexOf(p) >= 0 ? p : 'dashed';
  };
  M.ID_RE = /^[A-Za-z0-9_.:\-]{1,64}$/;
  M.COLOR_RE = /^#[0-9A-Fa-f]{6}$/;
  M.CATEGORY_RE = /^[a-z][a-z0-9_]{0,31}(\.[a-z0-9_]{1,40}){0,3}$/;

  M.newId = function (prefix) {
    var s = '';
    var a = new Uint8Array(6);
    (window.crypto || window.msCrypto).getRandomValues(a);
    for (var i = 0; i < a.length; i++) s += (a[i] < 16 ? '0' : '') + a[i].toString(16);
    return (prefix || 'e') + s;
  };

  function fillStyle(st, def) {
    var o = {};
    st = st || {};
    Object.keys(def).forEach(function (k) {
      var v = st[k] === undefined ? def[k] : st[k];
      o[k] = v && typeof v === 'object' ? DS.clone(v) : v;     // never share a default object (gradient)
    });
    return o;
  }

  /* Missing keys get their model default (the server's normalise() is the
   * authority; this keeps the editor from ever reading undefined). */
  M.fillElement = function (e, layer) {
    var d = { id: M.newId('e'), kind: 'shape', shape: 'rect', symbol: '', category: '', name: '', description: '', text: '',
      x: 0, y: 0, w: 120, h: 60, rotation: 0, layer: layer || '', parent: '', points: [], path: '', image: '',
      ports: [], rows: [], properties: {}, metadata: {}, source_ref: '', confidence: 1, native: {} };
    Object.keys(d).forEach(function (k) { if (e[k] === undefined || e[k] === null) e[k] = d[k]; });
    e.style = fillStyle(e.style, M.STYLE);
    return e;
  };
  M.fillConnector = function (c, layer) {
    var d = { id: M.newId('c'), source: '', target: '', source_port: '', target_port: '', start: [], end: [], points: [],
      routing: 'straight', start_arrow: 'none', end_arrow: 'arrow', direction: 'forward', label: '', labels: [], kind: '',
      layer: layer || '', properties: {}, metadata: {}, source_ref: '', confidence: 1, native: {} };
    Object.keys(d).forEach(function (k) { if (c[k] === undefined || c[k] === null) c[k] = d[k]; });
    c.style = fillStyle(c.style, M.CSTYLE);
    return c;
  };
  M.direction = function (c) {
    var s = c.start_arrow !== 'none', t = c.end_arrow !== 'none';
    return s && t ? 'both' : t ? 'forward' : s ? 'backward' : 'none';
  };
  M.newPage = function (name) {
    var lid = M.newId('l');
    return { id: M.newId('page-'), name: name || 'Page', width: 1600, height: 1000, background: '',
      layers: [{ id: lid, name: 'Default', visible: true, locked: false }], groups: [], elements: [], connectors: [] };
  };
  M.fillDoc = function (doc) {
    doc = doc || {};
    doc.schema = M.SCHEMA;
    doc.name = doc.name || 'Untitled diagram';
    doc.metadata = doc.metadata || {};
    doc.source = doc.source || { format: '', filename: '', sha256: '', page: '' };
    doc.recognition = doc.recognition || { engine: '', version: '', warnings: [], stats: {} };
    if (!Array.isArray(doc.pages) || !doc.pages.length) doc.pages = [M.newPage('Page 1')];
    doc.pages.forEach(function (p, i) {
      p.id = p.id || 'page-' + (i + 1);
      p.name = p.name || 'Page ' + (i + 1);
      p.width = p.width || 1600; p.height = p.height || 1000;
      if (p.background === undefined) p.background = '';
      if (!Array.isArray(p.layers) || !p.layers.length) p.layers = [{ id: 'layer-1', name: 'Default', visible: true, locked: false }];
      p.groups = p.groups || []; p.elements = p.elements || []; p.connectors = p.connectors || [];
      var l0 = p.layers[0].id;
      p.elements.forEach(function (e) { M.fillElement(e, l0); });
      p.connectors.forEach(function (c) { M.fillConnector(c, l0); });
    });
    return doc;
  };
  M.stats = function (doc) {
    var els = [], cons = [];
    (doc.pages || []).forEach(function (p) { els = els.concat(p.elements || []); cons = cons.concat(p.connectors || []); });
    return {
      elements: els.length, connectors: cons.length,
      dangling: cons.filter(function (c) { return !(c.source && c.target); }).length,
      low: els.filter(function (e) { return (e.confidence === undefined ? 1 : e.confidence) < M.LOW_CONFIDENCE; }).length,
      unclassified: els.filter(function (e) { return e.kind === 'shape' && !e.category; }).length
    };
  };
  /* "generic/router" -> {lib, sym} */
  M.splitSymbol = function (ref) {
    var i = (ref || '').indexOf('/');
    return i > 0 ? { lib: ref.slice(0, i), sym: ref.slice(i + 1) } : null;
  };

  // -------------------------------------------------------------- geometry

  var G = DS.geom = {};
  G.center = function (e) { return [e.x + e.w / 2, e.y + e.h / 2]; };
  G.rotate = function (px, py, cx, cy, deg) {
    if (!deg) return [px, py];
    var a = deg * Math.PI / 180, c = Math.cos(a), s = Math.sin(a);
    var dx = px - cx, dy = py - cy;
    return [cx + dx * c - dy * s, cy + dx * s + dy * c];
  };
  /* Axis-aligned bounds of an element, rotation included. */
  G.bbox = function (e) {
    if (!e.rotation) return { x: e.x, y: e.y, w: e.w, h: e.h };
    var c = G.center(e);
    var pts = [[e.x, e.y], [e.x + e.w, e.y], [e.x + e.w, e.y + e.h], [e.x, e.y + e.h]].map(function (p) { return G.rotate(p[0], p[1], c[0], c[1], e.rotation); });
    var xs = pts.map(function (p) { return p[0]; }), ys = pts.map(function (p) { return p[1]; });
    var x0 = Math.min.apply(null, xs), y0 = Math.min.apply(null, ys);
    return { x: x0, y: y0, w: Math.max.apply(null, xs) - x0, h: Math.max.apply(null, ys) - y0 };
  };
  G.union = function (boxes) {
    if (!boxes.length) return null;
    var x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    boxes.forEach(function (b) { x0 = Math.min(x0, b.x); y0 = Math.min(y0, b.y); x1 = Math.max(x1, b.x + b.w); y1 = Math.max(y1, b.y + b.h); });
    return { x: x0, y: y0, w: x1 - x0, h: y1 - y0 };
  };
  G.intersects = function (a, b) { return a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h; };
  G.contains = function (a, b) { return b.x >= a.x && b.y >= a.y && b.x + b.w <= a.x + a.w && b.y + b.h <= a.y + a.h; };
  G.inside = function (e, px, py) {
    var c = G.center(e);
    var p = G.rotate(px, py, c[0], c[1], -(e.rotation || 0));
    return p[0] >= e.x && p[0] <= e.x + e.w && p[1] >= e.y && p[1] <= e.y + e.h;
  };
  G.portXY = function (e, port) {
    var c = G.center(e);
    return G.rotate(e.x + port.x * e.w, e.y + port.y * e.h, c[0], c[1], e.rotation || 0);
  };
  G.dist2 = function (a, b) { var dx = a[0] - b[0], dy = a[1] - b[1]; return dx * dx + dy * dy; };
  /* Distance from p to segment ab and the parameter t of the projection. */
  G.segDist = function (p, a, b) {
    var dx = b[0] - a[0], dy = b[1] - a[1];
    var L = dx * dx + dy * dy;
    var t = L ? Math.max(0, Math.min(1, ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / L)) : 0;
    var x = a[0] + t * dx, y = a[1] + t * dy;
    return { d: Math.sqrt((p[0] - x) * (p[0] - x) + (p[1] - y) * (p[1] - y)), t: t, x: x, y: y };
  };
  G.snap = function (v, grid) { return grid > 0 ? Math.round(v / grid) * grid : v; };
  G.round = function (v) { return Math.round(v * 100) / 100; };

  /* A simple uniform-grid spatial index over boxes. */
  G.Index = function (cell) {
    this.cell = cell || 200;
    this.map = new Map();
    this.boxes = new Map();
  };
  G.Index.prototype._keys = function (b) {
    var c = this.cell, out = [];
    var x0 = Math.floor(b.x / c), x1 = Math.floor((b.x + b.w) / c), y0 = Math.floor(b.y / c), y1 = Math.floor((b.y + b.h) / c);
    if ((x1 - x0 + 1) * (y1 - y0 + 1) > 400) { out.push('big'); return out; }
    for (var i = x0; i <= x1; i++) for (var j = y0; j <= y1; j++) out.push(i + ',' + j);
    return out;
  };
  G.Index.prototype.set = function (id, box) {
    this.remove(id);
    var keys = this._keys(box);
    var self = this;
    keys.forEach(function (k) { var s = self.map.get(k); if (!s) { s = new Set(); self.map.set(k, s); } s.add(id); });
    this.boxes.set(id, { box: box, keys: keys });
  };
  G.Index.prototype.remove = function (id) {
    var r = this.boxes.get(id);
    if (!r) return;
    var self = this;
    r.keys.forEach(function (k) { var s = self.map.get(k); if (s) s.delete(id); });
    this.boxes.delete(id);
  };
  G.Index.prototype.query = function (b) {
    var out = new Set(), self = this;
    this._keys(b).concat(['big']).forEach(function (k) {
      var s = self.map.get(k);
      if (s) s.forEach(function (id) { if (G.intersects(self.boxes.get(id).box, b)) out.add(id); });
    });
    return Array.from(out);
  };

  // ----------------------------------------------------------------- Store

  /* The command stack. A transaction records the BEFORE snapshot of every
   * object it touches (by kind + id, on the current page), and at commit the
   * AFTER snapshot; undo/redo swap them. Z-order changes snapshot the id
   * order of the touched arrays. Drags mutate live inside one open
   * transaction, so a drag of 300 elements is one undo step. */
  var KINDS = { el: 'elements', conn: 'connectors', group: 'groups', layer: 'layers' };

  function Store(doc, opts) {
    this.doc = M.fillDoc(doc);
    this.pageIndex = 0;
    this.undoStack = [];
    this.redoStack = [];
    this.limit = (opts && opts.limit) || 500;
    this.listeners = [];
    this.tx = null;
    this.revision = 0;
    this.savedRevision = 0;
    this._maps = new WeakMap();
  }
  DS.Store = Store;

  Store.prototype.page = function (i) { return this.doc.pages[i === undefined ? this.pageIndex : i]; };
  Store.prototype.pageById = function (id) {
    for (var i = 0; i < this.doc.pages.length; i++) if (this.doc.pages[i].id === id) return this.doc.pages[i];
    return null;
  };
  /* id -> object maps per page and kind, rebuilt lazily when the array changes. */
  Store.prototype.map = function (kind, page) {
    page = page || this.page();
    var arr = page[KINDS[kind]];
    var cache = this._maps.get(arr);
    if (!cache || cache.n !== arr.length || cache.rev !== this.revision) {
      var m = new Map();
      for (var i = 0; i < arr.length; i++) m.set(arr[i].id, arr[i]);
      cache = { m: m, n: arr.length, rev: this.revision };
      this._maps.set(arr, cache);
    }
    return cache.m;
  };
  Store.prototype.get = function (kind, id, page) { return this.map(kind, page).get(id) || null; };
  Store.prototype.el = function (id) { return this.get('el', id); };
  Store.prototype.conn = function (id) { return this.get('conn', id); };
  Store.prototype.layer = function (id) { return this.get('layer', id); };
  Store.prototype.onChange = function (fn) { this.listeners.push(fn); };
  Store.prototype.emit = function (ch) { var self = this; this.listeners.forEach(function (fn) { fn(ch, self); }); };
  Store.prototype.dirty = function () { return this.revision !== this.savedRevision; };
  Store.prototype.markSaved = function () { this.savedRevision = this.revision; };

  function Tx(store, label, opts) {
    this.store = store;
    this.label = label;
    this.coalesce = opts && opts.coalesce;
    this.pageId = store.page().id;
    this.recs = new Map();     // kind:id -> {kind, id, before, beforeIndex}
    this.orders = new Map();   // kind -> before order
    this.pageMeta = null;      // before snapshot of the page meta
    this.pagesBefore = null;   // full pages array snapshot (page add/delete/reorder)
    this.changed = { els: new Set(), conns: new Set(), structural: false };
  }
  Tx.prototype.touch = function (kind, id) {
    var key = kind + ':' + id;
    if (this.recs.has(key)) return this.store.get(kind, id);
    var page = this.store.pageById(this.pageId);
    var arr = page[KINDS[kind]];
    var idx = -1;
    for (var i = 0; i < arr.length; i++) if (arr[i].id === id) { idx = i; break; }
    this.recs.set(key, { kind: kind, id: id, before: idx >= 0 ? DS.clone(arr[idx]) : null, beforeIndex: idx });
    this._mark(kind, id);
    return idx >= 0 ? arr[idx] : null;
  };
  Tx.prototype._mark = function (kind, id) {
    if (kind === 'el') this.changed.els.add(id);
    else if (kind === 'conn') this.changed.conns.add(id);
    else this.changed.structural = true;
  };
  Tx.prototype.add = function (kind, obj, index) {
    var key = kind + ':' + obj.id;
    if (!this.recs.has(key)) this.recs.set(key, { kind: kind, id: obj.id, before: null, beforeIndex: -1 });
    var arr = this.store.pageById(this.pageId)[KINDS[kind]];
    if (index === undefined || index < 0 || index > arr.length) arr.push(obj); else arr.splice(index, 0, obj);
    this.store.revision++;
    this._mark(kind, obj.id);
    if (kind === 'el' || kind === 'conn') this.changed.structural = this.changed.structural || false;
    this.changed.added = true;
    return obj;
  };
  Tx.prototype.remove = function (kind, id) {
    this.touch(kind, id);
    var arr = this.store.pageById(this.pageId)[KINDS[kind]];
    for (var i = 0; i < arr.length; i++) if (arr[i].id === id) { arr.splice(i, 1); break; }
    this.store.revision++;
    this.changed.removed = true;
  };
  Tx.prototype.order = function (kind) {
    if (this.orders.has(kind)) return;
    this.orders.set(kind, this.store.pageById(this.pageId)[KINDS[kind]].map(function (o) { return o.id; }));
    this.changed.structural = true;
    this.changed.order = true;
  };
  Tx.prototype.meta = function () {
    if (this.pageMeta) return;
    var p = this.store.pageById(this.pageId);
    this.pageMeta = { name: p.name, width: p.width, height: p.height, background: p.background };
    this.changed.structural = true;
  };
  Tx.prototype.pages = function () {
    if (this.pagesBefore) return;
    this.pagesBefore = DS.clone(this.store.doc.pages);
    this.pagesIndexBefore = this.store.pageIndex;
    this.changed.structural = true;
    this.changed.pages = true;
  };

  Store.prototype.begin = function (label, opts) {
    if (this.tx) this.commit();
    this.tx = new Tx(this, label, opts);
    return this.tx;
  };
  /* Run fn(tx) in one transaction and commit. */
  Store.prototype.run = function (label, fn, opts) {
    var tx = this.begin(label, opts);
    try { fn(tx); } catch (e) { this.rollback(); throw e; }
    return this.commit();
  };
  Store.prototype.rollback = function () {
    var tx = this.tx;
    if (!tx) return;
    this.tx = null;
    var cmd = this._finish(tx);
    if (cmd) { this._apply(cmd, 'before'); this.revision++; this.emit(cmd.changed); }
  };
  Store.prototype._finish = function (tx) {
    var page = this.pageById(tx.pageId) || this.page();
    var self = this;
    var recs = [];
    tx.recs.forEach(function (r) {
      var arr = page[KINDS[r.kind]];
      var idx = -1;
      for (var i = 0; i < arr.length; i++) if (arr[i].id === r.id) { idx = i; break; }
      var after = idx >= 0 ? DS.clone(arr[idx]) : null;
      if (JSON.stringify(after) === JSON.stringify(r.before) && !tx.orders.has(r.kind)) return;
      recs.push({ kind: r.kind, id: r.id, before: r.before, beforeIndex: r.beforeIndex, after: after, afterIndex: idx });
    });
    var orders = [];
    tx.orders.forEach(function (before, kind) {
      var after = page[KINDS[kind]].map(function (o) { return o.id; });
      if (before.join('\u0001') !== after.join('\u0001')) orders.push({ kind: kind, before: before, after: after });
    });
    var meta = null;
    if (tx.pageMeta) {
      var am = { name: page.name, width: page.width, height: page.height, background: page.background };
      if (JSON.stringify(am) !== JSON.stringify(tx.pageMeta)) meta = { before: tx.pageMeta, after: am };
    }
    var pages = null;
    if (tx.pagesBefore) pages = { before: tx.pagesBefore, after: DS.clone(self.doc.pages), ib: tx.pagesIndexBefore, ia: self.pageIndex };
    if (!recs.length && !orders.length && !meta && !pages) return null;
    return { label: tx.label, pageId: tx.pageId, recs: recs, orders: orders, meta: meta, pages: pages,
      coalesce: tx.coalesce, time: Date.now(), changed: tx.changed };
  };
  Store.prototype.commit = function () {
    var tx = this.tx;
    if (!tx) return null;
    this.tx = null;
    var cmd = this._finish(tx);
    if (!cmd) return null;
    var top = this.undoStack[this.undoStack.length - 1];
    if (cmd.coalesce && top && top.coalesce === cmd.coalesce && cmd.time - top.time < 1200 && top.pageId === cmd.pageId && !cmd.pages && !top.pages) {
      // merge: keep top's BEFORE, take cmd's AFTER
      var byKey = new Map(top.recs.map(function (r) { return [r.kind + ':' + r.id, r]; }));
      cmd.recs.forEach(function (r) {
        var o = byKey.get(r.kind + ':' + r.id);
        if (o) { o.after = r.after; o.afterIndex = r.afterIndex; } else top.recs.push(r);
      });
      top.time = cmd.time;
      cmd.changed.els.forEach(function (id) { top.changed.els.add(id); });
      cmd.changed.conns.forEach(function (id) { top.changed.conns.add(id); });
    } else {
      this.undoStack.push(cmd);
      if (this.undoStack.length > this.limit) this.undoStack.shift();
    }
    this.redoStack = [];
    this.revision++;
    this.emit(cmd.changed);
    return cmd;
  };
  Store.prototype._apply = function (cmd, side) {
    var self = this;
    if (cmd.pages) {
      this.doc.pages = DS.clone(cmd.pages[side]);
      this.pageIndex = Math.min(side === 'before' ? cmd.pages.ib : cmd.pages.ia, this.doc.pages.length - 1);
      return;
    }
    var page = this.pageById(cmd.pageId);
    if (!page) return;
    var pi = this.doc.pages.indexOf(page);
    if (pi >= 0) this.pageIndex = pi;
    var idxKey = side === 'before' ? 'beforeIndex' : 'afterIndex';
    // removals first, then inserts in index order, then replacements
    cmd.recs.forEach(function (r) {
      var arr = page[KINDS[r.kind]];
      if (r[side] === null) {
        for (var i = 0; i < arr.length; i++) if (arr[i].id === r.id) { arr.splice(i, 1); break; }
      }
    });
    cmd.recs.filter(function (r) { return r[side] !== null; }).sort(function (a, b) { return a[idxKey] - b[idxKey]; }).forEach(function (r) {
      var arr = page[KINDS[r.kind]];
      var obj = DS.clone(r[side]);
      for (var i = 0; i < arr.length; i++) if (arr[i].id === r.id) { arr[i] = obj; return; }
      var at = r[idxKey];
      if (at < 0 || at > arr.length) arr.push(obj); else arr.splice(at, 0, obj);
    });
    cmd.orders.forEach(function (o) {
      var arr = page[KINDS[o.kind]];
      var pos = new Map(o[side].map(function (id, i) { return [id, i]; }));
      arr.sort(function (a, b) { return (pos.has(a.id) ? pos.get(a.id) : 1e9) - (pos.has(b.id) ? pos.get(b.id) : 1e9); });
    });
    if (cmd.meta) Object.assign(page, cmd.meta[side]);
    self.revision++;
  };
  Store.prototype.canUndo = function () { return this.undoStack.length > 0; };
  Store.prototype.canRedo = function () { return this.redoStack.length > 0; };
  Store.prototype.undo = function () {
    if (this.tx) this.commit();
    var cmd = this.undoStack.pop();
    if (!cmd) return null;
    this._apply(cmd, 'before');
    this.redoStack.push(cmd);
    this.emit(Object.assign({}, cmd.changed, { structural: true, undo: true }));
    return cmd;
  };
  Store.prototype.redo = function () {
    var cmd = this.redoStack.pop();
    if (!cmd) return null;
    this._apply(cmd, 'after');
    this.undoStack.push(cmd);
    this.emit(Object.assign({}, cmd.changed, { structural: true, redo: true }));
    return cmd;
  };
  /* Replace the whole document (reload after a conflict, version restore). */
  Store.prototype.replace = function (doc) {
    this.doc = M.fillDoc(doc);
    this.pageIndex = Math.min(this.pageIndex, this.doc.pages.length - 1);
    this.undoStack = []; this.redoStack = [];
    this.revision++;
    this.savedRevision = this.revision;
    this.emit({ els: new Set(), conns: new Set(), structural: true, pages: true });
  };
  /* Everything connected to the given elements on the current page. */
  Store.prototype.connectorsOf = function (ids) {
    var set = ids instanceof Set ? ids : new Set(ids);
    return this.page().connectors.filter(function (c) { return set.has(c.source) || set.has(c.target); });
  };
  Store.prototype.groupOf = function (id) {
    var gs = this.page().groups;
    for (var i = 0; i < gs.length; i++) if (gs[i].members.indexOf(id) >= 0) return gs[i];
    return null;
  };
  Store.prototype.childrenOf = function (id) {
    var out = [], page = this.page();
    var stack = [id], seen = new Set([id]);
    while (stack.length) {
      var cur = stack.pop();
      for (var i = 0; i < page.elements.length; i++) {
        var e = page.elements[i];
        if (e.parent === cur && !seen.has(e.id)) { seen.add(e.id); out.push(e); stack.push(e.id); }
      }
    }
    return out;
  };
})();
