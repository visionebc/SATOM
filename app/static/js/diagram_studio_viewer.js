/* diagram_studio_viewer.js — read-only viewer of a PUBLISHED diagram.
 *
 * Reuses the editor's renderer: pan/zoom/fit, minimap, page tabs, layer
 * toggles (local, never saved), search, a read-only inspector on click, the
 * list view, and the "Export to" menu (GET /diagrams/<id>/export/<fmt>).
 */
(function () {
  'use strict';
  var DS = window.DS, h = DS.h, G = DS.geom;
  var root = document.getElementById('dsViewer');
  if (!root || root.dataset.dsBooted) return;
  root.dataset.dsBooted = '1';
  var cfg = DS.config(), api = DS.Api(cfg);
  var doc = DS.model.fillDoc(cfg.doc || null);
  var pageIndex = 0, picked = null;
  var svg = document.getElementById('dvCanvas');
  var r = new DS.Renderer(svg, {
    symbolUrl: function (l, s) { return api.symbolSvg(l, s); },
    decorate: function (e) { return picked && picked.kind === 'el' && picked.id === e.id ? 'ds-hl' : ''; }
  });
  var mm = new DS.Minimap(document.getElementById('dvMinimap'), r);
  var tabs = document.getElementById('dvTabs');
  var insp = document.getElementById('dvInspector');
  var layersEl = document.getElementById('dvLayers');
  var search = document.getElementById('dvSearch'), results = document.getElementById('dvResults');
  var list = document.getElementById('dvList'), wrap = document.getElementById('dvWrap');
  var hl = DS.s('g', { class: 'ds-ov-sel' }, r.overlay);

  function page() { return doc.pages[pageIndex]; }
  function show(i) {
    pageIndex = i; picked = null;
    r.setPage(page()); r.setGrid(false);
    renderTabs(); renderLayers(); inspect(null); runSearch();
    requestAnimationFrame(function () { r.fit(); mm.draw(); });
    if (!list.hidden) drawList();
  }
  function renderTabs() {
    DS.clear(tabs);
    if (doc.pages.length < 2) { tabs.hidden = true; return; }
    tabs.hidden = false;
    doc.pages.forEach(function (p, i) {
      var t = h('button', { type: 'button', role: 'tab', class: 'ds-tab' + (i === pageIndex ? ' active' : ''), 'aria-selected': i === pageIndex ? 'true' : 'false', tabindex: i === pageIndex ? '0' : '-1', text: p.name });
      t.addEventListener('click', function () { show(i); });
      t.addEventListener('keydown', function (ev) {
        if (ev.key !== 'ArrowRight' && ev.key !== 'ArrowLeft') return;
        ev.preventDefault();
        var j = (i + (ev.key === 'ArrowRight' ? 1 : -1) + doc.pages.length) % doc.pages.length;
        show(j); tabs.querySelectorAll('[role=tab]')[j].focus();
      });
      tabs.appendChild(t);
    });
  }
  function renderLayers() {
    DS.clear(layersEl);
    var ul = h('ul', { class: 'ds-layer-list' });
    page().layers.slice().reverse().forEach(function (l) {
      var cb = h('input', { type: 'checkbox', class: 'form-check-input', checked: l.visible, id: 'dvL' + l.id });
      cb.addEventListener('change', function () { l.visible = cb.checked; r.applyLayerState(); mm.draw(); });
      ul.appendChild(h('li', { class: 'ds-layer' }, h('div', { class: 'form-check mb-0' }, [cb, h('label', { class: 'form-check-label small', for: 'dvL' + l.id, text: l.name })])));
    });
    layersEl.appendChild(ul);
    layersEl.appendChild(h('p', { class: 'small ds-muted mt-2 mb-0', text: 'Showing or hiding a layer changes only your view.' }));
  }
  function kv(obj) {
    var keys = Object.keys(obj || {});
    if (!keys.length) return null;
    return h('table', { class: 'table table-sm ds-kv' }, h('tbody', null, keys.map(function (k) { return h('tr', null, [h('th', { scope: 'row', text: k }), h('td', { text: String(obj[k]) })]); })));
  }
  function inspect(t) {
    DS.clear(hl);
    DS.clear(insp);
    var prev = picked;
    picked = t && t.kind !== 'bg' ? t : null;
    var ids = [];
    if (prev && prev.kind === 'el') ids.push(prev.id);
    if (picked && picked.kind === 'el') ids.push(picked.id);
    r.updateEls(ids, { noConns: true });
    if (!picked) { insp.appendChild(h('p', { class: 'small ds-muted mb-0', text: 'Click an element or a connector to see its details.' })); return; }
    var p = page();
    if (picked.kind === 'el') {
      var e = p.elements.filter(function (x) { return x.id === picked.id; })[0];
      if (!e) return;
      insp.appendChild(h('h3', { class: 'h6 mb-1', text: e.name || e.text || e.id }));
      insp.appendChild(h('div', { class: 'ds-btnrow mb-2' }, [e.category ? DS.badge('info', e.category, 'tag') : DS.badge('secondary', 'unclassified', 'question-circle'), h('span', { class: 'small ds-muted', text: e.shape })]));
      if (e.description) insp.appendChild(h('p', { class: 'small', text: e.description }));
      if (e.text && e.name) insp.appendChild(h('p', { class: 'small mb-2', text: e.text }));
      var props = kv(e.properties); if (props) { insp.appendChild(h('div', { class: 'ds-label', text: 'Properties' })); insp.appendChild(props); }
      var meta = kv(e.metadata); if (meta) { insp.appendChild(h('div', { class: 'ds-label', text: 'Metadata' })); insp.appendChild(meta); }
      var conns = p.connectors.filter(function (c) { return c.source === e.id || c.target === e.id; });
      if (conns.length) insp.appendChild(h('p', { class: 'small ds-muted mb-0', text: conns.length + ' connection(s)' }));
    } else {
      var c = p.connectors.filter(function (x) { return x.id === picked.id; })[0];
      if (!c) return;
      var nm = function (id) { var x = p.elements.filter(function (y) { return y.id === id; })[0]; return x ? (x.name || x.text || x.id) : 'free end'; };
      insp.appendChild(h('h3', { class: 'h6 mb-1', text: c.label || c.kind || 'Connector' }));
      insp.appendChild(h('p', { class: 'small mb-2', text: nm(c.source) + ' → ' + nm(c.target) }));
      var cp = kv(c.properties); if (cp) { insp.appendChild(h('div', { class: 'ds-label', text: 'Properties' })); insp.appendChild(cp); }
      var rt = r.routes.get(c.id); if (rt) DS.s('path', { d: rt.d, class: 'ds-sel-conn' }, hl);
    }
  }
  function runSearch() {
    var q = search.value.trim().toLowerCase();
    DS.clear(results);
    if (!q) return;
    var hits = [];
    page().elements.forEach(function (e) {
      var hay = [e.text, e.name, e.description, e.category].concat(Object.keys(e.properties || {}).map(function (k) { return k + ' ' + e.properties[k]; })).join(' ').toLowerCase();
      if (hay.indexOf(q) >= 0) hits.push({ kind: 'el', id: e.id, label: e.name || e.text || e.id, sub: e.category || e.shape });
    });
    page().connectors.forEach(function (c) { if ([c.label, c.kind].join(' ').toLowerCase().indexOf(q) >= 0) hits.push({ kind: 'conn', id: c.id, label: c.label || c.kind, sub: 'connector' }); });
    results.appendChild(h('li', { class: 'small ds-muted', 'aria-live': 'polite', text: hits.length + ' match(es)' }));
    hits.slice(0, 100).forEach(function (x) {
      var b = h('button', { type: 'button', class: 'ds-search-hit' }, [DS.icon(x.kind === 'el' ? 'square' : 'arrow-right'), ' ', h('span', { text: x.label }), h('small', { text: x.sub })]);
      b.addEventListener('click', function () {
        inspect(x);
        if (x.kind === 'el') { var e = page().elements.filter(function (y) { return y.id === x.id; })[0]; if (e) r.centerOn(G.bbox(e), true); }
      });
      results.appendChild(h('li', null, b));
    });
  }
  function drawList() { DS.renderList(list, page(), function (kind, id) { inspect({ kind: kind, id: id }); }); }

  DS.attachNav(r, { onPick: function (t) { inspect(t); } });
  search.addEventListener('input', DS.debounce(runSearch, 150));
  document.getElementById('dvZoomIn').addEventListener('click', function () { r.zoomAt(1.2); });
  document.getElementById('dvZoomOut').addEventListener('click', function () { r.zoomAt(1 / 1.2); });
  document.getElementById('dvFit').addEventListener('click', function () { r.fit(); });
  document.getElementById('dvListBtn').addEventListener('click', function (ev) {
    var on = list.hidden;
    list.hidden = !on; wrap.hidden = on;
    ev.currentTarget.setAttribute('aria-pressed', on ? 'true' : 'false');
    ev.currentTarget.classList.toggle('active', on);
    if (on) drawList(); else requestAnimationFrame(function () { mm.draw(); });
  });
  var exporter = new DS.Exporter({
    api: api, cfg: cfg, published: { id: (cfg.diagram || {}).id }, exportUrl: cfg.exportUrl,
    getDoc: function () { return doc; },
    currentPage: function () { return page().id; },
    pages: function () { return doc.pages.map(function (p) { return { id: p.id, name: p.name }; }); },
    name: function () { return (cfg.diagram || {}).name || doc.name; }
  });
  exporter.wire(document);
  DS.on(window, 'resize', DS.debounce(function () { mm.draw(); }, 100));
  show(0);
})();
