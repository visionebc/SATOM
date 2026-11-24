/* diagram_studio_panels.js — Diagram Studio editor panels.
 *
 * Toolbar wiring, the symbol library (search, families, drag onto the
 * canvas), the Object Inspector, the Layers panel, the page tabs, search
 * (Ctrl+F), the list view, the version history drawer, the shortcuts help
 * and the Export to menu. Everything edits through ed.cmd() so each change
 * is one undo step; read-only mode disables every input.
 */
(function () {
  'use strict';
  var DS = window.DS;
  var h = DS.h, M = DS.model, G = DS.geom;

  var BASIC = [
    { shape: 'rect', label: 'Rectangle', w: 120, h: 60 }, { shape: 'round', label: 'Rounded', w: 120, h: 60 },
    { shape: 'ellipse', label: 'Ellipse', w: 120, h: 70 }, { shape: 'diamond', label: 'Decision', w: 120, h: 80, category: 'flow.decision' },
    { shape: 'terminator', label: 'Terminator', w: 120, h: 50, category: 'flow.terminator' }, { shape: 'process', label: 'Sub-process', w: 120, h: 60 },
    { shape: 'parallelogram', label: 'Input / output', w: 130, h: 60, category: 'flow.io' }, { shape: 'document', label: 'Document', w: 120, h: 70, category: 'flow.document' },
    { shape: 'cylinder', label: 'Database', w: 90, h: 90, category: 'infra.database' }, { shape: 'cloud', label: 'Cloud', w: 140, h: 90, category: 'infra.cloud' },
    { shape: 'hexagon', label: 'Hexagon', w: 120, h: 70 }, { shape: 'triangle', label: 'Triangle', w: 90, h: 80 },
    { shape: 'trapezoid', label: 'Trapezoid', w: 120, h: 60 }, { shape: 'pill', label: 'Pill', w: 120, h: 40 },
    { shape: 'note', label: 'Note', w: 140, h: 90, category: 'generic.note', style: { fill: '#FEF9C3', stroke: '#A16207' } },
    { shape: 'actor', label: 'Actor', w: 50, h: 90, category: 'uml.actor' },
    { shape: 'table', label: 'Table', w: 180, h: 96, rows: [{ id: 'r1', text: 'id', bold: true }, { id: 'r2', text: 'name', bold: false }], text: 'Table' },
    { shape: 'swimlane', label: 'Swimlane', w: 300, h: 200, kind: 'container', text: 'Lane' },
    { shape: 'zone', label: 'Zone', w: 320, h: 220, kind: 'container', text: 'Zone', style: { dashed: true, fill: '#F8FAFE', stroke: '#1D4ED8', valign: 'top' } },
    { shape: 'rect', label: 'Text', w: 140, h: 40, kind: 'text', text: 'Text', style: { fill: 'none', stroke: 'none' } },
    { shape: 'line', label: 'Line', w: 160, h: 10 }
  ];

  DS.EditorPanels = function (ed) {
    var store = ed.store, r = ed.r, api = ed.api, cfg = ed.cfg;
    var root = document.getElementById('dsEditor');

    // -------------------------------------------------------------- toolbar
    function bind(id, fn) { var b = document.getElementById(id); if (b) b.addEventListener('click', function (ev) { ev.preventDefault(); fn(b); }); }
    bind('dsUndo', function () { ed.undo(); });
    bind('dsRedo', function () { ed.redo(); });
    bind('dsSave', function () { ed.save(); });
    bind('dsGroup', function () { ed.group(); });
    bind('dsUngroup', function () { ed.ungroup(); });
    bind('dsFront', function () { ed.zorder(true); });
    bind('dsBack', function () { ed.zorder(false); });
    bind('dsDelete', function () { ed.deleteSelection(); });
    bind('dsDuplicate', function () { ed.duplicate(); });
    bind('dsZoomIn', function () { ed.zoom(1.2); });
    bind('dsZoomOut', function () { ed.zoom(1 / 1.2); });
    bind('dsFit', function () { ed.fit(); });
    bind('dsZoom100', function () { ed.zoomTo(1); });
    bind('dsSearchBtn', function () { openSearch(); });
    bind('dsHelpBtn', function () { help(); });
    bind('dsHistoryBtn', function () { history(); });
    bind('dsListBtn', function (b) { toggleList(b); });
    bind('dsRename', function () { renameDiagram(); });
    DS.$$('[data-ds-align]').forEach(function (b) { b.addEventListener('click', function () { ed.align(b.getAttribute('data-ds-align')); }); });
    DS.$$('[data-ds-distribute]').forEach(function (b) { b.addEventListener('click', function () { ed.distribute(b.getAttribute('data-ds-distribute')); }); });
    bind('dsSameSize', function () { ed.sameSize(); });
    DS.$$('[data-ds-layout]').forEach(function (b) { b.addEventListener('click', function () { ed.autoLayout(b.getAttribute('data-ds-layout')); }); });
    DS.$$('[data-ds-routing]').forEach(function (b) {
      b.addEventListener('click', function () { ed.setRouting(b.getAttribute('data-ds-routing')); syncToggles(); });
    });
    var snapBtn = document.getElementById('dsSnap'), guidesBtn = document.getElementById('dsGuides'), gridBtn = document.getElementById('dsGridShow');
    var gridSize = document.getElementById('dsGridSize');
    function syncToggles() {
      [[snapBtn, ed.settings.snap], [guidesBtn, ed.settings.guides], [gridBtn, ed.settings.showGrid]].forEach(function (p) {
        if (p[0]) { p[0].setAttribute('aria-pressed', p[1] ? 'true' : 'false'); p[0].classList.toggle('active', !!p[1]); }
      });
      if (gridSize) gridSize.value = String(ed.settings.grid);
      DS.$$('[data-ds-routing]').forEach(function (b) {
        var on = b.getAttribute('data-ds-routing') === ed.settings.routing;
        b.setAttribute('aria-checked', on ? 'true' : 'false');
        var ic = b.querySelector('.ds-check'); if (ic) ic.style.visibility = on ? 'visible' : 'hidden';
      });
      var rl = document.getElementById('dsRoutingLabel');
      if (rl) rl.textContent = { straight: 'Straight', orthogonal: 'Orthogonal', curved: 'Curved' }[ed.settings.routing];
    }
    if (snapBtn) snapBtn.addEventListener('click', function () { ed.settings.snap = !ed.settings.snap; ed.saveSettings(); syncToggles(); });
    if (guidesBtn) guidesBtn.addEventListener('click', function () { ed.settings.guides = !ed.settings.guides; ed.saveSettings(); syncToggles(); });
    if (gridBtn) gridBtn.addEventListener('click', function () { ed.settings.showGrid = !ed.settings.showGrid; ed.saveSettings(); r.setGrid(ed.settings.showGrid, ed.settings.grid); syncToggles(); });
    if (gridSize) gridSize.addEventListener('change', function () { ed.settings.grid = Number(gridSize.value) || 10; ed.saveSettings(); r.setGrid(ed.settings.showGrid, ed.settings.grid); });
    var gridKind = document.getElementById('dsGridKind');
    if (gridKind) {
      gridKind.value = ed.settings.gridKind === 'iso' ? 'iso' : 'square';
      gridKind.addEventListener('change', function () { ed.settings.gridKind = gridKind.value === 'iso' ? 'iso' : 'square'; ed.saveSettings(); r.setGridKind(ed.settings.gridKind); });
    }
    if (r.setGridKind) r.setGridKind(ed.settings.gridKind);
    syncToggles();
    r.setGrid(ed.settings.showGrid, ed.settings.grid);

    function syncSelectionButtons() {
      var n = ed.sel.els.size + ed.sel.conns.size;
      [['dsGroup', n < 2], ['dsUngroup', !n], ['dsFront', !n], ['dsBack', !n], ['dsDelete', !n], ['dsDuplicate', !n]].forEach(function (p) {
        var b = document.getElementById(p[0]); if (b) b.disabled = !ed.canEdit || p[1];
      });
    }
    ed.on('selection', syncSelectionButtons);
    ed.on('change', syncSelectionButtons);

    var nameEl = document.getElementById('dsDiagramName');
    function renameDiagram() {
      if (!ed.canEdit) return;
      DS.prompt('Rename diagram', 'Name', ed.diagram.name, { max: 200 }).then(function (v) {
        if (!v || v === ed.diagram.name) return;
        DS.http('PATCH', api.diagram(ed.diagram.id), { name: v }).then(function (res) {
          if (!res.ok) { DS.toast(DS.errorText(res, 'Rename failed'), 'danger'); return; }
          ed.diagram.name = v; store.doc.name = v;
          if (nameEl) nameEl.textContent = v;
          document.title = v + ' — Diagram Studio';
          DS.toast('Renamed.', 'success', 1500);
        }, function (e) { DS.toast(e.message, 'danger'); });
      });
    }

    // -------------------------------------------------------- export menu
    var exporter = new DS.Exporter({
      api: api, cfg: cfg,
      getDoc: function () {
        var doc = ed.docForSave();
        return DS.routing.bake(doc, function (pi, cid) {
          if (pi === store.pageIndex) return r.routes.get(cid);
          var p = doc.pages[pi], byId = new Map(p.elements.map(function (e) { return [e.id, e]; }));
          var c = p.connectors.filter(function (x) { return x.id === cid; })[0];
          return c ? DS.routing.route(c, byId) : null;
        });
      },
      currentPage: function () { return store.page().id; },
      pages: function () { return store.doc.pages.map(function (p) { return { id: p.id, name: p.name }; }); },
      name: function () { return ed.diagram.name || store.doc.name; }
    });
    exporter.wire(root);
    ed.exporter = exporter;

    // -------------------------------------------------------------- library
    var libHost = document.getElementById('dsLibrary');
    var libSearch = document.getElementById('dsLibSearch');
    var libraries = cfg.libraries || null;
    function itemNode(label, proto, iconNode) {
      var b = h('button', { type: 'button', class: 'ds-lib-item', draggable: ed.canEdit ? 'true' : 'false', title: label + (ed.canEdit ? ' — drag onto the canvas, or press Enter to add it in the middle' : ''), 'aria-label': 'Add ' + label }, [iconNode, h('span', { class: 'ds-lib-label', text: label })]);
      b.dataset.search = (label + ' ' + (proto.category || '') + ' ' + (proto._kw || '')).toLowerCase();
      var clean = DS.clone(proto); delete clean._kw;
      b.addEventListener('dragstart', function (ev) { ev.dataTransfer.setData('application/x-ds-item', JSON.stringify(clean)); ev.dataTransfer.effectAllowed = 'copy'; });
      b.addEventListener('click', function () { if (ed.canEdit) ed.addElement(clean); });
      if (!ed.canEdit) b.disabled = true;
      return b;
    }
    function shapeIcon(def) {
      var sv = DS.s('svg', { viewBox: '-2 -2 44 34', width: 40, height: 30, 'aria-hidden': 'true', class: 'ds-lib-shape' });
      var e = M.fillElement({ shape: def.shape, kind: def.kind || 'shape', w: 40, h: def.shape === 'line' ? 30 : (def.shape === 'actor' ? 30 : 30), rows: def.rows || [] });
      e.style.fill = '#FFFFFF'; e.style.stroke = '#1F2937';
      if (def.kind === 'text') { DS.s('text', { x: 20, y: 20, 'text-anchor': 'middle', 'font-size': 14, text: 'T', fill: '#1F2937' }, sv); return sv; }
      DS.outline(e).forEach(function (p) {
        var a = { fill: p.fill === false ? 'none' : '#FFFFFF', stroke: '#1F2937', 'stroke-width': 1.2 };
        if (p.t === 'rect') DS.s('rect', Object.assign(a, { width: 40, height: 30, rx: p.rx || 0 }), sv);
        else if (p.t === 'ellipse') DS.s('ellipse', Object.assign(a, { cx: p.cx, cy: p.cy, rx: p.rx, ry: p.ry }), sv);
        else if (p.t === 'poly') DS.s('polygon', Object.assign(a, { points: p.pts.map(function (q) { return q.join(','); }).join(' ') }), sv);
        else if (p.t === 'line') DS.s('polyline', Object.assign(a, { fill: 'none', points: p.pts.map(function (q) { return q.join(','); }).join(' ') }), sv);
        else if (p.t === 'path') DS.s('path', Object.assign(a, { d: p.d }), sv);
      });
      return sv;
    }
    function section(title, open, kids, key) {
      var d = h('details', { class: 'ds-lib-section', open: open ? 'open' : null, 'data-key': key });
      d.appendChild(h('summary', { text: title }));
      d.appendChild(h('div', { class: 'ds-lib-grid' }, kids));
      return d;
    }
    function buildLibrary() {
      if (!libHost) return;
      DS.clear(libHost);
      indexVariants();
      libHost.appendChild(section('Basic shapes', true, BASIC.map(function (b) {
        var proto = { shape: b.shape, kind: b.kind || 'shape', w: b.w, h: b.h, text: b.text !== undefined ? b.text : '', category: b.category || '', rows: b.rows || [], style: b.style || {} };
        return itemNode(b.label, proto, shapeIcon(b));
      }), 'basic'));
      libHost.appendChild(variantTabs());
      (libraries || []).forEach(function (lib) {
        var fams = lib.families || {};
        var variant = libVariant(lib);
        var byFam = {};
        (lib.symbols || []).forEach(function (sy) { var f = (sy.category || 'generic.x').split('.')[0]; (byFam[f] = byFam[f] || []).push(sy); });
        var famOrder = ['network', 'security', 'infra', 'devices', 'data', 'software', 'people', 'flow', 'uml', 'bpmn', 'c4', 'generic'];
        Object.keys(byFam).sort(function (x, y) {
          var ix = famOrder.indexOf(x), iy = famOrder.indexOf(y);
          return (ix < 0 ? 99 : ix) - (iy < 0 ? 99 : iy) || (x < y ? -1 : x > y ? 1 : 0);
        }).forEach(function (f) {
          var label = (fams[f] && fams[f].label) || f;
          var items = byFam[f].map(function (sy) {
            var img = h('img', { src: api.symbolSvg(lib.id, sy.id), alt: '', width: 28, height: 28, loading: 'lazy', class: 'ds-lib-icon' });
            var proto = { shape: 'symbol', kind: 'shape', symbol: lib.id + '/' + sy.id, category: sy.category, w: sy.w || 64, h: sy.h || 64, text: sy.label,
              ports: (sy.ports || []).map(function (p) { return { id: p.id, x: p.x, y: p.y }; }), style: variant === 'flat' ? (sy.style || {}) : { fill: 'none', stroke: 'none' },
              _kw: (sy.keywords || []).join(' ') + ' ' + VARIANT_LABEL[variant] };
            return itemNode(sy.label, proto, img);
          });
          var sec = section(label + (lib.builtin === false ? ' · ' + lib.label : '') + (variant !== 'flat' ? ' · ' + VARIANT_LABEL[variant] : ''), false, items, lib.id + ':' + f);
          sec.dataset.variant = variant;
          libHost.appendChild(sec);
        });
      });
      filterLibrary();
    }
    function filterLibrary() {
      var q = (libSearch && libSearch.value || '').trim().toLowerCase();
      DS.$$('.ds-lib-section', libHost).forEach(function (sec) {
        var any = 0;
        DS.$$('.ds-lib-item', sec).forEach(function (it) { var on = !q || it.dataset.search.indexOf(q) >= 0; it.hidden = !on; if (on) any++; });
        // without a query only the chosen style shows; a query searches every library
        sec.hidden = !any || (!q && !!sec.dataset.variant && sec.dataset.variant !== libStyle);
        if (q && any) sec.open = true;
      });
    }

    // ------------------------------------------- symbol style variants
    /* Libraries come in three styles: "flat" (monochrome, recoloured by the
     * element stroke), "color" (full colour) and "iso3d" (isometric 3D). A
     * symbol's "variants" ({library id: symbol id}) links the same concept
     * across styles; the inspector switches an element between them. */
    var VARIANT_LABEL = { flat: 'Flat', color: 'Colour', iso3d: '3D' };
    var VARIANT_ORDER = ['flat', 'color', 'iso3d'];
    var libStyle = 'flat';
    try { libStyle = localStorage.getItem('satom.ds.lib.style') || 'flat'; } catch (e) { /* private mode */ }
    if (!VARIANT_LABEL[libStyle]) libStyle = 'flat';
    var symIndex = new Map();      // "lib/sym" -> {lib, sym, variant}
    function libVariant(lib) { return VARIANT_LABEL[lib && lib.variant] ? lib.variant : 'flat'; }
    function indexVariants() {
      symIndex = new Map();
      if (DS.themes && DS.themes.setLibraries) DS.themes.setLibraries(libraries);   // themes skip full-colour / 3D icons
      (libraries || []).forEach(function (lib) {
        (lib.symbols || []).forEach(function (sy) { symIndex.set(lib.id + '/' + sy.id, { lib: lib, sym: sy, variant: libVariant(lib) }); });
      });
    }
    /* {flat|color|iso3d: "lib/sym"} for the concept of *ref* (itself included). */
    function siblings(ref) {
      var hit = symIndex.get(ref || '');
      if (!hit) return {};
      var out = {};
      out[hit.variant] = ref;
      var links = hit.sym.variants || {};
      Object.keys(links).forEach(function (lid) {
        var r2 = lid + '/' + links[lid], t = symIndex.get(r2);
        if (t && !out[t.variant]) out[t.variant] = r2;
      });
      return out;
    }
    ed.symbolSiblings = siblings;
    function variantTabs() {
      var bar = h('div', { class: 'btn-group btn-group-sm w-100 my-2', role: 'group', 'aria-label': 'Symbol style' });
      VARIANT_ORDER.forEach(function (v) {
        var b = h('button', { type: 'button', class: 'btn btn-fw-secondary' + (v === libStyle ? ' active' : ''), 'aria-pressed': v === libStyle ? 'true' : 'false',
          title: { flat: 'Flat monochrome symbols (take the element colour)', color: 'Full-colour symbols', iso3d: 'Isometric 3D symbols' }[v], text: VARIANT_LABEL[v] });
        b.addEventListener('click', function () {
          libStyle = v;
          try { localStorage.setItem('satom.ds.lib.style', v); } catch (e) { /* private mode */ }
          DS.$$('button', bar).forEach(function (x) { var on = x === b; x.classList.toggle('active', on); x.setAttribute('aria-pressed', on ? 'true' : 'false'); });
          filterLibrary();
        });
        bar.appendChild(b);
      });
      return bar;
    }
    /* Re-point one element (inside a command) at the *variant* of its symbol. */
    function applyVariant(o, variant) {
      var target = siblings(o.symbol)[variant];
      if (!target || target === o.symbol) return false;
      var from = symIndex.get(o.symbol), to = symIndex.get(target);
      o.symbol = target;
      if (o.shape !== 'symbol') return true;           // a corner icon only changes its picture
      var k2 = Math.min(o.w, o.h) / Math.max(1, Math.min(from.sym.w || 64, from.sym.h || 64));
      var cx = o.x + o.w / 2, cy = o.y + o.h / 2;
      o.w = G.round((to.sym.w || 64) * k2); o.h = G.round((to.sym.h || 64) * k2);
      o.x = G.round(cx - o.w / 2); o.y = G.round(cy - o.h / 2);
      o.ports = (to.sym.ports || []).map(function (p) { return { id: p.id, x: p.x, y: p.y }; });
      if (variant === 'flat') {
        if (o.style.fill === 'none' && o.style.stroke === 'none') { o.style.fill = M.STYLE.fill; o.style.stroke = M.STYLE.stroke; }
      } else {
        // a colour / 3D icon draws its own colours: no box, and no gradient or shadow left over from a theme
        o.style.fill = 'none'; o.style.stroke = 'none';
        o.style.gradient = { type: 'none', color: (o.style.gradient && o.style.gradient.color) || '#FFFFFF', angle: 90 };
        o.style.shadow = false;
      }
      return true;
    }
    function switchVariant(els, variant) {
      var todo = els.filter(function (e) { return e.symbol && !ed.isLocked(e) && siblings(e.symbol)[variant] && siblings(e.symbol)[variant] !== e.symbol; });
      var missing = els.filter(function (e) { return e.symbol && !siblings(e.symbol)[variant]; }).length;
      if (todo.length) {
        ed.cmd('Switch to ' + VARIANT_LABEL[variant], function (tx) { todo.forEach(function (e) { applyVariant(tx.touch('el', e.id), variant); }); });
      }
      DS.toast(todo.length + ' symbol(s) switched to ' + VARIANT_LABEL[variant] + (missing ? '; ' + missing + ' have no ' + VARIANT_LABEL[variant] + ' variant' : '') + '.', todo.length ? 'success' : 'info', 2500);
      renderInspector();
    }
    function variantField(e) {
      var sib = siblings(e.symbol);
      var cur = (symIndex.get(e.symbol) || {}).variant;
      var grp = h('div', { class: 'btn-group btn-group-sm', role: 'group', 'aria-label': 'Symbol style variant' });
      VARIANT_ORDER.forEach(function (v) {
        var b = h('button', { type: 'button', class: 'btn btn-fw-secondary' + (v === cur ? ' active' : ''), 'aria-pressed': v === cur ? 'true' : 'false', text: VARIANT_LABEL[v],
          title: sib[v] ? sib[v] : 'No ' + VARIANT_LABEL[v] + ' variant of this symbol' });
        b.disabled = !ed.canEdit || ed.isLocked(e) || !sib[v] || v === cur;
        b.addEventListener('click', function () { switchVariant([e], v); });
        grp.appendChild(b);
      });
      return h('div', { class: 'ds-field ds-field-wide' }, [h('span', { class: 'ds-label', text: 'Variant' }), grp]);
    }
    function switchAllField(getEls, scope) {
      var grp = h('div', { class: 'ds-btnrow' });
      VARIANT_ORDER.forEach(function (v) {
        var b = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', text: VARIANT_LABEL[v], title: 'Switch every symbol of the ' + scope + ' to its ' + VARIANT_LABEL[v] + ' variant' });
        b.disabled = !ed.canEdit;
        b.addEventListener('click', function () { switchVariant(getEls(), v); });
        grp.appendChild(b);
      });
      return group('Symbol style', [h('div', { class: 'ds-field ds-field-wide' }, [h('span', { class: 'ds-label', text: 'Switch all to' }), grp])]);
    }
    if (libSearch) libSearch.addEventListener('input', DS.debounce(filterLibrary, 120));
    if (libraries) buildLibrary();
    else {
      buildLibrary();
      DS.http('GET', api.libraries()).then(function (res) { if (res.ok && Array.isArray(res.data)) { libraries = res.data; buildLibrary(); } }, function () { /* basic shapes only */ });
    }

    // categories (for the inspector's category picker)
    var categories = null;
    DS.http('GET', api.categories()).then(function (res) { if (res.ok && res.data) categories = res.data; renderInspector(); }, function () { /* free text */ });
    function categoryOptions() {
      var out = [];
      ((categories && categories.families) || []).forEach(function (f) { (f.classes || []).forEach(function (c) { out.push({ id: f.id + '.' + c.id, label: f.label + ' › ' + c.label }); }); });
      return out;
    }

    // ------------------------------------------------------------ inspector
    var insp = document.getElementById('dsInspector');
    var inspBody = document.getElementById('dsInspectorBody');
    var liveFields = null;

    function field(label, ctl, opts) {
      opts = opts || {};
      var id = 'dsF' + Math.random().toString(36).slice(2, 8);
      ctl.id = id;
      if (!ed.canEdit || opts.ro) ctl.disabled = true;
      return h('div', { class: 'ds-field' + (opts.wide ? ' ds-field-wide' : '') }, [h('label', { for: id, text: label }), ctl]);
    }
    function num(v, step) { return h('input', { type: 'number', class: 'form-control form-control-sm', value: String(Math.round(v * 100) / 100), step: step || 1 }); }
    function txt(v, max) { return h('input', { type: 'text', class: 'form-control form-control-sm', value: v || '', maxlength: max || 200 }); }
    function sel(options, v) {
      return h('select', { class: 'form-select form-select-sm' }, options.map(function (o) {
        var val = Array.isArray(o) ? o[0] : o, lab = Array.isArray(o) ? o[1] : o;
        return h('option', { value: val, text: lab, selected: val === v });
      }));
    }
    function check(v, label) {
      var c = h('input', { type: 'checkbox', class: 'form-check-input', checked: !!v });
      return { box: c, node: h('label', { class: 'form-check form-check-inline ds-check-inline' }, [c, ' ', label]) };
    }
    function colour(v) {
      var none = v === 'none';
      var inp = h('input', { type: 'color', class: 'form-control form-control-sm form-control-color', value: none ? '#FFFFFF' : (v || '#FFFFFF'), title: 'Colour' });
      var nb = check(none, 'None');
      inp.disabled = none || !ed.canEdit; nb.box.disabled = !ed.canEdit;
      nb.box.addEventListener('change', function () { inp.disabled = nb.box.checked; });
      var wrapNode = h('div', { class: 'ds-colour' }, [inp, nb.node]);
      wrapNode.value = function () { return nb.box.checked ? 'none' : inp.value.toUpperCase(); };
      wrapNode.inputs = [inp, nb.box];
      return wrapNode;
    }
    function group(title, kids, open) {
      var d = h('details', { class: 'ds-insp-group', open: open === false ? null : 'open' });
      d.appendChild(h('summary', { text: title }));
      d.appendChild(h('div', { class: 'ds-insp-grid' }, kids));
      return d;
    }
    function onCommit(ctl, fn) {
      var ev = ctl.inputs ? 'change' : (ctl.type === 'checkbox' || ctl.tagName === 'SELECT' || ctl.type === 'color' ? 'change' : 'change');
      (ctl.inputs || [ctl]).forEach(function (c) { c.addEventListener(ev, function () { fn(ctl.inputs ? ctl.value() : (ctl.type === 'checkbox' ? ctl.checked : ctl.value)); }); });
    }
    /* Edit fields of the selected elements as one coalesced command. */
    /* A commit from an inspector field: the field already shows its value, so
     * the change does not re-render the inspector -- a value typed and left
     * with Tab (change fires while the focus is between two fields) keeps the
     * focus going to the next field. */
    var inspCommit = false;
    function inspCmd(label, fn, opts) {
      inspCommit = true;
      try { ed.cmd(label, fn, opts); } finally { inspCommit = false; }
    }
    function setEls(label, key, fn) {
      var els = ed.editableEls();
      if (!els.length) return;
      inspCmd(label, function (tx) { els.forEach(function (e) { fn(tx.touch('el', e.id)); }); }, { coalesce: 'insp:' + key + ':' + els.map(function (e) { return e.id; }).join(',') });
    }
    function setConns(label, key, fn) {
      var cs = ed.selectedConns().filter(function (c) { return !ed.isLocked(c); });
      if (!cs.length) return;
      inspCmd(label, function (tx) { cs.forEach(function (c) { var cc = tx.touch('conn', c.id); fn(cc); cc.direction = M.direction(cc); }); }, { coalesce: 'insp:' + key + ':' + cs.map(function (c) { return c.id; }).join(',') });
    }

    // The ONE "Style" section (fill, gradient, line, pattern, opacities,
    // shadow, text) is built by diagram_studio_style.js.
    var styleUI = DS.StyleUI ? DS.StyleUI(ed, { setEls: setEls, setConns: setConns }) : null;
    function styleBlock(els, cons, editable) {
      if (!styleUI) return null;
      var b = styleUI.blockFor(els, cons);
      if (!editable) DS.$$('input,select,textarea,button', b).forEach(function (x) { if (x.getAttribute('data-key') !== 'copy' && x.getAttribute('data-key') !== 'theme') x.disabled = true; });
      return b;
    }

    function kvTable(obj, editable, onChange) {
      var tb = h('tbody');
      var keys = Object.keys(obj || {});
      keys.forEach(function (key) {
        var kIn = h('input', { type: 'text', class: 'form-control form-control-sm', value: key, maxlength: 64, 'aria-label': 'Property name' });
        var vIn = h('input', { type: 'text', class: 'form-control form-control-sm', value: String(obj[key]), maxlength: 1000, 'aria-label': 'Value of ' + key });
        var del = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', 'aria-label': 'Remove property ' + key, title: 'Remove' }, DS.icon('trash'));
        if (!editable) { kIn.disabled = vIn.disabled = del.disabled = true; }
        var commit = function () {
          var nk = kIn.value.trim();
          var next = {};
          Object.keys(obj).forEach(function (k2) { if (k2 === key) { if (nk) next[nk] = vIn.value; } else next[k2] = obj[k2]; });
          onChange(next);
        };
        kIn.addEventListener('change', commit); vIn.addEventListener('change', commit);
        del.addEventListener('click', function () { var next = DS.clone(obj); delete next[key]; onChange(next); });
        tb.appendChild(h('tr', null, [h('td', null, kIn), h('td', null, vIn), h('td', { class: 'actions-col' }, del)]));
      });
      if (!keys.length) tb.appendChild(h('tr', null, h('td', { colspan: 3, class: 'text-muted small', text: 'No properties.' })));
      var t = h('table', { class: 'table table-sm ds-kv' }, [h('thead', null, h('tr', null, [h('th', { scope: 'col', text: 'Name' }), h('th', { scope: 'col', text: 'Value' }), h('th', null, h('span', { class: 'visually-hidden', text: 'Actions' }))])), tb]);
      var add = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary mt-1' }, [DS.icon('plus-lg'), ' Add property']);
      add.disabled = !editable;
      add.addEventListener('click', function () {
        var next = DS.clone(obj || {}), i = 1;
        while (next['property' + i] !== undefined) i++;
        next['property' + i] = '';
        onChange(next);
      });
      return h('div', { class: 'ds-field-wide' }, [t, add]);
    }
    function roTable(obj) {
      var keys = Object.keys(obj || {});
      if (!keys.length) return h('p', { class: 'text-muted small mb-0 ds-field-wide', text: 'None.' });
      return h('table', { class: 'table table-sm ds-kv ds-field-wide' }, h('tbody', null, keys.map(function (k2) { return h('tr', null, [h('th', { scope: 'row', text: k2 }), h('td', { text: String(obj[k2]) })]); })));
    }
    function confidenceBadge(v) {
      v = v === undefined ? 1 : v;
      var low = v < M.LOW_CONFIDENCE;
      return DS.badge(low ? 'warning' : 'success', Math.round(v * 100) + ' % ' + (low ? '(low)' : '(ok)'), low ? 'exclamation-triangle' : 'check-circle');
    }

    function symbolPicker(current) {
      return new Promise(function (resolve) {
        var q = h('input', { type: 'search', class: 'form-control form-control-sm mb-2', placeholder: 'Search symbols', 'aria-label': 'Search symbols' });
        var grid = h('div', { class: 'ds-symbol-grid', role: 'listbox', 'aria-label': 'Symbols' });
        var chosen = current;
        var none = h('button', { type: 'button', class: 'ds-sym-opt', role: 'option', 'aria-selected': !current ? 'true' : 'false' }, [DS.icon('slash-circle'), h('span', { text: 'No symbol' })]);
        none.addEventListener('click', function () { chosen = ''; mark(); });
        grid.appendChild(none);
        (libraries || []).forEach(function (lib) {
          (lib.symbols || []).forEach(function (sy) {
            var ref = lib.id + '/' + sy.id;
            var b = h('button', { type: 'button', class: 'ds-sym-opt', role: 'option', 'data-ref': ref, 'aria-selected': ref === current ? 'true' : 'false', title: sy.label + ' (' + sy.category + ')' },
              [h('img', { src: api.symbolSvg(lib.id, sy.id), alt: '', width: 28, height: 28, loading: 'lazy' }), h('span', { text: sy.label })]);
            b.dataset.search = (sy.label + ' ' + sy.category + ' ' + (sy.keywords || []).join(' ')).toLowerCase();
            b.dataset.cat = sy.category;
            b.addEventListener('click', function () { chosen = ref; mark(); });
            b.addEventListener('dblclick', function () { chosen = ref; resolve({ ref: ref, cat: sy.category }); DS.$('.modal.show .btn-close') && DS.$('.modal.show .btn-close').click(); });
            grid.appendChild(b);
          });
        });
        function mark() { DS.$$('.ds-sym-opt', grid).forEach(function (b) { b.setAttribute('aria-selected', (b.dataset.ref || '') === chosen ? 'true' : 'false'); }); }
        q.addEventListener('input', function () { var v = q.value.toLowerCase(); DS.$$('.ds-sym-opt[data-ref]', grid).forEach(function (b) { b.hidden = v && b.dataset.search.indexOf(v) < 0; }); });
        DS.dialog({ title: 'Choose a symbol', body: h('div', null, [q, grid]), size: 'lg', scroll: true, buttons: [
          { label: 'Cancel', value: null },
          { label: 'Use symbol', primary: true, value: function () { var b = DS.$('.ds-sym-opt[data-ref="' + CSS.escape(chosen || '') + '"]', grid); return { ref: chosen, cat: b ? b.dataset.cat : '' }; } }
        ] }).then(function (v) { resolve(v); });
      });
    }

    function categoryField(value, onSet) {
      var listId = 'dsCatList' + Math.random().toString(36).slice(2, 7);
      var inp = h('input', { type: 'text', class: 'form-control form-control-sm', value: value || '', list: listId, placeholder: 'family.class (e.g. network.firewall)', maxlength: 120 });
      var dl = h('datalist', { id: listId }, categoryOptions().map(function (o) { return h('option', { value: o.id, text: o.label }); }));
      var err = h('div', { class: 'invalid-feedback', text: 'Use lower-case family.class, e.g. network.firewall.' });
      inp.addEventListener('change', function () {
        var v = inp.value.trim();
        var ok = !v || M.CATEGORY_RE.test(v);
        inp.classList.toggle('is-invalid', !ok);
        if (ok) onSet(v);
      });
      var f = field('Category', inp, { wide: true });
      f.appendChild(dl); f.appendChild(err);
      return f;
    }

    function renderInspector() {
      if (!inspBody) return;
      DS.clear(inspBody);
      liveFields = null;
      var els = ed.selectedEls(), cons = ed.selectedConns();
      var title = document.getElementById('dsInspectorTitle');
      if (els.length === 1 && !cons.length) inspectElement(els[0]);
      else if (cons.length === 1 && !els.length) inspectConnector(cons[0]);
      else if (els.length || cons.length) inspectMulti(els, cons);
      else inspectPage();
      if (title) title.textContent = els.length === 1 && !cons.length ? 'Element' : cons.length === 1 && !els.length ? 'Connector' : (els.length || cons.length) ? 'Selection' : 'Page';
    }
    ed.renderInspector = renderInspector;

    function inspectPage() {
      var p = store.page();
      var name = txt(p.name, 200); onCommit(name, function (v) { if (v.trim()) ed.cmd('Rename page', function (tx) { tx.meta(); store.page().name = v.trim(); }); });
      var w = num(p.width), hh = num(p.height);
      onCommit(w, function (v) { ed.cmd('Page size', function (tx) { tx.meta(); store.page().width = Math.max(1, Number(v) || 1600); }); });
      onCommit(hh, function (v) { ed.cmd('Page size', function (tx) { tx.meta(); store.page().height = Math.max(1, Number(v) || 1000); }); });
      var bg = colour(p.background || 'none'); onCommit(bg, function (v) { ed.cmd('Background', function (tx) { tx.meta(); store.page().background = v === 'none' ? '' : v; }); });
      var st = M.stats({ pages: [p] });
      inspBody.appendChild(group('Page', [field('Name', name, { wide: true }), field('Width', w), field('Height', hh), field('Background', bg, { wide: true })]));
      inspBody.appendChild(group('Contents', [h('ul', { class: 'ds-stats ds-field-wide' }, [
        h('li', { text: st.elements + ' elements' }), h('li', { text: st.connectors + ' connectors (' + st.dangling + ' dangling)' }),
        h('li', { text: st.low + ' low-confidence, ' + st.unclassified + ' unclassified' })
      ])]));
      var src = store.doc.source || {};
      if (src.filename) inspBody.appendChild(group('Source', [roTable({ file: src.filename, format: src.format, page: src.page })], false));
      if (p.elements.some(function (x) { return x.symbol; })) inspBody.appendChild(switchAllField(function () { return store.page().elements; }, 'page'));
      inspBody.appendChild(h('p', { class: 'text-muted small mt-2 mb-0', text: 'Select an element or a connector to edit it. Double-click a shape to edit its text.' }));
    }

    function inspectElement(e) {
      var locked = ed.isLocked(e);
      var editable = ed.canEdit && !locked;
      if (locked) inspBody.appendChild(h('div', { class: 'fw-alert-warning small p-2 mb-2', role: 'note' }, [DS.icon('lock'), ' On a locked or hidden layer: read-only.']));
      var x = num(e.x), y = num(e.y), w = num(e.w), hh = num(e.h), rot = num(e.rotation, 1);
      [[x, 'x'], [y, 'y'], [w, 'w'], [hh, 'h'], [rot, 'rotation']].forEach(function (p) {
        onCommit(p[0], function (v) {
          var n = Number(v);
          if (!isFinite(n)) return;
          if (p[1] === 'w' || p[1] === 'h') n = Math.max(1, n);
          if (p[1] === 'rotation') n = ((n % 360) + 540) % 360 - 180;
          setEls('Geometry', p[1], function (o) { o[p[1]] = G.round(n); });
        });
      });
      liveFields = { id: e.id, x: x, y: y, w: w, h: hh, rotation: rot };
      inspBody.appendChild(group('Geometry', [field('X', x, { ro: !editable }), field('Y', y, { ro: !editable }), field('Width', w, { ro: !editable }), field('Height', hh, { ro: !editable }), field('Rotation °', rot, { ro: !editable })]));

      var text = h('textarea', { class: 'form-control form-control-sm', rows: 3, maxlength: 4000, text: e.text });
      onCommit(text, function (v) { setEls('Edit text', 'text', function (o) { o.text = v; }); });
      var name = txt(e.name, 200); onCommit(name, function (v) { setEls('Name', 'name', function (o) { o.name = v; }); });
      var desc = h('textarea', { class: 'form-control form-control-sm', rows: 2, maxlength: 2000, text: e.description });
      onCommit(desc, function (v) { setEls('Description', 'desc', function (o) { o.description = v; }); });
      inspBody.appendChild(group('Text', [field('Text', text, { wide: true, ro: !editable }), field('Name', name, { wide: true, ro: !editable }), field('Description', desc, { wide: true, ro: !editable })]));

      var shape = sel(M.SHAPES, e.shape); onCommit(shape, function (v) { setEls('Shape', 'shape', function (o) { o.shape = v; }); });
      var kind = sel(M.KINDS.filter(function (kk) { return kk !== 'image' || e.kind === 'image'; }), e.kind); onCommit(kind, function (v) { setEls('Kind', 'kind', function (o) { o.kind = v; }); });
      var symBtn = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary ds-sym-btn' }, [e.symbol ? h('img', { src: (function () { var s2 = M.splitSymbol(e.symbol); return s2 ? api.symbolSvg(s2.lib, s2.sym) : ''; })(), alt: '', width: 18, height: 18 }) : DS.icon('grid-3x3-gap'), ' ', e.symbol || 'Choose…']);
      symBtn.disabled = !editable;
      symBtn.addEventListener('click', function () {
        symbolPicker(e.symbol).then(function (v) {
          if (!v) return;
          setEls('Symbol', 'symbol', function (o) { o.symbol = v.ref || ''; if (v.ref && v.cat && !o.category) o.category = v.cat; });
          renderInspector();
        });
      });
      var cat = categoryField(e.category, function (v) { setEls('Category', 'cat', function (o) { o.category = v; o.confidence = Math.max(o.confidence, v ? 1 : o.confidence); }); });
      if (!editable) cat.querySelector('input').disabled = true;
      inspBody.appendChild(group('Classification', [field('Shape', shape, { ro: !editable }), field('Kind', kind, { ro: !editable }), cat,
        h('div', { class: 'ds-field ds-field-wide' }, [h('span', { class: 'ds-label', text: 'Symbol' }), symBtn]),
        e.symbol && symIndex.has(e.symbol) ? variantField(e) : null,
        h('div', { class: 'ds-field ds-field-wide' }, [h('span', { class: 'ds-label', text: 'Confidence' }), confidenceBadge(e.confidence)])].filter(Boolean)));

      var cb = styleBlock([e], [], editable); if (cb) inspBody.appendChild(cb);
      if (e.shape === 'table') inspBody.appendChild(group('Rows', [rowsEditor(e, editable)]));
      inspBody.appendChild(group('Custom properties', [kvTable(e.properties, editable, function (next) { setEls('Properties', 'props', function (o) { o.properties = next; }); renderInspector(); })]));
      inspBody.appendChild(group('Metadata (read-only)', [roTable(e.metadata)], Object.keys(e.metadata || {}).length > 0));
      var info = { id: e.id, layer: (ed.layerOf(e.layer) || {}).name, parent: e.parent || '—', group: (store.groupOf(e.id) || {}).id || '—', 'source ref': e.source_ref || '—' };
      if (e.native && e.native.format) info['native format'] = e.native.format;
      inspBody.appendChild(group('Details', [roTable(info)], false));
    }

    function rowsEditor(e, editable) {
      var list = h('div', { class: 'ds-rows ds-field-wide' });
      (e.rows || []).forEach(function (row, i) {
        var t = txt(row.text, 300); t.setAttribute('aria-label', 'Row ' + (i + 1));
        var b = check(row.bold, 'Bold');
        var del = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', 'aria-label': 'Remove row ' + (i + 1) }, DS.icon('trash'));
        t.disabled = b.box.disabled = del.disabled = !editable;
        t.addEventListener('change', function () { setEls('Row', 'row' + i, function (o) { o.rows[i].text = t.value; }); });
        b.box.addEventListener('change', function () { setEls('Row', 'rowb' + i, function (o) { o.rows[i].bold = b.box.checked; }); });
        del.addEventListener('click', function () { setEls('Remove row', 'rowd', function (o) { o.rows.splice(i, 1); }); renderInspector(); });
        list.appendChild(h('div', { class: 'ds-row-edit' }, [t, b.node, del]));
      });
      var add = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary' }, [DS.icon('plus-lg'), ' Add row']);
      add.disabled = !editable;
      add.addEventListener('click', function () { setEls('Add row', 'rowa', function (o) { o.rows.push({ id: 'r' + (o.rows.length + 1) + Math.random().toString(36).slice(2, 5), text: 'field', bold: false }); o.h = Math.max(o.h, 30 + 22 * o.rows.length + 4); }); renderInspector(); });
      list.appendChild(add);
      return list;
    }

    function inspectConnector(c) {
      var locked = ed.isLocked(c);
      var editable = ed.canEdit && !locked;
      var names = function (id) { var e = store.el(id); return e ? (e.name || e.text || e.id) : ''; };
      var label = txt(c.label, 200); onCommit(label, function (v) { setConns('Label', 'label', function (o) { o.label = v; }); });
      var routing = sel([['straight', 'Straight'], ['orthogonal', 'Orthogonal'], ['curved', 'Curved']], c.routing);
      onCommit(routing, function (v) { setConns('Routing', 'routing', function (o) { o.routing = v; if (v === 'orthogonal') o.points = []; }); });
      var arrows = M.ARROWS.map(function (a) { return [a, a.replace('_', ' ')]; });
      var sa = sel(arrows, c.start_arrow), ea = sel(arrows, c.end_arrow);
      onCommit(sa, function (v) { setConns('Arrow', 'sa', function (o) { o.start_arrow = v; }); });
      onCommit(ea, function (v) { setConns('Arrow', 'ea', function (o) { o.end_arrow = v; }); });
      var kind = txt(c.kind, 40); kind.placeholder = 'ethernet, vpn, data_flow…';
      onCommit(kind, function (v) { var vv = v.trim().toLowerCase(); if (!vv || /^[a-z][a-z0-9_\-]{0,39}$/.test(vv)) setConns('Kind', 'kind', function (o) { o.kind = vv; }); else DS.toast('Kind: lower-case letters, digits, _ and - only.', 'warning'); });
      inspBody.appendChild(group('Connector', [field('Label', label, { wide: true, ro: !editable }), field('Routing', routing, { ro: !editable }), field('Kind', kind, { ro: !editable }),
        field('Start arrow', sa, { ro: !editable }), field('End arrow', ea, { ro: !editable })]));
      var ends = [
        h('div', { class: 'ds-field ds-field-wide' }, [h('span', { class: 'ds-label', text: 'From' }), c.source ? h('span', { text: names(c.source) + (c.source_port ? ' · port ' + c.source_port : ' · nearest side') }) : DS.badge('warning', 'Free end (dangling)', 'exclamation-triangle')]),
        h('div', { class: 'ds-field ds-field-wide' }, [h('span', { class: 'ds-label', text: 'To' }), c.target ? h('span', { text: names(c.target) + (c.target_port ? ' · port ' + c.target_port : ' · nearest side') }) : DS.badge('warning', 'Free end (dangling)', 'exclamation-triangle')])
      ];
      var clr = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary' }, [DS.icon('bezier2'), ' Clear waypoints (' + c.points.length + ')']);
      clr.disabled = !editable || !c.points.length;
      clr.addEventListener('click', function () { setConns('Clear waypoints', 'clr', function (o) { o.points = []; }); renderInspector(); });
      var unfix = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary' }, [DS.icon('magnet'), ' Use nearest sides']);
      unfix.disabled = !editable || (!c.source_port && !c.target_port);
      unfix.addEventListener('click', function () { setConns('Unpin ports', 'unpin', function (o) { o.source_port = ''; o.target_port = ''; }); renderInspector(); });
      ends.push(h('div', { class: 'ds-field ds-field-wide ds-btnrow' }, [clr, unfix]));
      inspBody.appendChild(group('Ends', ends));
      var labs = h('div', { class: 'ds-field-wide' });
      (c.labels || []).forEach(function (lb, i) {
        var t = txt(lb.text, 200), pos = h('input', { type: 'number', class: 'form-control form-control-sm ds-pos', min: 0, max: 1, step: 0.05, value: String(lb.pos), 'aria-label': 'Position along the line (0 to 1)' });
        t.setAttribute('aria-label', 'Label ' + (i + 1));
        var del = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', 'aria-label': 'Remove label ' + (i + 1) }, DS.icon('trash'));
        t.disabled = pos.disabled = del.disabled = !editable;
        t.addEventListener('change', function () { setConns('Label', 'lt' + i, function (o) { o.labels[i].text = t.value; }); });
        pos.addEventListener('change', function () { setConns('Label position', 'lp' + i, function (o) { o.labels[i].pos = Math.max(0, Math.min(1, Number(pos.value) || 0)); }); });
        del.addEventListener('click', function () { setConns('Remove label', 'ld', function (o) { o.labels.splice(i, 1); }); renderInspector(); });
        labs.appendChild(h('div', { class: 'ds-row-edit' }, [t, pos, del]));
      });
      var addL = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary' }, [DS.icon('plus-lg'), ' Add label']);
      addL.disabled = !editable || (c.labels || []).length >= 16;
      addL.addEventListener('click', function () { setConns('Add label', 'la', function (o) { o.labels.push({ text: 'label', pos: 0.25 }); }); renderInspector(); });
      labs.appendChild(addL);
      inspBody.appendChild(group('Extra labels', [labs], (c.labels || []).length > 0));
      var ccb = styleBlock([], [c], editable); if (ccb) inspBody.appendChild(ccb);
      inspBody.appendChild(group('Custom properties', [kvTable(c.properties, editable, function (next) { setConns('Properties', 'props', function (o) { o.properties = next; }); renderInspector(); })]));
      inspBody.appendChild(group('Metadata (read-only)', [roTable(c.metadata)], false));
      inspBody.appendChild(group('Details', [roTable({ id: c.id, layer: (ed.layerOf(c.layer) || {}).name, direction: c.direction, 'source ref': c.source_ref || '—' }),
        h('div', { class: 'ds-field ds-field-wide' }, [h('span', { class: 'ds-label', text: 'Confidence' }), confidenceBadge(c.confidence)])], false));
    }

    function inspectMulti(els, cons) {
      inspBody.appendChild(h('p', { class: 'small mb-2', text: els.length + ' element(s) and ' + cons.length + ' connector(s) selected. Changes apply to all of them.' }));
      if (els.length) {
        var cat = categoryField('', function (v) { setEls('Category', 'mcat', function (o) { o.category = v; }); });
        if (!ed.canEdit) cat.querySelector('input').disabled = true;
        inspBody.appendChild(group('Classification', [cat]));
        if (els.some(function (x) { return x.symbol; })) inspBody.appendChild(switchAllField(function () { return ed.selectedEls(); }, 'selection'));
      }
      if (cons.length) {
        var c0 = cons[0];
        var routing = sel([['straight', 'Straight'], ['orthogonal', 'Orthogonal'], ['curved', 'Curved']], c0.routing);
        onCommit(routing, function (v) { setConns('Routing', 'mrouting', function (o) { o.routing = v; if (v === 'orthogonal') o.points = []; }); });
        var arrows = M.ARROWS.map(function (a) { return [a, a.replace('_', ' ')]; });
        var ea = sel(arrows, c0.end_arrow); onCommit(ea, function (v) { setConns('Arrow', 'mea', function (o) { o.end_arrow = v; }); });
        var g2 = group('Connector', [field('Routing', routing), field('End arrow', ea)]);
        if (!ed.canEdit) DS.$$('input,select,textarea,button', g2).forEach(function (x) { x.disabled = true; });
        inspBody.appendChild(g2);
      }
      var mcb = styleBlock(els, cons, ed.canEdit); if (mcb) inspBody.appendChild(mcb);
    }

    ed.on('selection', renderInspector);
    ed.on('change', function (ch) {
      // keep focus stable: only rebuild when the inspector does not hold focus
      // and the change did not come from one of its own fields
      if (inspCommit || (inspBody && inspBody.contains(document.activeElement))) { liveSync(); return; }
      renderInspector();
    });
    function liveSync() {
      if (!liveFields) return;
      var e = store.el(liveFields.id); if (!e) return;
      ['x', 'y', 'w', 'h', 'rotation'].forEach(function (key) { var f = liveFields[key]; if (f !== document.activeElement) f.value = String(Math.round(e[key] * 100) / 100); });
    }
    ed.on('live', liveSync);

    // -------------------------------------------------------------- layers
    var layersHost = document.getElementById('dsLayersBody');
    function renderLayers() {
      if (!layersHost) return;
      DS.clear(layersHost);
      var p = store.page();
      var cur = ed.currentLayer();
      var counts = {};
      p.elements.forEach(function (e) { counts[e.layer] = (counts[e.layer] || 0) + 1; });
      p.connectors.forEach(function (c) { counts[c.layer] = (counts[c.layer] || 0) + 1; });
      var list = h('ul', { class: 'ds-layer-list', role: 'list' });
      p.layers.slice().reverse().forEach(function (l) {
        var idx = p.layers.indexOf(l);
        var active = l.id === cur.id;
        var vis = h('button', { type: 'button', class: 'btn btn-sm ds-icon-btn', 'aria-pressed': l.visible ? 'true' : 'false', 'aria-label': (l.visible ? 'Hide' : 'Show') + ' layer ' + l.name, title: l.visible ? 'Visible — click to hide' : 'Hidden — click to show' }, DS.icon(l.visible ? 'eye' : 'eye-slash'));
        var lock = h('button', { type: 'button', class: 'btn btn-sm ds-icon-btn', 'aria-pressed': l.locked ? 'true' : 'false', 'aria-label': (l.locked ? 'Unlock' : 'Lock') + ' layer ' + l.name, title: l.locked ? 'Locked — click to unlock' : 'Unlocked — click to lock' }, DS.icon(l.locked ? 'lock-fill' : 'unlock'));
        var name = h('button', { type: 'button', class: 'ds-layer-name' + (active ? ' active' : ''), 'aria-current': active ? 'true' : null, title: 'Make this the layer new items go to; double-click to rename' }, [
          h('span', { text: l.name }), h('span', { class: 'ds-layer-count', text: String(counts[l.id] || 0) }),
          active ? h('span', { class: 'visually-hidden', text: ' (active)' }) : null
        ]);
        var up = h('button', { type: 'button', class: 'btn btn-sm ds-icon-btn', 'aria-label': 'Move layer ' + l.name + ' up', title: 'Move up' }, DS.icon('chevron-up'));
        var down = h('button', { type: 'button', class: 'btn btn-sm ds-icon-btn', 'aria-label': 'Move layer ' + l.name + ' down', title: 'Move down' }, DS.icon('chevron-down'));
        up.disabled = !ed.canEdit || idx === p.layers.length - 1; down.disabled = !ed.canEdit || idx === 0;
        vis.disabled = lock.disabled = !ed.canEdit && false;
        vis.addEventListener('click', function () { layerToggle(l.id, 'visible'); });
        lock.addEventListener('click', function () { layerToggle(l.id, 'locked'); });
        name.addEventListener('click', function () { ed.activeLayer = l.id; renderLayers(); });
        name.addEventListener('dblclick', function () { renameLayer(l); });
        up.addEventListener('click', function () { moveLayer(l.id, 1); });
        down.addEventListener('click', function () { moveLayer(l.id, -1); });
        list.appendChild(h('li', { class: 'ds-layer' + (l.visible ? '' : ' ds-layer-hidden') + (l.locked ? ' ds-layer-locked' : '') }, [vis, lock, name, up, down]));
      });
      layersHost.appendChild(list);
      var bar = h('div', { class: 'ds-btnrow mt-2' });
      var add = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', title: 'Add a layer on top' }, [DS.icon('plus-lg'), ' Add']);
      var ren = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', title: 'Rename the active layer' }, [DS.icon('pencil'), ' Rename']);
      var del = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', title: 'Delete the active layer; its items move to the layer below' }, [DS.icon('trash'), ' Delete']);
      var mv = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', title: 'Move the selection to the active layer' }, [DS.icon('box-arrow-in-down'), ' Move selection here']);
      [add, ren, del, mv].forEach(function (b) { b.disabled = !ed.canEdit; });
      del.disabled = !ed.canEdit || p.layers.length < 2;
      mv.disabled = !ed.canEdit || !(ed.sel.els.size || ed.sel.conns.size);
      add.addEventListener('click', addLayer);
      ren.addEventListener('click', function () { renameLayer(ed.currentLayer()); });
      del.addEventListener('click', function () { deleteLayer(ed.currentLayer()); });
      mv.addEventListener('click', moveSelectionToLayer);
      [add, ren, del, mv].forEach(function (b) { bar.appendChild(b); });
      if (ed.canEdit) layersHost.appendChild(bar);
      else layersHost.appendChild(h('p', { class: 'small ds-muted mt-2 mb-0', text: 'Hiding a layer here changes only your view.' }));
    }
    function layerToggle(id, key) {
      if (!ed.canEdit) {
        // read-only users may still hide layers locally (not saved)
        var l0 = store.layer(id); if (key === 'visible' && l0) { l0.visible = !l0.visible; r.applyLayerState(); renderLayers(); }
        return;
      }
      ed.cmd(key === 'visible' ? 'Show/hide layer' : 'Lock/unlock layer', function (tx) { var l = tx.touch('layer', id); l[key] = !l[key]; });
      if (key === 'locked' || key === 'visible') { var lay = store.layer(id); if (lay && (lay.locked || !lay.visible)) ed.select(Array.from(ed.sel.els).filter(function (eid) { var e = store.el(eid); return e && e.layer !== id; }), Array.from(ed.sel.conns).filter(function (cid) { var c = store.conn(cid); return c && c.layer !== id; })); }
    }
    function addLayer() {
      var p = store.page();
      var l = { id: M.newId('l'), name: 'Layer ' + (p.layers.length + 1), visible: true, locked: false };
      ed.cmd('Add layer', function (tx) { tx.add('layer', l); });
      ed.activeLayer = l.id; renderLayers();
    }
    function renameLayer(l) {
      if (!ed.canEdit) return;
      DS.prompt('Rename layer', 'Name', l.name, { max: 200 }).then(function (v) { if (v && v !== l.name) ed.cmd('Rename layer', function (tx) { tx.touch('layer', l.id).name = v; }); });
    }
    function moveLayer(id, dir) {
      var p = store.page(), i = p.layers.findIndex(function (l) { return l.id === id; }), j = i + dir;
      if (j < 0 || j >= p.layers.length) return;
      ed.cmd('Reorder layers', function (tx) { tx.order('layer'); var t = p.layers[i]; p.layers[i] = p.layers[j]; p.layers[j] = t; });
    }
    function deleteLayer(l) {
      var p = store.page();
      if (p.layers.length < 2) return;
      var idx = p.layers.indexOf(l), into = p.layers[idx > 0 ? idx - 1 : 1];
      var n = p.elements.filter(function (e) { return e.layer === l.id; }).length + p.connectors.filter(function (c) { return c.layer === l.id; }).length;
      DS.confirm('Delete layer', n ? 'Delete layer "' + l.name + '"? Its ' + n + ' item(s) move to "' + into.name + '".' : 'Delete the empty layer "' + l.name + '"?', 'Delete', true).then(function (ok) {
        if (!ok) return;
        ed.cmd('Delete layer', function (tx) {
          p.elements.forEach(function (e) { if (e.layer === l.id) tx.touch('el', e.id).layer = into.id; });
          p.connectors.forEach(function (c) { if (c.layer === l.id) tx.touch('conn', c.id).layer = into.id; });
          p.groups.forEach(function (g) { if (g.layer === l.id) tx.touch('group', g.id).layer = into.id; });
          tx.remove('layer', l.id);
        });
        ed.activeLayer = into.id; renderLayers();
      });
    }
    function moveSelectionToLayer() {
      var l = ed.currentLayer();
      var els = ed.selectedEls(), cons = ed.selectedConns();
      ed.cmd('Move to layer', function (tx) {
        els.forEach(function (e) { tx.touch('el', e.id).layer = l.id; });
        cons.forEach(function (c) { tx.touch('conn', c.id).layer = l.id; });
      });
      DS.toast('Moved ' + (els.length + cons.length) + ' item(s) to "' + l.name + '".', 'success', 1800);
    }
    ed.on('change', renderLayers);
    ed.on('page', renderLayers);
    ed.on('selection', renderLayers);

    // --------------------------------------------------------------- pages
    var tabs = document.getElementById('dsPageTabs');
    function renderTabs() {
      if (!tabs) return;
      DS.clear(tabs);
      store.doc.pages.forEach(function (p, i) {
        var active = i === store.pageIndex;
        var t = h('button', { type: 'button', role: 'tab', class: 'ds-tab' + (active ? ' active' : ''), 'aria-selected': active ? 'true' : 'false', tabindex: active ? '0' : '-1', title: ed.canEdit ? 'Double-click to rename' : p.name, text: p.name });
        t.addEventListener('click', function () { ed.setPage(i); });
        t.addEventListener('dblclick', function () { renamePage(i); });
        t.addEventListener('keydown', function (ev) {
          if (ev.key === 'ArrowRight' || ev.key === 'ArrowLeft') { ev.preventDefault(); var j = (i + (ev.key === 'ArrowRight' ? 1 : -1) + store.doc.pages.length) % store.doc.pages.length; ed.setPage(j); var nt = tabs.querySelectorAll('[role=tab]')[j]; if (nt) nt.focus(); }
          if (ev.key === 'F2') renamePage(i);
        });
        tabs.appendChild(t);
      });
      if (ed.canEdit) {
        var add = h('button', { type: 'button', class: 'ds-tab ds-tab-add', 'aria-label': 'Add page', title: 'Add page' }, DS.icon('plus-lg'));
        add.addEventListener('click', addPage);
        tabs.appendChild(add);
        var more = h('div', { class: 'dropdown d-inline-block' }, [
          h('button', { type: 'button', class: 'ds-tab ds-tab-add dropdown-toggle', 'data-bs-toggle': 'dropdown', 'aria-expanded': 'false', 'aria-label': 'Page actions', title: 'Page actions' }, DS.icon('three-dots')),
          h('ul', { class: 'dropdown-menu' }, [
            menuItem('Rename page', 'pencil', function () { renamePage(store.pageIndex); }),
            menuItem('Move page left', 'arrow-left', function () { movePage(-1); }, store.pageIndex === 0),
            menuItem('Move page right', 'arrow-right', function () { movePage(1); }, store.pageIndex === store.doc.pages.length - 1),
            menuItem('Duplicate page', 'copy', duplicatePage),
            menuItem('Delete page', 'trash', deletePage, store.doc.pages.length < 2)
          ])
        ]);
        tabs.appendChild(more);
      }
    }
    function menuItem(label, icon, fn, disabled) {
      var b = h('button', { type: 'button', class: 'dropdown-item', disabled: !!disabled }, [DS.icon(icon, 'me-2'), label]);
      b.addEventListener('click', fn);
      return h('li', null, b);
    }
    function pagesCmd(label, fn) { ed.cmd(label, function (tx) { tx.pages(); fn(); }); }
    function addPage() {
      var p = M.newPage('Page ' + (store.doc.pages.length + 1));
      pagesCmd('Add page', function () { store.doc.pages.push(p); store.pageIndex = store.doc.pages.length - 1; });
    }
    function renamePage(i) {
      if (!ed.canEdit) return;
      var p = store.doc.pages[i];
      DS.prompt('Rename page', 'Name', p.name, { max: 200 }).then(function (v) { if (v && v !== p.name) pagesCmd('Rename page', function () { store.doc.pages[i].name = v; }); });
    }
    function movePage(dir) {
      var i = store.pageIndex, j = i + dir;
      if (j < 0 || j >= store.doc.pages.length) return;
      pagesCmd('Move page', function () { var a = store.doc.pages; var t = a[i]; a[i] = a[j]; a[j] = t; store.pageIndex = j; });
    }
    function duplicatePage() {
      var src = DS.clone(store.page());
      src.id = M.newId('page-'); src.name = src.name + ' (copy)';
      pagesCmd('Duplicate page', function () { store.doc.pages.splice(store.pageIndex + 1, 0, src); store.pageIndex += 1; });
    }
    function deletePage() {
      if (store.doc.pages.length < 2) return;
      var p = store.page();
      DS.confirm('Delete page', 'Delete page "' + p.name + '" with ' + p.elements.length + ' element(s)? Undo brings it back.', 'Delete', true).then(function (ok) {
        if (!ok) return;
        pagesCmd('Delete page', function () { store.doc.pages.splice(store.pageIndex, 1); store.pageIndex = Math.max(0, store.pageIndex - 1); });
      });
    }
    ed.on('page', renderTabs);
    ed.on('change', function (ch) { if (ch.pages || ch.structural) renderTabs(); });

    // -------------------------------------------------------------- search
    var searchBox = document.getElementById('dsSearch');
    var searchInput = document.getElementById('dsSearchInput');
    var searchResults = document.getElementById('dsSearchResults');
    function openSearch() {
      if (!searchBox) return;
      searchBox.hidden = false;
      searchInput.focus(); searchInput.select();
      runSearch();
    }
    function closeSearch() { if (searchBox) { searchBox.hidden = true; document.getElementById('dsCanvas').focus({ preventScroll: true }); } }
    function runSearch() {
      var q = searchInput.value.trim().toLowerCase();
      DS.clear(searchResults);
      if (!q) { searchResults.appendChild(h('li', { class: 'text-muted small', text: 'Type text, a name, a category or a property value.' })); return; }
      var hits = [];
      store.page().elements.forEach(function (e) {
        var hay = [e.text, e.name, e.description, e.category, e.symbol].concat(Object.keys(e.properties || {}).map(function (k2) { return k2 + ' ' + e.properties[k2]; }))
          .concat(Object.keys(e.metadata || {}).map(function (k2) { return String(e.metadata[k2]); })).join(' ').toLowerCase();
        if (hay.indexOf(q) >= 0) hits.push({ kind: 'el', id: e.id, label: e.name || e.text || e.id, sub: e.category || e.shape });
      });
      store.page().connectors.forEach(function (c) {
        var hay = [c.label, c.kind].concat((c.labels || []).map(function (l) { return l.text; })).concat(Object.keys(c.properties || {}).map(function (k2) { return k2 + ' ' + c.properties[k2]; })).join(' ').toLowerCase();
        if (hay.indexOf(q) >= 0) hits.push({ kind: 'conn', id: c.id, label: c.label || c.kind || c.id, sub: 'connector' });
      });
      var other = 0;
      store.doc.pages.forEach(function (p, i) { if (i !== store.pageIndex) p.elements.forEach(function (e) { if ((e.text + ' ' + e.name).toLowerCase().indexOf(q) >= 0) other++; }); });
      searchResults.appendChild(h('li', { class: 'ds-search-count small', 'aria-live': 'polite', text: hits.length + ' match(es) on this page' + (other ? ', ' + other + ' on other pages' : '') }));
      hits.slice(0, 200).forEach(function (hit) {
        var b = h('button', { type: 'button', class: 'ds-search-hit' }, [DS.icon(hit.kind === 'el' ? 'square' : 'arrow-right'), ' ', h('span', { text: hit.label }), h('small', { text: hit.sub })]);
        b.addEventListener('click', function () { ed.reveal(hit.kind, hit.id); });
        searchResults.appendChild(h('li', null, b));
      });
    }
    if (searchInput) {
      searchInput.addEventListener('input', DS.debounce(runSearch, 120));
      searchInput.addEventListener('keydown', function (ev) {
        if (ev.key === 'Escape') { ev.preventDefault(); closeSearch(); }
        if (ev.key === 'Enter') { ev.preventDefault(); var f = searchResults.querySelector('.ds-search-hit'); if (f) f.click(); }
        if (ev.key === 'ArrowDown') { ev.preventDefault(); var f2 = searchResults.querySelector('.ds-search-hit'); if (f2) f2.focus(); }
      });
      searchResults.addEventListener('keydown', function (ev) {
        var items = DS.$$('.ds-search-hit', searchResults), i = items.indexOf(document.activeElement);
        if (ev.key === 'ArrowDown' && i >= 0) { ev.preventDefault(); (items[i + 1] || items[i]).focus(); }
        if (ev.key === 'ArrowUp' && i >= 0) { ev.preventDefault(); (i ? items[i - 1] : searchInput).focus(); }
        if (ev.key === 'Escape') closeSearch();
      });
      var sc = document.getElementById('dsSearchClose');
      if (sc) sc.addEventListener('click', closeSearch);
    }
    ed.on('search', openSearch);
    ed.on('escape', function () { if (searchBox && !searchBox.hidden) closeSearch(); });

    // ------------------------------------------------------------ list view
    var listHost = document.getElementById('dsList');
    var listOn = false;
    function toggleList(btn) {
      listOn = !listOn;
      listHost.hidden = !listOn;
      document.getElementById('dsCanvasWrap').hidden = listOn;
      if (btn) { btn.setAttribute('aria-pressed', listOn ? 'true' : 'false'); btn.classList.toggle('active', listOn); }
      if (listOn) drawList();
      else requestAnimationFrame(function () { ed.drawOverlay(); if (ed.minimap) ed.minimap.draw(); });
    }
    function drawList() { if (listOn) DS.renderList(listHost, store.page(), function (kind, id) { if (kind === 'el') ed.select([id], []); else ed.select([], [id]); }); }
    ed.on('change', DS.debounce(drawList, 200));
    ed.on('page', drawList);

    // ------------------------------------------------------------- history
    function history() {
      var drawer = document.getElementById('dsHistory');
      var body = document.getElementById('dsHistoryBody');
      if (!drawer) return;
      drawer.hidden = !drawer.hidden;
      document.getElementById('dsHistoryBtn').setAttribute('aria-expanded', drawer.hidden ? 'false' : 'true');
      if (drawer.hidden) return;
      DS.clear(body).appendChild(h('p', { class: 'text-muted small', text: 'Loading versions…' }));
      DS.http('GET', api.versions(ed.diagram.id)).then(function (res) {
        DS.clear(body);
        if (!res.ok) { body.appendChild(h('div', { class: 'fw-alert-danger small p-2', role: 'alert', text: DS.errorText(res, 'Versions') })); return; }
        var list = Array.isArray(res.data) ? res.data : (res.data && res.data.versions) || [];
        if (!list.length) { body.appendChild(h('p', { class: 'text-muted small', text: 'No saved versions yet.' })); return; }
        var ul = h('ol', { class: 'ds-versions', reversed: true });
        list.slice().sort(function (a, b) { return b.number - a.number; }).forEach(function (v) {
          var cur = v.number === ed.diagram.version;
          var pv = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary' }, [DS.icon('eye'), ' Preview']);
          var rs = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary' }, [DS.icon('arrow-counterclockwise'), ' Restore']);
          rs.disabled = !ed.canEdit || cur;
          pv.addEventListener('click', function () { previewVersion(v.number); });
          rs.addEventListener('click', function () { restoreVersion(v.number); });
          var st = v.stats || {};
          ul.appendChild(h('li', { class: 'ds-version' }, [
            h('div', { class: 'ds-version-head' }, [h('strong', { text: 'Version ' + v.number }), cur ? DS.badge('primary', 'current', 'check2') : null]),
            h('div', { class: 'small text-muted', text: DS.fmtDate(v.created_at) + (v.created_by ? ' · ' + v.created_by : '') }),
            v.note ? h('div', { class: 'small', text: v.note }) : null,
            h('div', { class: 'small text-muted', text: (st.elements !== undefined ? st.elements + ' elements, ' + st.connectors + ' connectors' : '') }),
            h('div', { class: 'ds-btnrow mt-1' }, [pv, rs])
          ]));
        });
        body.appendChild(ul);
      }, function (e) { DS.clear(body).appendChild(h('div', { class: 'fw-alert-danger small p-2', role: 'alert', text: e.message })); });
    }
    var hc = document.getElementById('dsHistoryClose');
    if (hc) hc.addEventListener('click', function () { history(); });
    function previewVersion(n) {
      DS.http('GET', api.version(ed.diagram.id, n)).then(function (res) {
        if (!res.ok) { DS.toast(DS.errorText(res, 'Preview'), 'danger'); return; }
        var doc = M.fillDoc(res.data.doc || res.data);
        var svgEl = DS.s('svg', { class: 'ds-preview-svg', role: 'img', 'aria-label': 'Version ' + n + ' preview' });
        var tabsEl = h('div', { class: 'ds-preview-tabs', role: 'tablist' });
        var body = h('div', null, [tabsEl, h('div', { class: 'ds-preview-box' }, svgEl)]);
        DS.dialog({ title: 'Version ' + n + ' (read-only)', body: body, size: 'xl', buttons: [{ label: 'Close', value: null }] });
        var rr = new DS.Renderer(svgEl, { symbolUrl: function (l, s2) { return api.symbolSvg(l, s2); } });
        function show(i) {
          rr.setPage(doc.pages[i]); rr.setGrid(false);
          setTimeout(function () { rr.fit(); }, 30);
          DS.$$('button', tabsEl).forEach(function (b, j) { b.setAttribute('aria-selected', j === i ? 'true' : 'false'); b.classList.toggle('active', j === i); });
        }
        doc.pages.forEach(function (p, i) { var b = h('button', { type: 'button', role: 'tab', class: 'ds-tab', text: p.name }); b.addEventListener('click', function () { show(i); }); tabsEl.appendChild(b); });
        setTimeout(function () { show(0); }, 200);
      });
    }
    function restoreVersion(n) {
      var msg = 'Restore version ' + n + '? It becomes a new version; nothing is deleted.' + (store.dirty() ? ' Your unsaved changes will be lost.' : '');
      DS.confirm('Restore version', msg, 'Restore', store.dirty()).then(function (ok) {
        if (!ok) return;
        DS.http('POST', api.restore(ed.diagram.id, n), {}).then(function (res) {
          if (!res.ok) { DS.toast(DS.errorText(res, 'Restore failed'), 'danger'); return; }
          ed.reload().then(function () { DS.toast('Version ' + n + ' restored.', 'success'); var d = document.getElementById('dsHistory'); if (d && !d.hidden) { d.hidden = true; history(); } });
        });
      });
    }

    // ----------------------------------------------------------------- help
    var SHORTCUTS = [
      ['Delete / Backspace', 'Delete the selection'], ['Ctrl+Z', 'Undo'], ['Ctrl+Y, Ctrl+Shift+Z', 'Redo'],
      ['Ctrl+C / Ctrl+X / Ctrl+V', 'Copy / cut / paste'], ['Ctrl+D', 'Duplicate'], ['Ctrl+A', 'Select all'],
      ['Ctrl+G / Ctrl+Shift+G', 'Group / ungroup'], ['Arrow keys', 'Nudge 1 px (Shift: 10 px); pan when nothing is selected'],
      ['Ctrl+S', 'Save now'], ['Ctrl+F', 'Search elements'], ['+ / -', 'Zoom in / out'], ['0', 'Fit the drawing'], ['1', 'Zoom to 100 %'],
      ['Enter or F2', 'Edit the text of the selection'], ['Double-click', 'Edit text or a connector label'], ['Esc', 'Cancel / clear the selection'],
      ['Space + drag, middle-drag', 'Pan'], ['Wheel', 'Zoom at the pointer (Shift+wheel pans sideways)'],
      ['Shift+click, drag on empty canvas', 'Add to the selection, marquee select'], ['Alt+click', 'Pick one element inside a group'],
      ['Shift while resizing', 'Keep the aspect ratio'], ['Shift while rotating', 'Snap to 15°'], ['Alt while dragging', 'No snapping'],
      ['Drag from a port dot', 'Draw a connector; drop on a shape to attach it'],
      ['Connector: drag a ○ on a segment', 'Add a waypoint (double-click a ■ waypoint to remove it)'], 
      ['Ctrl+Alt+C / Ctrl+Alt+V', 'Copy / paste the style of the selection'], ['?', 'This help']
    ];
    function help() {
      var t = h('table', { class: 'table table-sm ds-help-table' }, [h('thead', null, h('tr', null, [h('th', { scope: 'col', text: 'Keys' }), h('th', { scope: 'col', text: 'Action' })])),
        h('tbody', null, SHORTCUTS.map(function (s2) { return h('tr', null, [h('td', null, h('kbd', { text: s2[0] })), h('td', { text: s2[1] })]); }))]);
      DS.dialog({ title: 'Keyboard shortcuts', body: t, size: 'lg', scroll: true, buttons: [{ label: 'Close', value: null, primary: true }] });
    }
    ed.on('help', help);

    renderInspector(); renderLayers(); renderTabs(); syncSelectionButtons();
  };
  if (DS.editor && !DS.editor.booted && document.getElementById('dsEditor') && document.body.contains(document.getElementById('dsEditor'))) DS.editor.boot();
})();
