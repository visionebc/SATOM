/* diagram_studio_review.js — Review a recognised result before it becomes a diagram.
 *
 * The canvas shows the result with its doubts drawn on it (dashed amber =
 * low confidence, dotted violet = unclassified, dotted line = dangling
 * connector; each also listed with an icon and a word, never colour only).
 * The side panel groups the flagged items; each can get a category (picker
 * from /api/categories with search), a symbol (picker with icons), its
 * text, its connector ends (click the source/target shape on the canvas),
 * be grouped/ungrouped or deleted. Edits are undoable (Ctrl+Z). Accept
 * posts the reviewed document and opens the editor.
 */
(function () {
  'use strict';
  var DS = window.DS, h = DS.h, G = DS.geom, M = DS.model;
  var root = document.getElementById('dsReview');
  if (!root || root.dataset.dsBooted) return;
  root.dataset.dsBooted = '1';
  var cfg = DS.config(), api = DS.Api(cfg);
  var jobId = cfg.jobId;
  var store = null, r = null, cats = null, libraries = null;
  var resolved = new Set(), active = null, sel = new Set(), pickMode = null;
  var issuesEl = document.getElementById('rvIssues'), countEl = document.getElementById('rvCount'), summaryEl = document.getElementById('rvSummary');
  var flags = null;

  function low(e) { return (e.confidence === undefined ? 1 : e.confidence) < M.LOW_CONFIDENCE; }
  function unclassified(e) { return e.kind === 'shape' && !e.category; }
  function dangling(c) { return !(c.source && c.target); }

  // --------------------------------------------------------------- load
  function fail(msg) {
    DS.clear(root).appendChild(h('div', { class: 'fw-card p-4' }, [h('div', { class: 'fw-alert-danger p-2 mb-3', role: 'alert' }, [DS.icon('x-octagon'), ' ', msg]),
      h('a', { class: 'btn btn-sm btn-fw-secondary', href: cfg.base + 'import' }, [DS.icon('arrow-left'), ' Back to the import'])]));
  }
  Promise.all([
    cfg.job ? Promise.resolve({ ok: true, data: cfg.job }) : DS.http('GET', api.job(jobId)),
    DS.http('GET', api.jobResult(jobId)),
    DS.http('GET', api.categories()).catch(function () { return { ok: false }; }),
    DS.http('GET', api.libraries()).catch(function () { return { ok: false }; }),
    DS.http('GET', api.folders()).catch(function () { return { ok: false }; })
  ]).then(function (rs) {
    var job = rs[0].ok ? rs[0].data : {};
    if (!rs[1].ok && (job.status === 'refused' || job.status === 'failed')) {
      fail((job.status === 'refused' ? 'This file was refused: ' : 'Recognition failed: ') + (job.error || 'no result.') + ' Import it again from the wizard.');
      return;
    }
    if (!rs[1].ok) { fail(rs[1].status === 409 ? 'The recognition has not finished yet (status: ' + (job.status || 'unknown') + ').' : rs[1].status === 410 ? 'This result was removed after 7 days. Import the file again.' : DS.errorText(rs[1], 'Loading the result failed')); return; }
    if (job.diagram_id) DS.toast('A diagram was already created from this import.', 'warning');
    cats = rs[2].ok ? rs[2].data : null;
    libraries = rs[3].ok && Array.isArray(rs[3].data) ? rs[3].data : [];
    var fsel = document.getElementById('rvFolder');
    if (rs[4].ok && Array.isArray(rs[4].data)) {
      var fl = rs[4].data, kids = function (pid) { return fl.filter(function (f) { return (f.parent_id || null) === pid; }); };
      (function walk(pid, d) { kids(pid).forEach(function (f) { fsel.appendChild(h('option', { value: String(f.id), text: '  '.repeat(d) + f.name })); walk(f.id, d + 1); }); })(null, 0);
    }
    flags = job.classification || {};
    store = new DS.Store(rs[1].data.doc || rs[1].data, { limit: 300 });
    document.getElementById('rvName').value = store.doc.name && store.doc.name !== 'Untitled diagram' ? store.doc.name : (job.filename || 'Imported diagram').replace(/\.[^.]+$/, '');
    start();
  }, function (e) { fail(e.message); });

  // -------------------------------------------------------------- canvas
  function start() {
    var svg = document.getElementById('rvCanvas');
    r = new DS.Renderer(svg, {
      symbolUrl: function (l, s) { return api.symbolSvg(l, s); },
      decorate: function (e) { return [low(e) && !resolved.has(e.id) ? 'ds-low' : '', unclassified(e) && !resolved.has(e.id) ? 'ds-unclassified' : '', sel.has(e.id) ? 'ds-hl' : ''].join(' '); },
      decorateConn: function (c) {
        if (resolved.has(c.id)) return active && active.kind === 'conn' && active.id === c.id ? 'ds-conn-active' : '';
        return [dangling(c) ? 'ds-dangling' : '', low(c) ? 'ds-lowconn' : '', active && active.kind === 'conn' && active.id === c.id ? 'ds-conn-active' : ''].join(' ');
      }
    });
    DS.attachNav(r, { onPick: onCanvasPick });
    store.onChange(function () { r.setPage(store.page()); drawFlags(); renderIssues(); document.getElementById('rvUndo').disabled = !store.canUndo(); });
    showPage(0);
    document.getElementById('rvAccept').disabled = !(cfg.mayEdit && cfg.mayImport !== false);
  }
  function showPage(i) {
    store.pageIndex = i;
    r.setPage(store.page()); r.setGrid(false);
    drawFlags(); renderTabs(); renderIssues();
    requestAnimationFrame(function () { r.fit(); });
  }
  function renderTabs() {
    var tabs = document.getElementById('rvTabs');
    DS.clear(tabs);
    if (store.doc.pages.length < 2) return;
    store.doc.pages.forEach(function (p, i) {
      var b = h('button', { type: 'button', role: 'tab', class: 'ds-tab' + (i === store.pageIndex ? ' active' : ''), 'aria-selected': i === store.pageIndex ? 'true' : 'false', text: p.name });
      b.addEventListener('click', function () { active = null; sel.clear(); showPage(i); });
      tabs.appendChild(b);
    });
  }
  /* A numbered badge on every flagged element: shape + text, not colour only. */
  function drawFlags() {
    var g = r.overlay;
    DS.clear(g);
    store.page().elements.forEach(function (e) {
      if (resolved.has(e.id) || !(low(e) || unclassified(e))) return;
      var b = G.bbox(e);
      var k = Math.max(0.6, 1 / r.view.k);
      DS.s('circle', { cx: b.x + b.w, cy: b.y, r: 7 * k, class: 'ds-flag-dot' + (low(e) ? '' : ' ds-flag-dot-danger') }, g);
      DS.s('text', { x: b.x + b.w, y: b.y + 3.5 * k, 'text-anchor': 'middle', class: 'ds-flag-text', 'font-size': 10 * k, text: low(e) ? '!' : '?' }, g);
    });
    store.page().connectors.forEach(function (c) {
      if (resolved.has(c.id) || !(low(c) || dangling(c))) return;
      var rt0 = r.routes.get(c.id); if (!rt0) return;
      var q = DS.routing.pointAlong(rt0.flat, 0.5), k2 = Math.max(0.6, 1 / r.view.k);
      DS.s('circle', { cx: q[0], cy: q[1], r: 7 * k2, class: 'ds-flag-dot' + (dangling(c) ? ' ds-flag-dot-danger' : '') }, g);
      DS.s('text', { x: q[0], y: q[1] + 3.5 * k2, 'text-anchor': 'middle', class: 'ds-flag-text', 'font-size': 10 * k2, text: '!' }, g);
    });
    if (active) {
      var e2 = active.kind === 'el' ? store.el(active.id) : null;
      if (e2) { var bb = G.bbox(e2); DS.s('rect', { x: bb.x - 4, y: bb.y - 4, width: bb.w + 8, height: bb.h + 8, class: 'ds-sel-box' }, g); }
      var rt = active.kind === 'conn' ? r.routes.get(active.id) : null;
      if (rt) {
        DS.s('path', { d: rt.d, class: 'ds-sel-conn' }, g);
        // the two ends, named, so a wrong attachment is visible at a glance
        var kk = Math.max(0.6, 1 / r.view.k);
        [[rt.pts[0], 'S'], [rt.pts[rt.pts.length - 1], 'T']].forEach(function (x) {
          DS.s('circle', { cx: x[0][0], cy: x[0][1], r: 8 * kk, class: 'ds-end-dot' }, g);
          DS.s('text', { x: x[0][0], y: x[0][1] + 3.5 * kk, 'text-anchor': 'middle', class: 'ds-flag-text', 'font-size': 10 * kk, text: x[1] }, g);
        });
      }
    }
  }

  function onCanvasPick(t, ev) {
    if (pickMode) {
      if (t.kind !== 'el') { DS.toast('Click a shape (or press Esc to cancel).', 'info', 1500); return; }
      var pm = pickMode;
      endPick();
      store.run(pm.which === 'source' ? 'Set source' : 'Set target', function (tx) {
        var c = tx.touch('conn', pm.id);
        if (pm.which === 'source') { c.source = t.id; c.source_port = ''; c.start = []; } else { c.target = t.id; c.target_port = ''; c.end = []; }
        c.confidence = 1;
      });
      if (!dangling(store.conn(pm.id))) resolved.add(pm.id);
      var n2 = store.el(t.id);
      DS.announce((pm.which === 'source' ? 'Source' : 'Target') + ' set to ' + (n2 ? n2.text || n2.name || n2.id : t.id));
      refresh();
      return;
    }
    if (t.kind === 'bg') { active = null; sel.clear(); refresh(); return; }
    if (ev && ev.shiftKey && t.kind === 'el') { if (sel.has(t.id)) sel.delete(t.id); else sel.add(t.id); refresh(); return; }
    sel.clear(); if (t.kind === 'el') sel.add(t.id);
    active = { kind: t.kind, id: t.id }; refresh();
    var li = issuesEl.querySelector('[data-key="' + t.kind + ':' + t.id + '"]');
    if (li) li.scrollIntoView({ block: 'nearest' });
    var se = document.getElementById('rvSelected'); if (se) se.scrollIntoView({ block: 'nearest' });
  }
  function refresh() {
    r.updateEls(store.page().elements.map(function (e) { return e.id; }), { noConns: true });
    r.updateConns(store.page().connectors.map(function (c) { return c.id; }));
    drawFlags(); renderIssues();
  }
  function startPick(id, which) {
    pickMode = { id: id, which: which };
    var b = document.getElementById('rvPick');
    b.hidden = false;
    DS.clear(b).appendChild(document.createTextNode('Click the ' + which + ' shape on the canvas — Esc cancels'));
    document.getElementById('rvCanvas').focus();
  }
  function endPick() { pickMode = null; document.getElementById('rvPick').hidden = true; }

  // -------------------------------------------------------------- issues
  function groups() {
    var p = store.page();
    var unknown = new Set((flags && flags.unknown) || []);
    return [
      { key: 'low', title: 'Low confidence', icon: 'exclamation-triangle', badge: 'warning', items: p.elements.filter(function (e) { return low(e) && !resolved.has(e.id); }).map(function (e) { return { kind: 'el', o: e }; }) },
      { key: 'unc', title: 'Unclassified', icon: 'question-circle', badge: 'secondary', items: p.elements.filter(function (e) { return !low(e) && (unclassified(e) || unknown.has(e.id)) && !resolved.has(e.id); }).map(function (e) { return { kind: 'el', o: e }; }) },
      { key: 'dang', title: 'Dangling connectors', icon: 'plug', badge: 'danger', items: p.connectors.filter(function (c) { return dangling(c) && !resolved.has(c.id); }).map(function (c) { return { kind: 'conn', o: c }; }) },
      { key: 'lowc', title: 'Low-confidence connectors', icon: 'bezier2', badge: 'warning', items: p.connectors.filter(function (c) { return !dangling(c) && low(c) && !resolved.has(c.id); }).map(function (c) { return { kind: 'conn', o: c }; }) }
    ];
  }
  function renderIssues() {
    if (!store) return;
    var gs = groups(), total = gs.reduce(function (a, g) { return a + g.items.length; }, 0);
    countEl.textContent = total ? total + ' item(s) left' : 'Nothing left to review';
    DS.clear(summaryEl).appendChild(h('div', { class: 'ds-btnrow' }, gs.map(function (g) { return DS.badge(g.items.length ? g.badge : 'success', g.title + ': ' + g.items.length, g.items.length ? g.icon : 'check-circle'); })));
    DS.clear(issuesEl);
    if (!total) { issuesEl.appendChild(h('div', { class: 'ds-empty' }, [DS.icon('check2-circle'), h('div', { text: 'Every flagged item has been reviewed.' })])); }
    gs.forEach(function (g) {
      if (!g.items.length) return;
      var ul = h('ul', { class: 'ds-issues' });
      g.items.slice(0, 300).forEach(function (it) { ul.appendChild(issue(it, g)); });
      issuesEl.appendChild(h('details', { class: 'ds-insp-group', open: 'open' }, [h('summary', { text: g.title + ' (' + g.items.length + ')' }), ul]));
    });
    renderSelected();
  }
  /* The editor of whatever is selected, flagged or not: any element, any
   * connector (a wrongly attached one is fixed here). */
  function renderSelected() {
    var host = document.getElementById('rvSelected');
    if (!host) return;
    DS.clear(host);
    var o = active ? (active.kind === 'el' ? store.el(active.id) : store.conn(active.id)) : null;
    if (!o) { host.hidden = true; return; }
    host.hidden = false;
    var it = { kind: active.kind, o: o };
    var flagged = !resolved.has(o.id) && (active.kind === 'el' ? (low(o) || unclassified(o)) : (low(o) || dangling(o)));
    var close = h('button', { type: 'button', class: 'btn-close btn-sm ms-auto', 'aria-label': 'Close the selection' });
    close.addEventListener('click', function () { active = null; sel.clear(); refresh(); });
    host.appendChild(h('div', { class: 'ds-sel-head' }, [DS.icon(active.kind === 'el' ? 'square' : 'bezier2'),
      h('strong', { text: (active.kind === 'el' ? 'Shape: ' : 'Connector: ') + label(it) }),
      flagged ? DS.badge('warning', 'to review', 'exclamation-triangle') : DS.badge('success', 'ok', 'check-circle'),
      h('small', { class: 'ds-muted', text: Math.round((o.confidence === undefined ? 1 : o.confidence) * 100) + ' %' }), close]));
    host.appendChild(active.kind === 'el' ? elEditor(o) : connEditor(o));
  }
  function label(it) {
    if (it.kind === 'el') return it.o.text || it.o.name || it.o.shape + ' ' + it.o.id;
    var a = store.el(it.o.source), b = store.el(it.o.target);
    return (a ? a.text || a.id : 'free end') + ' → ' + (b ? b.text || b.id : 'free end');
  }
  function issue(it, g) {
    var key = it.kind + ':' + it.o.id;
    var isActive = active && active.kind === it.kind && active.id === it.o.id;
    var li = h('li', { class: 'ds-issue' + (isActive ? ' active' : ''), 'data-key': key });
    var pick = h('button', { type: 'button', class: 'ds-issue-pick', 'aria-expanded': isActive ? 'true' : 'false' }, [DS.icon(g.icon), h('span', { class: 'flex-grow-1', text: label(it) }),
      h('small', { class: 'ds-muted', text: Math.round((it.o.confidence === undefined ? 1 : it.o.confidence) * 100) + ' %' })]);
    pick.addEventListener('click', function () {
      active = isActive ? null : { kind: it.kind, id: it.o.id };
      sel.clear(); if (active && it.kind === 'el') sel.add(it.o.id);
      refresh();
      if (active) {
        var b = it.kind === 'el' ? G.bbox(it.o) : null;
        var rt = it.kind === 'conn' ? r.routes.get(it.o.id) : null;
        if (rt) { var xs = rt.pts.map(function (q) { return q[0]; }), ys = rt.pts.map(function (q) { return q[1]; }); b = { x: Math.min.apply(null, xs), y: Math.min.apply(null, ys), w: Math.max.apply(null, xs) - Math.min.apply(null, xs), h: Math.max.apply(null, ys) - Math.min.apply(null, ys) }; }
        if (b) { r.centerOn(b, true); drawFlags(); }
        var se = document.getElementById('rvSelected'); if (se) se.scrollIntoView({ block: 'nearest' });
      }
    });
    li.appendChild(pick);
    return li;
  }
  function set(label2, kind, id, fn) { store.run(label2, function (tx) { fn(tx.touch(kind, id)); }); }
  function elEditor(e) {
    var box = h('div', { class: 'ds-issue-edit' });
    var text = h('input', { type: 'text', class: 'form-control form-control-sm', value: e.text, maxlength: 4000, 'aria-label': 'Text' });
    text.addEventListener('change', function () { set('Text', 'el', e.id, function (o) { o.text = text.value; }); });
    box.appendChild(h('div', { class: 'ds-field ds-field-wide' }, [h('span', { class: 'ds-label', text: 'Text' }), text]));
    box.appendChild(h('div', { class: 'ds-field ds-field-wide' }, [h('span', { class: 'ds-label', text: 'Category' }), categoryPicker(e)]));
    var symBtn = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary ds-sym-btn' }, [DS.icon('grid-3x3-gap'), ' ', e.symbol || 'Choose a symbol…']);
    symBtn.addEventListener('click', function () { symbolPicker(e); });
    box.appendChild(h('div', { class: 'ds-field ds-field-wide' }, [h('span', { class: 'ds-label', text: 'Symbol' }), symBtn]));
    var ok = h('button', { type: 'button', class: 'btn btn-sm btn-fw-primary' }, [DS.icon('check-lg'), ' Accept']);
    var del = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary' }, [DS.icon('trash'), ' Delete']);
    ok.addEventListener('click', function () { set('Accept', 'el', e.id, function (o) { o.confidence = Math.max(o.confidence, 1); }); resolved.add(e.id); active = null; refresh(); });
    del.addEventListener('click', function () { removeEl(e.id); });
    box.appendChild(h('div', { class: 'ds-btnrow ds-field-wide' }, [ok, del]));
    return box;
  }
  function connEditor(c) {
    var box = h('div', { class: 'ds-issue-edit' });
    var name = function (id) { var e = store.el(id); return e ? (e.text || e.name || e.id) : ''; };
    function endRow(which) {
      var id = which === 'source' ? c.source : c.target;
      var b = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', title: 'Then click the ' + which + ' shape on the canvas' },
        [DS.icon('cursor'), ' Pick ' + which + ' on canvas']);
      b.addEventListener('click', function () { startPick(c.id, which); });
      return h('div', { class: 'ds-field ds-field-wide' }, [h('span', { class: 'ds-label', text: which === 'source' ? 'From (S)' : 'To (T)' }),
        h('div', { class: 'ds-btnrow' }, [id ? h('span', { class: 'ds-end-name', text: name(id) }) : DS.badge('danger', 'free end', 'plug'), b])]);
    }
    box.appendChild(endRow('source'));
    box.appendChild(endRow('target'));
    var swap = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', title: 'Exchange source and target: the arrow points the other way' }, [DS.icon('arrow-left-right'), ' Swap direction']);
    swap.addEventListener('click', function () {
      store.run('Swap direction', function (tx) {
        var o = tx.touch('conn', c.id), t;
        t = o.source; o.source = o.target; o.target = t;
        t = o.source_port; o.source_port = o.target_port; o.target_port = t;
        t = o.start; o.start = o.end; o.end = t;
        o.points = (o.points || []).slice().reverse();
        o.direction = M.direction(o);
        o.confidence = 1;
      });
      DS.announce('Direction swapped');
    });
    box.appendChild(h('div', { class: 'ds-btnrow ds-field-wide' }, [swap]));
    var arrows = M.ARROWS.map(function (a) { return [a, a.replace('_', ' ')]; });
    function arrowSel(key, label3) {
      var s2 = h('select', { class: 'form-select form-select-sm', 'aria-label': label3 }, arrows.map(function (a) { return h('option', { value: a[0], text: a[1], selected: c[key] === a[0] }); }));
      s2.addEventListener('change', function () { set(label3, 'conn', c.id, function (o) { o[key] = s2.value; o.direction = M.direction(o); }); });
      return h('div', { class: 'ds-field' }, [h('span', { class: 'ds-label', text: label3 }), s2]);
    }
    box.appendChild(arrowSel('start_arrow', 'Start arrow'));
    box.appendChild(arrowSel('end_arrow', 'End arrow'));
    var lab = h('input', { type: 'text', class: 'form-control form-control-sm', value: c.label, maxlength: 200, 'aria-label': 'Label' });
    lab.addEventListener('change', function () { set('Label', 'conn', c.id, function (o) { o.label = lab.value; }); });
    box.appendChild(h('div', { class: 'ds-field ds-field-wide' }, [h('span', { class: 'ds-label', text: 'Label' }), lab]));
    var ok = h('button', { type: 'button', class: 'btn btn-sm btn-fw-primary', title: dangling(c) ? 'Keep the free end' : 'The connector is right' }, [DS.icon('check-lg'), dangling(c) ? ' Accept as is' : ' Accept']);
    var del = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary' }, [DS.icon('trash'), ' Delete']);
    ok.addEventListener('click', function () { if (!dangling(c)) set('Accept', 'conn', c.id, function (o) { o.confidence = 1; }); resolved.add(c.id); active = null; refresh(); });
    del.addEventListener('click', function () { store.run('Delete connector', function (tx) { tx.remove('conn', c.id); }); active = null; refresh(); });
    box.appendChild(h('div', { class: 'ds-btnrow ds-field-wide' }, [ok, del]));
    return box;
  }
  function removeEl(id) {
    store.run('Delete', function (tx) {
      var p = store.page();
      p.connectors.filter(function (c) { return c.source === id || c.target === id; }).map(function (c) { return c.id; }).forEach(function (cid) { tx.remove('conn', cid); });
      p.groups.slice().forEach(function (g) { if (g.members.indexOf(id) >= 0) { var left = g.members.filter(function (m) { return m !== id; }); if (left.length < 2) tx.remove('group', g.id); else tx.touch('group', g.id).members = left; } });
      p.elements.forEach(function (e) { if (e.parent === id) tx.touch('el', e.id).parent = ''; });
      tx.remove('el', id);
    });
    active = null; sel.delete(id); refresh();
  }
  /* Category picker: search box + the family › class list. */
  function categoryPicker(e) {
    var wrap = h('div');
    var q = h('input', { type: 'search', class: 'form-control form-control-sm mb-1', placeholder: e.category || 'Search categories', 'aria-label': 'Search categories' });
    var listBox = h('div', { class: 'ds-cat-picker', role: 'listbox', 'aria-label': 'Categories' });
    function draw() {
      DS.clear(listBox);
      var v = q.value.trim().toLowerCase();
      var fams = (cats && cats.families) || [];
      if (!fams.length) listBox.appendChild(h('div', { class: 'small ds-muted p-2', text: 'The category list is not available; type family.class and press Enter.' }));
      fams.forEach(function (f) {
        var cls = (f.classes || []).filter(function (c) { return !v || (f.label + ' ' + c.label + ' ' + f.id + '.' + c.id).toLowerCase().indexOf(v) >= 0; });
        if (!cls.length) return;
        listBox.appendChild(h('div', { class: 'ds-cat-fam', text: f.label }));
        cls.forEach(function (c) {
          var id = f.id + '.' + c.id;
          var b = h('button', { type: 'button', role: 'option', 'aria-selected': e.category === id ? 'true' : 'false', text: c.label + (e.category === id ? '  ✓' : '') });
          b.addEventListener('click', function () { applyCategory(e, id, (c.symbols || [])[0]); });
          listBox.appendChild(b);
        });
      });
    }
    q.addEventListener('input', DS.debounce(draw, 100));
    q.addEventListener('keydown', function (ev) {
      if (ev.key !== 'Enter') return;
      ev.preventDefault();
      var v = q.value.trim();
      if (M.CATEGORY_RE.test(v)) applyCategory(e, v); else { var f = listBox.querySelector('button'); if (f) f.click(); }
    });
    draw();
    wrap.appendChild(q); wrap.appendChild(listBox);
    return wrap;
  }
  function applyCategory(e, id, firstSymbol) {
    set('Category', 'el', e.id, function (o) { o.category = id; o.confidence = 1; if (!o.symbol && firstSymbol && o.shape === 'symbol') o.symbol = firstSymbol; });
    resolved.add(e.id);
    DS.announce('Category set to ' + id);
    active = null; refresh();
  }
  function symbolPicker(e) {
    var q = h('input', { type: 'search', class: 'form-control form-control-sm mb-2', placeholder: 'Search symbols', 'aria-label': 'Search symbols' });
    var grid = h('div', { class: 'ds-symbol-grid', role: 'listbox', 'aria-label': 'Symbols' });
    var chosen = null;
    var all = [];
    libraries.forEach(function (lib) { (lib.symbols || []).forEach(function (sy) { all.push({ ref: lib.id + '/' + sy.id, lib: lib.id, sy: sy }); }); });
    // the element's own family first
    var fam = (e.category || '').split('.')[0];
    all.sort(function (a, b) { return ((b.sy.category || '').indexOf(fam + '.') === 0) - ((a.sy.category || '').indexOf(fam + '.') === 0); });
    all.forEach(function (x) {
      var b = h('button', { type: 'button', class: 'ds-sym-opt', role: 'option', 'aria-selected': x.ref === e.symbol ? 'true' : 'false', title: x.sy.label + ' (' + x.sy.category + ')' },
        [h('img', { src: api.symbolSvg(x.lib, x.sy.id), alt: '', width: 28, height: 28, loading: 'lazy' }), h('span', { text: x.sy.label })]);
      b.dataset.search = (x.sy.label + ' ' + x.sy.category + ' ' + (x.sy.keywords || []).join(' ')).toLowerCase();
      b.addEventListener('click', function () { chosen = x; DS.$$('.ds-sym-opt', grid).forEach(function (o) { o.setAttribute('aria-selected', o === b ? 'true' : 'false'); }); });
      grid.appendChild(b);
    });
    q.addEventListener('input', function () { var v = q.value.toLowerCase(); DS.$$('.ds-sym-opt', grid).forEach(function (o) { o.hidden = v && o.dataset.search.indexOf(v) < 0; }); });
    DS.dialog({ title: 'Choose a symbol', body: h('div', null, [q, grid]), size: 'lg', scroll: true, buttons: [{ label: 'Cancel', value: null }, { label: 'Use symbol', primary: true, value: function () { return chosen; } }] }).then(function (x) {
      if (!x) return;
      set('Symbol', 'el', e.id, function (o) {
        o.symbol = x.ref; o.category = o.category || x.sy.category; o.confidence = 1;
        if (o.shape === 'rect' || o.shape === 'symbol') { o.shape = 'symbol'; o.ports = (x.sy.ports || []).map(function (p) { return { id: p.id, x: p.x, y: p.y }; }); }
      });
      resolved.add(e.id); active = null; refresh();
    });
  }

  // ------------------------------------------------------------- toolbar
  document.getElementById('rvUndo').addEventListener('click', function () { if (store) store.undo(); });
  document.getElementById('rvZoomIn').addEventListener('click', function () { r.zoomAt(1.2); });
  document.getElementById('rvZoomOut').addEventListener('click', function () { r.zoomAt(1 / 1.2); });
  document.getElementById('rvFit').addEventListener('click', function () { r.fit(); });
  document.getElementById('rvGroup').addEventListener('click', function () {
    if (sel.size < 2) { DS.toast('Shift+click at least two shapes on the canvas, then group them.', 'info'); return; }
    var ids = Array.from(sel), layer = store.el(ids[0]).layer;
    store.run('Group', function (tx) {
      store.page().groups.slice().forEach(function (g) { var left = g.members.filter(function (m) { return !sel.has(m); }); if (left.length !== g.members.length) { if (left.length < 2) tx.remove('group', g.id); else tx.touch('group', g.id).members = left; } });
      tx.add('group', { id: M.newId('g'), name: '', members: ids, layer: layer });
    });
    DS.toast('Grouped ' + ids.length + ' shapes.', 'success', 1500);
  });
  document.getElementById('rvUngroup').addEventListener('click', function () {
    var ids = sel.size ? Array.from(sel) : (active ? [active.id] : []);
    var gs = store.page().groups.filter(function (g) { return g.members.some(function (m) { return ids.indexOf(m) >= 0; }); });
    if (!gs.length) { DS.toast('The selection is not grouped.', 'info'); return; }
    store.run('Ungroup', function (tx) { gs.forEach(function (g) { tx.remove('group', g.id); }); });
  });
  document.getElementById('rvAcceptHigh').addEventListener('click', function () {
    if (!store) return;
    var n = 0;
    groups().forEach(function (g) { g.items.forEach(function (it) { if ((it.o.confidence === undefined ? 1 : it.o.confidence) >= M.LOW_CONFIDENCE) { resolved.add(it.o.id); n++; } }); });
    refresh();
    DS.toast(n ? 'Accepted ' + n + ' high-confidence item(s). Low-confidence ones still need a look.' : 'No high-confidence item is waiting.', n ? 'success' : 'info');
  });
  DS.on(document, 'keydown', function (ev) {
    if (!document.body.contains(root) || !store) return;
    if (ev.key === 'Escape' && pickMode) { endPick(); return; }
    if ((ev.ctrlKey || ev.metaKey) && (ev.key === 'z' || ev.key === 'Z') && !/INPUT|TEXTAREA|SELECT/.test(ev.target.tagName)) { ev.preventDefault(); store.undo(); }
  });
  document.getElementById('rvAccept').addEventListener('click', function () {
    var name = document.getElementById('rvName'), btn = this;
    if (!name.value.trim()) { name.classList.add('is-invalid'); name.focus(); return; }
    name.classList.remove('is-invalid');
    var left = groups().reduce(function (a, g) { return a + g.items.length; }, 0);
    var go = left ? DS.confirm('Items not reviewed', left + ' flagged item(s) were not reviewed. Create the diagram anyway? You can still fix them in the editor.', 'Create anyway') : Promise.resolve(true);
    go.then(function (ok) {
      if (!ok) return;
      btn.disabled = true;
      var f = document.getElementById('rvFolder').value;
      store.doc.name = name.value.trim();
      DS.http('POST', api.jobAccept(jobId), { doc: store.doc, name: name.value.trim(), folder_id: f ? Number(f) : null }).then(function (res) {
        if (res.ok || (res.status === 409 && res.data && res.data.url)) {
          if (res.status === 409) DS.toast('A diagram was already created from this import; opening it.', 'warning');
          var url = res.data.url || api.editorPage(res.data.id);
          if (window.Turbo) window.Turbo.visit(url); else window.location.assign(url);
          return;
        }
        btn.disabled = false;
        DS.toast(DS.errorText(res, 'Creating the diagram failed'), 'danger');
      }, function (e) { btn.disabled = false; DS.toast(e.message, 'danger'); });
    });
  });
})();
