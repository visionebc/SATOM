/* Plugin Studio > app editor > Design: the page designer of an app.
 *
 * The design is JSON ({theme, page, result}); the canvas is the server's own
 * drawing of it (POST .../design/preview, templates/apps/_design.html), so
 * what the author sees is exactly what users get. This file only edits the
 * JSON: palette (click or drag), canvas drag & drop, outline, inspector,
 * theme, images, undo/redo. Server: views/studio.py app_design*,
 * services/studio_design.py (which checks every value again).
 */
(function () {
  'use strict';
  var cfgEl = document.getElementById('sd-config');
  if (!cfgEl) return;
  var CFG = JSON.parse(cfgEl.textContent);
  var SCH = CFG.schema, U = CFG.urls;
  var meta = document.querySelector('meta[name="csrf-token"]');
  var CSRF = meta ? meta.getAttribute('content') : '';
  var D = norm(CFG.design);
  var assets = CFG.assets || [];
  var surface = 'page', mode = 'edit', sel = null, themeOpen = true;
  var undo = [], redo = [], saved = JSON.stringify(D), timer = null, seq = 0;

  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function norm(d) {
    d = d && typeof d === 'object' ? JSON.parse(JSON.stringify(d)) : {};
    return { theme: d.theme || {}, page: d.page || [], result: d.result || [] };
  }
  function req(url, opts) {
    return fetch(url, opts).then(function (r) {
      return r.json().catch(function () { return { ok: false, error: 'HTTP ' + r.status }; }).then(function (d) {
        if (!r.ok || d.ok === false) throw new Error(d.error || ('HTTP ' + r.status));
        return d;
      });
    });
  }
  function post(url, body) {
    return req(url, { method: 'POST', credentials: 'same-origin', body: JSON.stringify(body || {}),
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF, 'Accept': 'application/json' } });
  }
  function state(t, bad) {
    $('sd-state').innerHTML = t ? '<span style="color:' + (bad ? '#8B1C2A' : '#15692A') + ';">' + esc(t) + '</span>' : '';
  }
  function dirty() { return JSON.stringify(D) !== saved; }

  /* ------------------------------------------------------------ the tree */
  function newId() {
    var id;
    do { id = Math.random().toString(36).slice(2, 10); } while (find(id));
    return id;
  }
  function blank(type) {
    var spec = SCH.blocks[type], b = { id: newId(), type: type, props: {}, style: {} };
    spec.props.forEach(function (p) { b.props[p.name] = p.kind === 'bool' ? false : p['default']; });
    if (spec.container === 'children') b.children = [];
    if (spec.container === 'columns') b.columns = [{ w: 6, children: [] }, { w: 6, children: [] }];
    if (spec.container === 'tabs') b.tabs = [{ label: 'Tab 1', children: [] }, { label: 'Tab 2', children: [] }];
    if (type === 'field') {
      var used = {};
      walk(D.page, function (x) { if (x.type === 'field') used[x.props.name] = 1; });
      var free = (CFG.fields || []).filter(function (f) { return !used[f.name]; })[0];
      b.props.name = free ? free.name : '';
    }
    if ((type === 'output' || type === 'stat') && Object.keys(CFG.outputs || {}).length) {
      b.props.key = Object.keys(CFG.outputs)[0];
    }
    return b;
  }
  /* every list a block holds: [{slot, list}] */
  function slots(b) {
    var out = [];
    if (b.children) out.push({ slot: 'children', list: b.children, label: '' });
    (b.columns || []).forEach(function (c, i) { out.push({ slot: 'col' + i, list: c.children, label: 'Column ' + (i + 1) + ' (' + c.w + '/12)' }); });
    (b.tabs || []).forEach(function (t, i) { out.push({ slot: 'tab' + i, list: t.children, label: 'Tab: ' + t.label }); });
    return out;
  }
  function walk(list, fn, parent) {
    (list || []).forEach(function (b, i) {
      fn(b, list, i, parent);
      slots(b).forEach(function (s) { walk(s.list, fn, b); });
    });
  }
  function find(id) {
    var hit = null;
    ['page', 'result'].forEach(function (surf) {
      walk(D[surf], function (b, list, i, parent) { if (b.id === id) hit = { b: b, list: list, i: i, parent: parent, surface: surf }; });
    });
    return hit;
  }
  function slotList(target) {
    var parts = String(target).split(':'), owner = parts[0], slot = parts[1];
    if (owner === 'root') return D[surface];
    var f = find(owner);
    if (!f) return null;
    var s = slots(f.b).filter(function (x) { return x.slot === slot; })[0];
    return s ? s.list : null;
  }
  function contains(b, id) {
    var yes = false;
    walk([b], function (x) { if (x.id === id) yes = true; });
    return yes;
  }
  function fresh(b) {  /* a deep copy with new ids */
    var c = JSON.parse(JSON.stringify(b));
    walk([c], function (x) { x.id = newId(); });
    return c;
  }
  function allowed(type) { return SCH.blocks[type].surfaces.indexOf(surface) >= 0; }

  function change(fn, keepSel) {
    undo.push(JSON.stringify(D));
    if (undo.length > 60) undo.shift();
    redo = [];
    fn();
    if (!keepSel && sel && !find(sel)) sel = null;
    redraw();
  }
  function insert(type, target, index) {
    if (!allowed(type)) return;
    var b = blank(type);
    change(function () {
      var list = slotList(target) || D[surface];
      list.splice(index == null ? list.length : index, 0, b);
      sel = b.id;
    });
  }
  function move(id, target, index) {
    var f = find(id), list = slotList(target);
    if (!f || !list) return;
    var owner = String(target).split(':')[0];
    if (owner !== 'root' && contains(f.b, owner)) return;  /* not into itself */
    change(function () {
      f.list.splice(f.i, 1);
      if (list === f.list && index > f.i) index -= 1;
      list.splice(index == null ? list.length : Math.min(index, list.length), 0, f.b);
    }, true);
  }
  /* where a click on the palette puts a block: into the selected container,
     after the selected block, or at the end */
  function placeFor() {
    var f = sel && find(sel);
    if (f && f.surface === surface) {
      var s = slots(f.b)[0];
      if (s) return { target: f.b.id + ':' + s.slot, index: null };
      var p = f.parent, slot = 'root:root';
      if (p) slots(p).forEach(function (x) { if (x.list === f.list) slot = p.id + ':' + x.slot; });
      return { target: slot, index: f.i + 1 };
    }
    return { target: 'root:root', index: null };
  }

  /* ------------------------------------------------------------- palette */
  function drawPalette() {
    var groups = {}, order = [];
    Object.keys(SCH.blocks).forEach(function (k) {
      var b = SCH.blocks[k];
      if (b.surfaces.indexOf(surface) < 0) return;
      if (!groups[b.group]) { groups[b.group] = []; order.push(b.group); }
      groups[b.group].push(k);
    });
    $('sd-palette').innerHTML = order.map(function (g) {
      return '<div class="text-muted mt-1 mb-1" style="font-size:11px;font-weight:600;">' + esc(g) + '</div>' +
        groups[g].map(function (k) {
          return '<button type="button" class="btn btn-sm btn-outline-secondary w-100 mb-1 text-start" draggable="true" data-sd-new="' + k + '">' +
            esc(SCH.blocks[k].label) + '</button>';
        }).join('');
    }).join('');
  }
  $('sd-palette').addEventListener('click', function (e) {
    var b = e.target.closest('[data-sd-new]'); if (!b) return;
    var at = placeFor();
    insert(b.getAttribute('data-sd-new'), at.target, at.index);
  });
  $('sd-palette').addEventListener('dragstart', function (e) {
    var b = e.target.closest('[data-sd-new]'); if (!b) return;
    e.dataTransfer.setData('text/plain', 'new:' + b.getAttribute('data-sd-new'));
    e.dataTransfer.effectAllowed = 'copy';
  });

  /* --------------------------------------------------------------- outline */
  function label(b) {
    var p = b.props || {}, name = p.title || p.text || p.label || p.name || p.key || '';
    if (b.type === 'output' || b.type === 'stat') name = (CFG.outputs || {})[p.key] || p.key || '';
    return esc(SCH.blocks[b.type].label) + (name ? ' <span class="text-muted">' + esc(String(name).slice(0, 28)) + '</span>' : '');
  }
  function treeHtml(list, depth) {
    return (list || []).map(function (b) {
      var h = '<div class="sapp-node' + (b.id === sel ? ' sapp-sel' : '') + '" data-sd-node="' + b.id + '" style="padding-left:' + (4 + depth * 12) + 'px;">' +
        '<span class="flex-grow-1 text-truncate">' + label(b) + '</span>' +
        (b.id === sel ? '<span class="d-flex gap-1">' +
          '<button type="button" class="btn btn-sm btn-link p-0" data-sd-op="up" title="Up"><i class="bi bi-arrow-up"></i></button>' +
          '<button type="button" class="btn btn-sm btn-link p-0" data-sd-op="down" title="Down"><i class="bi bi-arrow-down"></i></button>' +
          '<button type="button" class="btn btn-sm btn-link p-0" data-sd-op="dup" title="Duplicate"><i class="bi bi-files"></i></button>' +
          '<button type="button" class="btn btn-sm btn-link p-0 text-danger" data-sd-op="del" title="Delete"><i class="bi bi-trash"></i></button></span>' : '') +
        '</div>';
      slots(b).forEach(function (s) {
        if (s.label) h += '<div class="sapp-slot" style="padding-left:' + (8 + (depth + 1) * 12) + 'px;">' + esc(s.label) + '</div>';
        h += treeHtml(s.list, depth + 1);
      });
      return h;
    }).join('');
  }
  function drawTree() {
    $('sd-tree').innerHTML = treeHtml(D[surface], 0) ||
      '<div class="text-muted" style="font-size:12px;">' + (surface === 'page'
        ? 'No page design: users get the standard layout.' : 'No result design: users get the standard result.') + '</div>';
  }
  $('sd-tree').addEventListener('click', function (e) {
    var op = e.target.closest('[data-sd-op]');
    if (op) { operate(op.getAttribute('data-sd-op')); return; }
    var n = e.target.closest('[data-sd-node]');
    if (n) select(n.getAttribute('data-sd-node'));
  });
  function operate(op) {
    var f = sel && find(sel);
    if (!f) return;
    if (op === 'del') change(function () { f.list.splice(f.i, 1); sel = null; });
    else if (op === 'dup') change(function () { var c = fresh(f.b); f.list.splice(f.i + 1, 0, c); sel = c.id; });
    else if (op === 'up' && f.i > 0) change(function () { f.list.splice(f.i - 1, 0, f.list.splice(f.i, 1)[0]); }, true);
    else if (op === 'down' && f.i < f.list.length - 1) change(function () { f.list.splice(f.i + 1, 0, f.list.splice(f.i, 1)[0]); }, true);
  }
  function select(id) {
    sel = id; themeOpen = !id;
    drawTree(); drawInspector(); markSel();
  }

  /* ---------------------------------------------------------------- canvas */
  function markSel() {
    Array.prototype.forEach.call($('sd-canvas').querySelectorAll('.sapp-sel'), function (el) { el.classList.remove('sapp-sel'); });
    if (!sel) return;
    var el = $('sd-canvas').querySelector('[data-sapp-id="' + sel + '"]');
    if (el) el.classList.add('sapp-sel');
  }
  function render() {
    var n = ++seq;
    post(U.preview, { design: D, surface: surface, mode: mode }).then(function (d) {
      if (n !== seq) return;
      var c = $('sd-canvas');
      c.innerHTML = d.html || '<div class="sapp-empty sapp-drop" data-sapp-drop="root:root" style="min-height:160px;">' +
        (surface === 'page' ? 'The standard layout is used. Drag blocks here, or start from the standard layout.'
          : 'The standard result is used. Drag blocks here, or start from the standard layout.') + '</div>';
      if (mode === 'view' && surface === 'result' && d.sample && window.AppRun) window.AppRun.fill(c, d.sample);
      markSel();
      notes(d.problems || [], d.warnings || []);
    }).catch(function (e) { if (n === seq) notes([e.message], []); });
  }
  function notes(problems, warnings) {
    var h = '';
    if (problems.length) h += '<div class="alert alert-warning py-2 mb-2"><strong>Fix before publishing:</strong><ul class="mb-0">' +
      problems.map(function (p) { return '<li>' + esc(p) + '</li>'; }).join('') + '</ul></div>';
    if (warnings.length) h += '<div class="alert alert-info py-2 mb-0"><strong>Hard to read</strong> (allowed, but check it):<ul class="mb-0">' +
      warnings.map(function (p) { return '<li>' + esc(p) + '</li>'; }).join('') + '</ul></div>';
    $('sd-notes').innerHTML = h;
  }
  function redraw() {
    drawTree(); drawInspector();
    $('sd-undo').disabled = !undo.length; $('sd-redo').disabled = !redo.length;
    state(dirty() ? 'Unsaved changes' : '', false);
    window.clearTimeout(timer);
    timer = window.setTimeout(render, 200);
  }

  var canvas = $('sd-canvas');
  canvas.addEventListener('click', function (e) {
    if (mode !== 'edit') {  /* "as users see it": links do not leave the editor */
      if (e.target.closest('a[href]')) e.preventDefault();
      return;
    }
    if (e.target.closest('.nav-link')) return;  /* a tab of a Tabs block */
    e.preventDefault();
    var b = e.target.closest('[data-sapp-id]');
    select(b ? b.getAttribute('data-sapp-id') : null);
  }, true);
  var line = document.createElement('div');
  line.className = 'sapp-drop-line';
  function dropAt(e) {
    var zone = e.target.closest('[data-sapp-drop]');
    if (!zone || !canvas.contains(zone)) return null;
    var kids = Array.prototype.filter.call(zone.children, function (c) { return c.hasAttribute('data-sapp-id'); });
    var index = kids.length, before = null;
    for (var i = 0; i < kids.length; i++) {
      var r = kids[i].getBoundingClientRect();
      if (e.clientY < r.top + r.height / 2) { index = i; before = kids[i]; break; }
    }
    return { zone: zone, index: index, before: before };
  }
  canvas.addEventListener('dragstart', function (e) {
    if (mode !== 'edit') { e.preventDefault(); return; }
    var b = e.target.closest('[data-sapp-id]'); if (!b) return;
    e.dataTransfer.setData('text/plain', 'move:' + b.getAttribute('data-sapp-id'));
    e.dataTransfer.effectAllowed = 'move';
    b.classList.add('sapp-dragging');
  });
  canvas.addEventListener('dragend', function () {
    Array.prototype.forEach.call(canvas.querySelectorAll('.sapp-dragging'), function (el) { el.classList.remove('sapp-dragging'); });
    if (line.parentNode) line.parentNode.removeChild(line);
  });
  canvas.addEventListener('dragover', function (e) {
    if (mode !== 'edit') return;
    var at = dropAt(e);
    if (!at) return;
    e.preventDefault();
    if (at.before) at.zone.insertBefore(line, at.before); else at.zone.appendChild(line);
  });
  canvas.addEventListener('dragleave', function (e) {
    if (!canvas.contains(e.relatedTarget) && line.parentNode) line.parentNode.removeChild(line);
  });
  canvas.addEventListener('drop', function (e) {
    if (mode !== 'edit') return;
    var at = dropAt(e);
    if (line.parentNode) line.parentNode.removeChild(line);
    if (!at) return;
    e.preventDefault();
    var data = e.dataTransfer.getData('text/plain') || '', target = at.zone.getAttribute('data-sapp-drop');
    if (data.indexOf('new:') === 0) insert(data.slice(4), target, at.index);
    else if (data.indexOf('move:') === 0) move(data.slice(5), target, at.index);
  });

  /* ------------------------------------------------------------- inspector */
  function hexOk(v) { return /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(v); }
  function hex6(v) { return !hexOk(v) ? '' : (v.length === 4 ? '#' + v[1] + v[1] + v[2] + v[2] + v[3] + v[3] : v).toUpperCase(); }
  function lum(h) {
    h = hex6(h);
    return [1, 3, 5].map(function (i) {
      var c = parseInt(h.substr(i, 2), 16) / 255;
      return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    }).reduce(function (s, c, i) { return s + c * [0.2126, 0.7152, 0.0722][i]; }, 0);
  }
  function ratio(a, b) {
    var x = lum(a), y = lum(b);
    return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
  }
  function colorRow(key, lab, val) {
    var v = hex6(val || '');
    return '<div class="d-flex align-items-center gap-1 mb-1"><label class="flex-grow-1 small mb-0">' + esc(lab) + '</label>' +
      '<input type="color" class="form-control form-control-color sapp-swatch" data-c="' + key + '" value="' + (v || '#FFFFFF') + '"' + (v ? '' : ' style="opacity:.35"') + '>' +
      '<input class="form-control form-control-sm" style="width:84px;" data-h="' + key + '" value="' + esc(v) + '" placeholder="—" maxlength="7">' +
      '<button type="button" class="btn btn-sm btn-link p-0" data-clear="' + key + '" title="Clear"><i class="bi bi-x-lg"></i></button></div>';
  }
  function presetRow(key, lab, choices, val) {
    return '<div class="d-flex align-items-center gap-1 mb-1"><label class="flex-grow-1 small mb-0">' + esc(lab) + '</label>' +
      '<select class="form-select form-select-sm" style="width:120px;" data-s="' + key + '"><option value="">—</option>' +
      choices.map(function (c) { return '<option' + (c === val ? ' selected' : '') + '>' + esc(c) + '</option>'; }).join('') + '</select></div>';
  }
  var STYLE_LABELS = { bg: 'Background', bg2: 'Gradient to', color: 'Text', border_color: 'Border colour',
    padding: 'Padding', mb: 'Space below', radius: 'Corners', shadow: 'Shadow', border: 'Border',
    size: 'Text size', weight: 'Weight', align: 'Align', width: 'Width' };
  var THEME_LABELS = { accent: 'Accent (buttons, links)', page_bg: 'Page background', text: 'Text',
    surface: 'Card surface', border: 'Borders', radius: 'Corners', padding: 'Page padding' };

  function propInput(p, v) {
    var id = 'data-p="' + p.name + '"';
    if (p.kind === 'bool') return '<div class="form-check mb-1"><input class="form-check-input" type="checkbox" ' + id + (v ? ' checked' : '') + '><label class="form-check-label small">' + esc(p.label) + '</label></div>';
    var lab = '<label class="form-label small mb-0">' + esc(p.label) + '</label>', ctl;
    if (p.kind === 'md') ctl = '<textarea class="form-control form-control-sm" rows="5" ' + id + ' maxlength="' + p.max + '">' + esc(v) + '</textarea>';
    else if (p.kind === 'enum') ctl = '<select class="form-select form-select-sm" ' + id + '>' + p.choices.map(function (c) {
      return '<option value="' + esc(c) + '"' + (c === v ? ' selected' : '') + '>' + esc(c || '—') + '</option>'; }).join('') + '</select>';
    else if (p.kind === 'field') ctl = '<select class="form-select form-select-sm" ' + id + '><option value="">—</option>' + (CFG.fields || []).map(function (f) {
      return '<option value="' + esc(f.name) + '"' + (f.name === v ? ' selected' : '') + '>' + esc(f.label || f.name) + ' (' + esc(f.name) + ')</option>'; }).join('') + '</select>';
    else if (p.kind === 'output') ctl = '<select class="form-select form-select-sm" ' + id + '><option value="">—</option>' + Object.keys(CFG.outputs || {}).map(function (k) {
      return '<option value="' + esc(k) + '"' + (k === v ? ' selected' : '') + '>' + esc(CFG.outputs[k]) + ' (' + esc(k) + ')</option>'; }).join('') + '</select>';
    else if (p.kind === 'asset') ctl = '<select class="form-select form-select-sm" ' + id + '><option value="">—</option>' + assets.map(function (a) {
      return '<option value="' + a.sha + '"' + (a.sha === v ? ' selected' : '') + '>' + esc(a.name) + '</option>'; }).join('') + '</select>';
    else if (p.kind === 'int') ctl = '<input type="number" class="form-control form-control-sm" ' + id + ' min="' + p.lo + '" max="' + p.hi + '" value="' + esc(v) + '">';
    else ctl = '<input class="form-control form-control-sm" ' + id + ' maxlength="' + (p.max || 200) + '" value="' + esc(v) + '"' +
      (p.kind === 'icon' ? ' placeholder="bi-star"' : '') + '>' + (p.kind === 'icon' && v ? '<i class="bi ' + esc(v) + ' ms-1"></i>' : '');
    return '<div class="mb-1">' + lab + ctl + '</div>';
  }
  function drawInspector() {
    var f = sel && find(sel), box = $('sd-inspector'), h = '';
    if (!f) {
      $('sd-insp-title').textContent = 'Theme (the whole app)';
      var t = D.theme;
      h += '<p class="text-muted" style="font-size:11.5px;">Applies inside the app only; SATOM\'s menus and bars keep their colours.</p>';
      SCH.theme_colors.forEach(function (k) { h += colorRow(k, THEME_LABELS[k] || k, t[k]); });
      Object.keys(SCH.theme_presets).forEach(function (k) { h += presetRow(k, THEME_LABELS[k] || k, SCH.theme_presets[k], t[k]); });
      if (t.accent) h += '<div class="small text-muted">White on the accent: ' + ratio(t.accent, '#FFFFFF').toFixed(1) + ':1</div>';
      box.innerHTML = h;
      box.setAttribute('data-target', 'theme');
      return;
    }
    var b = f.b, spec = SCH.blocks[b.type];
    $('sd-insp-title').textContent = spec.label;
    spec.props.forEach(function (p) { h += propInput(p, b.props[p.name]); });
    if (b.columns) {
      h += '<div class="mb-1"><label class="form-label small mb-0">Columns (width of each, out of 12)</label><div class="d-flex gap-1">' +
        b.columns.map(function (c, i) { return '<input type="number" min="1" max="12" class="form-control form-control-sm" data-col="' + i + '" value="' + c.w + '">'; }).join('') +
        '</div><div class="d-flex gap-1 mt-1">' +
        '<button type="button" class="btn btn-sm btn-outline-secondary" data-cols="add"' + (b.columns.length >= SCH.limits.columns ? ' disabled' : '') + '>+ column</button>' +
        '<button type="button" class="btn btn-sm btn-outline-secondary" data-cols="del"' + (b.columns.length <= 1 ? ' disabled' : '') + '>− column</button></div>' +
        (b.columns.reduce(function (s, c) { return s + c.w; }, 0) !== 12 ? '<div class="small text-muted">The widths add up to ' + b.columns.reduce(function (s, c) { return s + c.w; }, 0) + ', not 12: the row wraps or leaves space.</div>' : '') + '</div>';
    }
    if (b.tabs) {
      h += '<div class="mb-1"><label class="form-label small mb-0">Tabs</label>' + b.tabs.map(function (t, i) {
        return '<div class="d-flex gap-1 mb-1"><input class="form-control form-control-sm" data-tab="' + i + '" value="' + esc(t.label) + '" maxlength="60">' +
          '<button type="button" class="btn btn-sm btn-link p-0 text-danger" data-tabdel="' + i + '"' + (b.tabs.length <= 1 ? ' disabled' : '') + '><i class="bi bi-x-lg"></i></button></div>';
      }).join('') + '<button type="button" class="btn btn-sm btn-outline-secondary" data-tabadd' + (b.tabs.length >= SCH.limits.tabs ? ' disabled' : '') + '>+ tab</button></div>';
    }
    h += '<hr class="my-2"><div class="text-muted mb-1" style="font-size:11px;text-transform:uppercase;letter-spacing:.04em;">Style</div>';
    SCH.colors.forEach(function (k) { h += colorRow(k, STYLE_LABELS[k] || k, b.style[k]); });
    Object.keys(SCH.presets).forEach(function (k) { h += presetRow(k, STYLE_LABELS[k] || k, SCH.presets[k], b.style[k]); });
    if (b.style.bg || b.style.color) {
      var fg = b.style.color || D.theme.text || '#0C1B33', bg = b.style.bg || D.theme.surface || '#FFFFFF';
      var r = Math.min(ratio(fg, bg), b.style.bg && b.style.bg2 ? ratio(fg, b.style.bg2) : 99);
      h += '<div class="small ' + (r < SCH.min_contrast ? 'text-danger' : 'text-muted') + '">Text contrast ' + r.toFixed(1) + ':1' +
        (r < SCH.min_contrast ? ' — hard to read (' + SCH.min_contrast + ':1 recommended)' : '') + '</div>';
    }
    box.innerHTML = h;
    box.setAttribute('data-target', 'block');
  }
  function target() {
    var f = sel && find(sel);
    return f ? { props: f.b.props, style: f.b.style, b: f.b } : { props: null, style: D.theme, b: null };
  }
  var before = null;  /* the design before a colour drag started (one undo step per pick) */
  function setColor(key, v) {
    var t = target();
    if (before !== null) { undo.push(before); before = null; redo = []; }
    else { undo.push(JSON.stringify(D)); redo = []; }
    if (v) t.style[key] = v; else delete t.style[key];
    redraw();
  }
  var insp = $('sd-inspector');
  insp.addEventListener('input', function (e) {
    var el = e.target;
    if (el.hasAttribute('data-c')) {  /* the colour picker: live, one undo step per pick */
      var t = target();
      if (before === null) before = JSON.stringify(D);
      t.style[el.getAttribute('data-c')] = el.value.toUpperCase();
      window.clearTimeout(timer); timer = window.setTimeout(render, 120);
      state('Unsaved changes');
    }
  });
  insp.addEventListener('change', function (e) {
    var el = e.target, t = target();
    if (el.hasAttribute('data-c')) {
      setColor(el.getAttribute('data-c'), el.value.toUpperCase());
    } else if (el.hasAttribute('data-h')) {
      var hv = el.value.trim();
      if (hv && !hexOk(hv)) { state('A colour is #rgb or #rrggbb, e.g. #0A3F9F', true); return; }
      setColor(el.getAttribute('data-h'), hex6(hv));
    } else if (el.hasAttribute('data-s')) {
      var sk = el.getAttribute('data-s'), sv = el.value;
      change(function () { if (sv) t.style[sk] = sv; else delete t.style[sk]; }, true);
    } else if (el.hasAttribute('data-p') && t.props) {
      var pk = el.getAttribute('data-p'), pv = el.type === 'checkbox' ? el.checked : (el.type === 'number' ? parseInt(el.value || '0', 10) : el.value);
      change(function () { t.props[pk] = pv; }, true);
    } else if (el.hasAttribute('data-col') && t.b) {
      var ci = +el.getAttribute('data-col'), w = Math.max(1, Math.min(12, parseInt(el.value || '1', 10)));
      change(function () { t.b.columns[ci].w = w; }, true);
    } else if (el.hasAttribute('data-tab') && t.b) {
      var ti = +el.getAttribute('data-tab'), lv = el.value;
      change(function () { t.b.tabs[ti].label = lv; }, true);
    }
  });
  insp.addEventListener('click', function (e) {
    var t = target(), el;
    if ((el = e.target.closest('[data-clear]'))) setColor(el.getAttribute('data-clear'), '');
    else if ((el = e.target.closest('[data-cols]')) && t.b) {
      var add = el.getAttribute('data-cols') === 'add';
      change(function () {
        var cols = t.b.columns;
        if (add && cols.length < SCH.limits.columns) cols.push({ w: 3, children: [] });
        if (!add && cols.length > 1) {
          var gone = cols.pop();
          cols[cols.length - 1].children = cols[cols.length - 1].children.concat(gone.children);  /* nothing is lost */
        }
        var w = Math.floor(12 / cols.length);
        cols.forEach(function (c, i) { c.w = i === cols.length - 1 ? 12 - w * (cols.length - 1) : w; });
      }, true);
    } else if (e.target.closest('[data-tabadd]') && t.b) {
      change(function () { t.b.tabs.push({ label: 'Tab ' + (t.b.tabs.length + 1), children: [] }); }, true);
    } else if ((el = e.target.closest('[data-tabdel]')) && t.b) {
      var i = +el.getAttribute('data-tabdel');
      change(function () {
        var gone = t.b.tabs.splice(i, 1)[0];
        t.b.tabs[Math.max(0, i - 1)].children = t.b.tabs[Math.max(0, i - 1)].children.concat(gone.children);
      }, true);
    }
  });
  $('sd-theme-btn').addEventListener('click', function () { select(null); });

  /* ---------------------------------------------------------------- images */
  function drawAssets() {
    $('sd-assets').innerHTML = assets.map(function (a) {
      return '<div class="text-center" style="width:74px;font-size:10.5px;"><img src="' + esc(a.url) + '" alt="" style="width:70px;height:50px;object-fit:cover;border-radius:6px;border:1px solid var(--fw-border);">' +
        '<div class="text-truncate" title="' + esc(a.name) + '">' + esc(a.name) + '</div>' +
        '<button type="button" class="btn btn-sm btn-link p-0 text-danger" data-asset-del="' + a.sha + '" style="font-size:11px;">Remove</button></div>';
    }).join('') || '<span class="text-muted" style="font-size:12px;">No images yet.</span>';
  }
  $('sd-upload').addEventListener('change', function () {
    var file = this.files && this.files[0], input = this;
    if (!file) return;
    var fd = new FormData();
    fd.append('file', file);
    req(U.upload, { method: 'POST', credentials: 'same-origin', body: fd, headers: { 'X-CSRFToken': CSRF, 'Accept': 'application/json' } })
      .then(function (d) {
        if (!assets.some(function (a) { return a.sha === d.asset.sha; })) assets.push(d.asset);
        input.value = '';
        drawAssets();
        var f = sel && find(sel);
        if (f && f.b.type === 'image') change(function () { f.b.props.asset = d.asset.sha; }, true); else drawInspector();
        state('Image uploaded.');
      }).catch(function (e) { input.value = ''; state(e.message, true); });
  });
  $('sd-assets').addEventListener('click', function (e) {
    var b = e.target.closest('[data-asset-del]'); if (!b) return;
    var sha = b.getAttribute('data-asset-del');
    var shown = false;
    ['page', 'result'].forEach(function (s) { walk(D[s], function (x) { if (x.type === 'image' && x.props.asset === sha) shown = true; }); });
    if (shown) { state('The design shows this image: take it out first.', true); return; }
    if (!window.confirm('Remove this image?')) return;
    post(U.assetDelete.replace('SHA', sha)).then(function () {
      assets = assets.filter(function (a) { return a.sha !== sha; });
      drawAssets(); drawInspector();
    }).catch(function (err) { state(err.message, true); });
  });

  /* --------------------------------------------------------------- toolbar */
  Array.prototype.forEach.call(document.querySelectorAll('[data-sd-surface]'), function (b) {
    b.addEventListener('click', function () {
      surface = b.getAttribute('data-sd-surface');
      document.querySelectorAll('[data-sd-surface]').forEach(function (x) { x.classList.toggle('active', x === b); });
      sel = null; drawPalette(); redraw();
    });
  });
  Array.prototype.forEach.call(document.querySelectorAll('[data-sd-mode]'), function (b) {
    b.addEventListener('click', function () {
      mode = b.getAttribute('data-sd-mode');
      document.querySelectorAll('[data-sd-mode]').forEach(function (x) { x.classList.toggle('active', x === b); });
      render();
    });
  });
  function history(from, to) {
    if (!from.length) return;
    to.push(JSON.stringify(D));
    D = norm(JSON.parse(from.pop()));
    if (sel && !find(sel)) sel = null;
    redraw();
  }
  $('sd-undo').addEventListener('click', function () { history(undo, redo); });
  $('sd-redo').addEventListener('click', function () { history(redo, undo); });
  $('sd-starter').addEventListener('click', function () {
    if (D[surface].length && !window.confirm('Replace this surface with the standard layout?')) return;
    req(U.starter, { credentials: 'same-origin', headers: { Accept: 'application/json' } }).then(function (d) {
      change(function () { D[surface] = d.design[surface]; sel = null; });
    }).catch(function (e) { state(e.message, true); });
  });
  $('sd-clear').addEventListener('click', function () {
    if (!D[surface].length || !window.confirm('Empty this surface? Users get the standard layout again.')) return;
    change(function () { D[surface] = []; sel = null; });
  });
  $('sd-save').addEventListener('click', function () {
    var body = JSON.stringify(D);
    post(U.save, { design: D }).then(function (d) {
      saved = body;
      state('Design saved.');
      notes(d.problems.filter(function (p) { return p.indexOf('design') === 0; }), d.warnings || []);
    }).catch(function (e) { state(e.message, true); });
  });
  document.addEventListener('keydown', function (e) {
    var pane = $('ap-tab-design');
    if (!pane || !pane.classList.contains('active')) return;
    var typing = /^(INPUT|TEXTAREA|SELECT)$/.test((e.target || {}).tagName || '');
    if ((e.ctrlKey || e.metaKey) && (e.key === 'z' || e.key === 'Z') && !typing) { e.preventDefault(); history(e.shiftKey ? redo : undo, e.shiftKey ? undo : redo); }
    else if ((e.ctrlKey || e.metaKey) && (e.key === 'y' || e.key === 'Y') && !typing) { e.preventDefault(); history(redo, undo); }
    else if ((e.key === 'Delete' || e.key === 'Backspace') && sel && !typing) { e.preventDefault(); operate('del'); }
  });
  window.addEventListener('beforeunload', function (e) {
    if (dirty()) { e.preventDefault(); e.returnValue = ''; }
  });

  drawPalette(); drawAssets();
  /* drawn when the tab is first shown: the canvas measures nothing before */
  var shown = false, tabBtn = document.querySelector('[data-bs-target="#ap-tab-design"]');
  function first() { if (!shown) { shown = true; redraw(); } }
  if (tabBtn) tabBtn.addEventListener('shown.bs.tab', first);
  if (document.getElementById('ap-tab-design').classList.contains('active')) first();
})();
