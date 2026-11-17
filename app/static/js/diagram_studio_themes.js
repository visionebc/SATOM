/* diagram_studio_themes.js — colour themes and style clipboard (no DOM).
 *
 * The shipped themes come from app/services/diagram_engine/themes.json
 * (cfg.themes); an operator's own themes live in this browser
 * (localStorage, per user) and travel as JSON files. A theme colours by
 * MEANING: an element takes the entry of its category family
 * (network.firewall -> families.network), else of its shape
 * (shapes.diamond), else families.generic; text takes text.font;
 * containers (zones, swimlanes) take their layer's tint; connectors take
 * connectors[kind] (else default). Every application is ONE undoable
 * command, whatever its scope (selection, page, whole diagram).
 *
 * Pure functions over the satom.diagram/1 model and DS.Store, so the
 * headless tests run this file in node without a browser.
 */
(function () {
  'use strict';
  var DS = window.DS = window.DS || {};
  var T = DS.themes = {};
  var HEX = /^#[0-9A-Fa-f]{6}$/;
  var ID = /^[a-z0-9][a-z0-9\-]{0,39}$/;
  T.SCHEMA = 'satom.diagram.themes/1';
  T.FAMILIES = ['network', 'infra', 'security', 'flow', 'uml', 'bpmn', 'software', 'generic'];
  T.SHAPES = ['diamond', 'terminator', 'cylinder', 'cloud', 'document', 'note', 'table', 'actor'];
  T.MAX_CUSTOM = 30;
  /* The style keys a theme, "Copy style" and "Reset style" deal with. */
  T.EL_KEYS = ['fill', 'stroke', 'stroke_width', 'dashed', 'dash_pattern', 'opacity', 'rounded', 'font_color', 'font_size',
    'font_family', 'bold', 'italic', 'fill_opacity', 'stroke_opacity', 'gradient', 'shadow', 'shadow_color'];
  T.CONN_KEYS = ['stroke', 'stroke_width', 'dashed', 'dash_pattern', 'opacity', 'font_color', 'stroke_opacity', 'shadow', 'shadow_color'];

  function clone(o) { return o === undefined ? undefined : JSON.parse(JSON.stringify(o)); }
  function up(c) { return String(c).toUpperCase(); }

  // ---------------------------------------------------------------- contrast
  function lin(c) { c /= 255; return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); }
  T.luminance = function (hex) {
    var r = parseInt(hex.slice(1, 3), 16), g = parseInt(hex.slice(3, 5), 16), b = parseInt(hex.slice(5, 7), 16);
    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
  };
  T.contrast = function (a, b) {
    var la = T.luminance(a), lb = T.luminance(b);
    return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
  };

  // -------------------------------------------------------------- validation
  /* Problems of one theme (empty = usable). `strict` adds the 4.5:1 text
   * contrast rule the shipped themes are held to (custom themes only warn). */
  T.validate = function (t, strict) {
    var errs = [];
    function col(where, v) { if (!(typeof v === 'string' && HEX.test(v))) { errs.push(where + ' is not a #RRGGBB colour'); return false; } return true; }
    if (!t || typeof t !== 'object') return ['not a theme object'];
    if (typeof t.id !== 'string' || !ID.test(t.id)) errs.push('the id must be lower-case letters, digits and -');
    if (typeof t.name !== 'string' || !t.name.trim() || t.name.length > 60) errs.push('the name must be 1 to 60 characters');
    ['gradient', 'shadow'].forEach(function (k) { if (typeof t[k] !== 'boolean') errs.push(k + ' must be true or false'); });
    function entry(where, e) {
      if (!e || typeof e !== 'object') { errs.push(where + ' is missing'); return; }
      var ok = ['fill', 'fill2', 'stroke', 'font'].map(function (k) { return col(where + '.' + k, e[k]); }).every(Boolean);
      if (ok && strict) ['fill', 'fill2'].forEach(function (k) {
        var c = T.contrast(e.font, e[k]);
        if (c < 4.5) errs.push(where + ': text on ' + k + ' is ' + c.toFixed(2) + ':1');
      });
    }
    T.FAMILIES.forEach(function (f) { entry('families.' + f, (t.families || {})[f]); });
    T.SHAPES.forEach(function (sh) { entry('shapes.' + sh, (t.shapes || {})[sh]); });
    col('text.font', (t.text || {}).font);
    col('container.stroke', (t.container || {}).stroke);
    col('container.font', (t.container || {}).font);
    if (!Array.isArray(t.layers) || !t.layers.length || t.layers.length > 16) errs.push('layers needs 1 to 16 tints');
    else t.layers.forEach(function (c, i) { col('layers[' + i + ']', c); });
    var cs = t.connectors || {};
    if (!cs['default']) errs.push('connectors.default is missing');
    Object.keys(cs).slice(0, 64).forEach(function (k) {
      if (!/^[a-z][a-z0-9_\-]{0,39}$/.test(k)) { errs.push('connector kind ' + k + ' is not a valid kind'); return; }
      col('connectors.' + k + '.stroke', (cs[k] || {}).stroke);
      col('connectors.' + k + '.font', (cs[k] || {}).font);
    });
    return errs;
  };
  /* Only the keys a theme has, colours upper-cased: what is stored/exported. */
  T.clean = function (t) {
    function e(x) { return { fill: up(x.fill), fill2: up(x.fill2), stroke: up(x.stroke), font: up(x.font) }; }
    var out = { id: t.id, name: String(t.name).trim().slice(0, 60), description: String(t.description || '').slice(0, 200),
      gradient: !!t.gradient, shadow: !!t.shadow, families: {}, shapes: {}, text: { font: up(t.text.font) },
      container: { stroke: up(t.container.stroke), font: up(t.container.font) }, layers: t.layers.map(up), connectors: {} };
    T.FAMILIES.forEach(function (f) { out.families[f] = e(t.families[f]); });
    T.SHAPES.forEach(function (sh) { out.shapes[sh] = e(t.shapes[sh]); });
    Object.keys(t.connectors).slice(0, 64).forEach(function (k) { out.connectors[k] = { stroke: up(t.connectors[k].stroke), font: up(t.connectors[k].font) }; });
    return out;
  };

  // ------------------------------------------------- full-colour / 3D symbols
  /* Symbols of a "color" or "iso3d" library carry their own colours. A theme
   * or "Reset style" never gives such a symbol element a fill, a border box,
   * a gradient or a shadow (its fill and line stay "none"); only its label
   * colour follows. The editor registers the loaded libraries (setLibraries);
   * without them the built-in library ids decide. */
  T.OWN_COLOUR_VARIANTS = ['color', 'iso3d'];
  var libVariants = {};
  T.setLibraries = function (libs) {
    libVariants = {};
    (libs || []).forEach(function (l) { if (l && typeof l.id === 'string') libVariants[l.id] = l.variant || 'flat'; });
  };
  T.symbolVariant = function (ref) {
    var s = DS.model && DS.model.splitSymbol ? DS.model.splitSymbol(ref) : null;
    if (!s) return '';
    if (Object.prototype.hasOwnProperty.call(libVariants, s.lib)) return libVariants[s.lib];
    return T.OWN_COLOUR_VARIANTS.indexOf(s.lib) >= 0 ? s.lib : 'flat';
  };
  T.ownColours = function (e) {
    return !!(e && e.shape === 'symbol' && e.symbol && T.OWN_COLOUR_VARIANTS.indexOf(T.symbolVariant(e.symbol)) >= 0);
  };

  // -------------------------------------------------------------- resolution
  function isContainer(e) { return e.kind === 'container' || e.shape === 'zone' || e.shape === 'swimlane'; }
  /* The theme entry an element takes, and why (for the picker's legend). */
  T.entryFor = function (t, e) {
    var fam = (e.category || '').split('.')[0];
    if (fam && t.families[fam]) return { e: t.families[fam], by: 'family' };
    if (t.shapes[e.shape]) return { e: t.shapes[e.shape], by: 'shape' };
    if (e.shape === 'pill') return { e: t.shapes.terminator, by: 'shape' };
    return { e: t.families.generic, by: 'generic' };
  };
  /* The style changes a theme makes to one element (null: leave it alone). */
  T.elementPatch = function (t, e, layerIndex) {
    if (e.kind === 'image') return null;
    if (e.kind === 'text') return { font_color: t.text.font };
    // the label sits under the icon, on the page: the theme's text colour reads there
    if (T.ownColours(e)) {
      return { fill: 'none', stroke: 'none', font_color: t.text.font, shadow: false,
        gradient: { type: 'none', color: (e.style && e.style.gradient && e.style.gradient.color) || '#FFFFFF', angle: 90 } };
    }
    if (isContainer(e)) {
      var tint = t.layers[(layerIndex || 0) % t.layers.length];
      return { fill: e.style && e.style.fill === 'none' ? 'none' : tint, stroke: t.container.stroke, font_color: t.container.font,
        gradient: { type: 'none', color: tint, angle: 90 }, shadow: false };
    }
    var en = T.entryFor(t, e).e;
    return { fill: en.fill, stroke: en.stroke, font_color: en.font,
      gradient: t.gradient ? { type: 'linear', color: en.fill2, angle: 90 } : { type: 'none', color: en.fill2, angle: 90 },
      shadow: !!t.shadow && e.shape !== 'line', shadow_color: '#000000' };
  };
  T.connectorPatch = function (t, c) {
    var en = t.connectors[c.kind] || t.connectors['default'];
    return { stroke: en.stroke, font_color: en.font };
  };
  function patch(obj, p) { Object.keys(p).forEach(function (k) { obj.style[k] = clone(p[k]); }); }

  /* Apply theme `t` as ONE command. scope: 'selection' | 'page' | 'diagram'.
   * sel: {els: [ids], conns: [ids]} (selection scope); locked(o) -> true
   * skips objects on locked/hidden layers. Returns the number of objects
   * restyled, or 0 when there was nothing to do. */
  T.apply = function (store, t, scope, sel, locked, label) {
    locked = locked || function () { return false; };
    var n = 0;
    function onPage(page, tx, only) {
      var li = new Map(page.layers.map(function (l, i) { return [l.id, i]; }));
      page.elements.forEach(function (e) {
        if (only && !only.els.has(e.id)) return;
        if (locked(e, page)) return;
        var p = T.elementPatch(t, e, li.get(e.layer) || 0);
        if (!p) return;
        patch(tx ? tx.touch('el', e.id) : e, p); n++;
      });
      page.connectors.forEach(function (c) {
        if (only && !only.conns.has(c.id)) return;
        if (locked(c, page)) return;
        patch(tx ? tx.touch('conn', c.id) : c, T.connectorPatch(t, c)); n++;
      });
    }
    var name = label || ('Apply theme "' + t.name + '"');
    if (scope === 'diagram') {
      store.run(name, function (tx) {
        tx.pages();                                   // every page in one undo step
        store.doc.pages.forEach(function (pg) { onPage(pg, null, null); });
      });
    } else {
      var only = scope === 'selection' ? { els: new Set(sel.els || []), conns: new Set(sel.conns || []) } : null;
      store.run(name, function (tx) { onPage(store.page(), tx, only); });
    }
    return n;
  };

  /* Preview without a command: {id: style} of what `apply` would set on the
   * CURRENT page (the picker swaps these in and back while hovering). */
  T.previewStyles = function (store, t, scope, sel, locked) {
    var page = store.page(), out = { els: {}, conns: {} };
    var li = new Map(page.layers.map(function (l, i) { return [l.id, i]; }));
    var only = scope === 'selection' ? { els: new Set(sel.els || []), conns: new Set(sel.conns || []) } : null;
    locked = locked || function () { return false; };
    page.elements.forEach(function (e) {
      if ((only && !only.els.has(e.id)) || locked(e, page)) return;
      var p = T.elementPatch(t, e, li.get(e.layer) || 0);
      if (p) { var st = clone(e.style); Object.keys(p).forEach(function (k) { st[k] = clone(p[k]); }); out.els[e.id] = st; }
    });
    page.connectors.forEach(function (c) {
      if ((only && !only.conns.has(c.id)) || locked(c, page)) return;
      var st = clone(c.style), p = T.connectorPatch(t, c);
      Object.keys(p).forEach(function (k) { st[k] = p[k]; });
      out.conns[c.id] = st;
    });
    return out;
  };

  /* A custom theme made from the diagram's own colours: per family / shape /
   * connector kind the most used colours, the rest from `base`. */
  T.fromDiagram = function (doc, base, name) {
    var t = clone(base);
    t.id = 'custom-' + Date.now().toString(36);
    t.name = String(name || 'My theme').slice(0, 60);
    t.description = 'Made from the colours of a diagram.';
    var tally = {}, ctally = {}, grad = 0, shadow = 0, shapes = 0, tints = {};
    function vote(map, key, val) { var m = map[key] = map[key] || {}; m[val] = (m[val] || 0) + 1; }
    function top(m) { var best = null, n = -1; Object.keys(m || {}).forEach(function (k) { if (m[k] > n) { n = m[k]; best = k; } }); return best; }
    doc.pages.forEach(function (pg) {
      var li = new Map(pg.layers.map(function (l, i) { return [l.id, i]; }));
      pg.elements.forEach(function (e) {
        var st = e.style || {};
        if (e.kind === 'image' || e.kind === 'text') return;
        if (isContainer(e)) { if (HEX.test(st.fill || '')) vote(tints, li.get(e.layer) || 0, up(st.fill)); return; }
        if (!HEX.test(st.fill || '') || !HEX.test(st.stroke || '') || !HEX.test(st.font_color || '')) return;
        var g = st.gradient || {}, fill2 = g.type === 'linear' && HEX.test(g.color || '') ? up(g.color) : up(st.fill);
        var fam = (e.category || '').split('.')[0];
        var key = fam && t.families[fam] ? 'f:' + fam : t.shapes[e.shape] ? 's:' + e.shape : 'f:generic';
        vote(tally, key, [up(st.fill), fill2, up(st.stroke), up(st.font_color)].join(','));
        shapes++; if (g.type && g.type !== 'none') grad++; if (st.shadow) shadow++;
      });
      pg.connectors.forEach(function (c) {
        var st = c.style || {};
        if (HEX.test(st.stroke || '') && HEX.test(st.font_color || '')) vote(ctally, c.kind || 'default', up(st.stroke) + ',' + up(st.font_color));
      });
    });
    Object.keys(tally).forEach(function (key) {
      var v = top(tally[key]).split(','), e = { fill: v[0], fill2: v[1], stroke: v[2], font: v[3] };
      if (key.indexOf('f:') === 0) t.families[key.slice(2)] = e; else t.shapes[key.slice(2)] = e;
    });
    Object.keys(ctally).forEach(function (k) { var v = top(ctally[k]).split(','); t.connectors[k] = { stroke: v[0], font: v[1] }; });
    Object.keys(tints).forEach(function (i) { if (Number(i) < t.layers.length) t.layers[Number(i)] = top(tints[i]); });
    if (shapes) { t.gradient = grad * 2 > shapes; t.shadow = shadow * 2 > shapes; }
    return T.clean(t);
  };

  // ------------------------------------------------------------------ store
  T.storageKey = function (userId) { return 'satom.ds.themes.u' + (userId === undefined || userId === null ? 'anon' : String(userId)); };
  T.loadCustom = function (userId) {
    try {
      var raw = JSON.parse(window.localStorage.getItem(T.storageKey(userId)) || '[]');
      return (Array.isArray(raw) ? raw : []).filter(function (t) { return !T.validate(t).length; }).map(T.clean).slice(0, T.MAX_CUSTOM);
    } catch (e) { return []; }
  };
  T.saveCustom = function (userId, list) {
    try { window.localStorage.setItem(T.storageKey(userId), JSON.stringify(list.slice(0, T.MAX_CUSTOM))); return true; } catch (e) { return false; }
  };
  /* A file's themes: {schema, themes: [...]} or one theme object. Each comes
   * back {theme} or {error}; ids are made custom- and unique against `taken`. */
  T.parseFile = function (text, taken) {
    var data;
    try { data = JSON.parse(text); } catch (e) { return [{ error: 'The file is not JSON.' }]; }
    var list = data && Array.isArray(data.themes) ? data.themes : [data];
    if (data && data.themes && data.schema !== T.SCHEMA) return [{ error: 'The file is not a ' + T.SCHEMA + ' document.' }];
    taken = new Set(taken || []);
    return list.slice(0, T.MAX_CUSTOM).map(function (t) {
      var errs = T.validate(t);
      if (errs.length) return { error: ((t && t.name) || 'A theme') + ': ' + errs.slice(0, 3).join('; ') + (errs.length > 3 ? '…' : '') };
      var c = T.clean(t);
      var base = c.id.indexOf('custom-') === 0 ? c.id : ('custom-' + c.id).slice(0, 40), id = base, i = 2;
      while (taken.has(id)) id = (base.slice(0, 36) + '-' + i++);
      taken.add(id); c.id = id;
      return { theme: c, warnings: T.validate(c, true) };
    });
  };
  T.toFile = function (themes) { return JSON.stringify({ schema: T.SCHEMA, themes: themes.map(T.clean) }, null, 1); };

  // ------------------------------------------------------ style clipboard
  /* What "Copy style" keeps: the element or connector style keys. */
  T.copyStyle = function (obj, isConn) {
    var keys = isConn ? T.CONN_KEYS : T.EL_KEYS, out = { from: isConn ? 'conn' : 'el', style: {} };
    keys.forEach(function (k) { if (obj.style[k] !== undefined) out.style[k] = clone(obj.style[k]); });
    return out;
  };
  /* Paste onto an element or a connector: only keys that kind has. */
  T.pasteStyle = function (obj, clip, isConn) {
    var keys = isConn ? T.CONN_KEYS : T.EL_KEYS;
    keys.forEach(function (k) { if (clip.style[k] !== undefined) obj.style[k] = clone(clip.style[k]); });
  };
  /* "Reset style": the model defaults (text and full-colour / 3D symbols keep no box). */
  T.resetStyle = function (obj, isConn) {
    var M = DS.model, def = isConn ? M.CSTYLE : M.STYLE, keys = isConn ? T.CONN_KEYS : T.EL_KEYS;
    keys.forEach(function (k) { obj.style[k] = clone(def[k]); });
    if (!isConn && (obj.kind === 'text' || T.ownColours(obj))) { obj.style.fill = 'none'; obj.style.stroke = 'none'; }
  };
})();
