/* diagram_studio_render.js — keyed SVG renderer of one satom.diagram/1 page.
 *
 * One <g> per element and per connector, keyed by id: an edit re-draws only
 * the nodes that changed (updateEls / updateConns), pan and zoom only move
 * one transform. Shapes follow exporters/_common.outline() and text_blocks()
 * so the canvas matches the exported SVG/PDF/draw.io files.
 *
 * Used by the editor, the review page and the published viewer.
 * CSP-safe: DOM APIs only. Symbol icons are fetched from the sanitising
 * endpoint and re-built element by element through a whitelist.
 */
(function () {
  'use strict';
  var DS = window.DS;
  var G = DS.geom, R = DS.routing, s = DS.s;
  var ROW_H = 22, HEADER_H = 30;
  var DEFAULT_FONT = 'Helvetica, Arial, sans-serif';

  function n(v) { return String(Math.round(v * 100) / 100); }
  function paint(c, d) { return c === 'none' ? 'none' : (DS.model.COLOR_RE.test(c || '') ? c : d); }

  // ------------------------------------------------------------- outlines

  function poly(fr, w, h) { return fr.map(function (p) { return [p[0] * w, p[1] * h]; }); }
  /* Exporter outline(): primitives in local coordinates. */
  function outline(e) {
    var shape = e.shape, w = Math.max(e.w, 0), h = Math.max(e.h, 0);
    var rxStyle = e.style.rounded ? Math.min(w, h) * 0.12 : 0;
    if (e.kind === 'image') return [{ t: 'rect', rx: 0, fill: false, stroke: false }];
    switch (shape) {
      case 'round': return [{ t: 'rect', rx: Math.min(w, h) * 0.12 }];
      case 'terminator': case 'pill': return [{ t: 'rect', rx: Math.min(w, h) / 2 }];
      case 'ellipse': return [{ t: 'ellipse', cx: w / 2, cy: h / 2, rx: w / 2, ry: h / 2 }];
      case 'diamond': return [{ t: 'poly', pts: poly([[.5, 0], [1, .5], [.5, 1], [0, .5]], w, h) }];
      case 'hexagon': return [{ t: 'poly', pts: poly([[.25, 0], [.75, 0], [1, .5], [.75, 1], [.25, 1], [0, .5]], w, h) }];
      case 'parallelogram': return [{ t: 'poly', pts: poly([[.2, 0], [1, 0], [.8, 1], [0, 1]], w, h) }];
      case 'trapezoid': return [{ t: 'poly', pts: poly([[.2, 0], [.8, 0], [1, 1], [0, 1]], w, h) }];
      case 'triangle': return [{ t: 'poly', pts: poly([[.5, 0], [1, 1], [0, 1]], w, h) }];
      case 'cylinder': {
        var ry = Math.max(1, Math.min(h * 0.15, h / 2 - 0.5)), hw = w / 2;
        return [{ t: 'path', d: 'M0,' + n(ry) + ' A' + n(hw) + ',' + n(ry) + ' 0 0 1 ' + n(w) + ',' + n(ry) + ' L' + n(w) + ',' + n(h - ry) + ' A' + n(hw) + ',' + n(ry) + ' 0 0 1 0,' + n(h - ry) + ' Z' },
          { t: 'path', d: 'M0,' + n(ry) + ' A' + n(hw) + ',' + n(ry) + ' 0 0 0 ' + n(w) + ',' + n(ry), fill: false }];
      }
      case 'cloud': {
        var c = [[.25, .8], [.05, .8, 0, .55, .15, .45], [.1, .25, .3, .1, .45, .2], [.55, 0, .8, .05, .82, .28],
          [1, .3, 1.02, .6, .88, .72], [.9, .88, .75, .95, .65, .82], [.55, .98, .35, .95, .25, .8]];
        var d = 'M' + n(c[0][0] * w) + ',' + n(c[0][1] * h);
        for (var i = 1; i < c.length; i++) d += ' C' + [0, 2, 4].map(function (k) { return n(c[i][k] * w) + ',' + n(c[i][k + 1] * h); }).join(' ');
        return [{ t: 'path', d: d + ' Z' }];
      }
      case 'document':
        return [{ t: 'path', d: 'M0,0 L' + n(w) + ',0 L' + n(w) + ',' + n(.88 * h) + ' C' + n(.75 * w) + ',' + n(.76 * h) + ' ' + n(.65 * w) + ',' + n(.76 * h) + ' ' + n(.5 * w) + ',' + n(.88 * h) +
          ' C' + n(.35 * w) + ',' + n(h) + ' ' + n(.25 * w) + ',' + n(h) + ' 0,' + n(.88 * h) + ' Z' }];
      case 'note': {
        var f = Math.max(0, Math.min(14, w / 3, h / 3));
        return [{ t: 'poly', pts: [[0, 0], [w - f, 0], [w, f], [w, h], [0, h]] },
          { t: 'path', d: 'M' + n(w - f) + ',0 L' + n(w - f) + ',' + n(f) + ' L' + n(w) + ',' + n(f), fill: false }];
      }
      case 'process': {
        var pf = Math.min(w * 0.1, 20);
        return [{ t: 'rect', rx: 0 }, { t: 'path', d: 'M' + n(pf) + ',0 L' + n(pf) + ',' + n(h) + ' M' + n(w - pf) + ',0 L' + n(w - pf) + ',' + n(h), fill: false }];
      }
      case 'actor': {
        var r = Math.max(1, Math.min(w * 0.2, h * 0.12));
        return [{ t: 'ellipse', cx: w / 2, cy: .15 * h, rx: r, ry: r },
          { t: 'path', fill: false, d: 'M' + n(w / 2) + ',' + n(.27 * h) + ' L' + n(w / 2) + ',' + n(.62 * h) + ' M' + n(.1 * w) + ',' + n(.4 * h) + ' L' + n(.9 * w) + ',' + n(.4 * h) +
            ' M' + n(w / 2) + ',' + n(.62 * h) + ' L' + n(.15 * w) + ',' + n(h) + ' M' + n(w / 2) + ',' + n(.62 * h) + ' L' + n(.85 * w) + ',' + n(h) }];
      }
      case 'swimlane': { var hh = Math.min(HEADER_H, h); return [{ t: 'rect', rx: 0 }, { t: 'line', pts: [[0, hh], [w, hh]] }]; }
      case 'table': {
        var th = Math.min(HEADER_H, h);
        var items = [{ t: 'rect', rx: 0 }, { t: 'line', pts: [[0, th], [w, th]] }];
        (e.rows || []).forEach(function (row, j) { var y = th + ROW_H * (j + 1); if (y < h - 0.5) items.push({ t: 'line', pts: [[0, y], [w, y]] }); });
        return items;
      }
      case 'polygon':
        if ((e.points || []).length >= 2) return [{ t: 'poly', pts: e.points.map(function (p) { return [p[0] * w, p[1] * h]; }) }];
        break;
      case 'path':
        if (e.path) return [{ t: 'path', d: e.path }];
        break;
      case 'line': return [{ t: 'line', pts: [[0, h / 2], [w, h / 2]] }];
      case 'symbol': return [{ t: 'rect', rx: Math.min(8, Math.min(w, h) * 0.12) }];
    }
    return [{ t: 'rect', rx: rxStyle }];
  }
  DS.outline = outline;

  function prim(p, st, w, h, parent, fx) {
    var fill = p.fill === false ? 'none' : (fx && fx.fill) || paint(st.fill, '#FFFFFF');
    var stroke = p.stroke === false ? 'none' : paint(st.stroke, '#1F2937');
    var a = { fill: fill, stroke: stroke };
    if (fx) Object.assign(a, p.fill === false || p.t === 'line' ? fx.line : fx.filled);
    if (p.t === 'rect') { a.x = 0; a.y = 0; a.width = n(w); a.height = n(h); if (p.rx) a.rx = n(p.rx); return s('rect', a, parent); }
    if (p.t === 'ellipse') { a.cx = n(p.cx); a.cy = n(p.cy); a.rx = n(p.rx); a.ry = n(p.ry); return s('ellipse', a, parent); }
    if (p.t === 'poly') { a.points = p.pts.map(function (q) { return n(q[0]) + ',' + n(q[1]); }).join(' '); return s('polygon', a, parent); }
    if (p.t === 'line') { return s('polyline', Object.assign({ points: p.pts.map(function (q) { return n(q[0]) + ',' + n(q[1]); }).join(' '), fill: 'none', stroke: stroke }, fx ? fx.line : {}), parent); }
    if (p.t === 'path') { a.d = p.d; return s('path', a, parent); }
    return null;
  }

  // ------------------------------------------------------- colour styling
  /* The numbers of exporters/_common.py (dash_array, gradient_vector, SHADOW_*):
   * the canvas draws what the SVG/PDF/draw.io files draw. */
  var SHADOW = { dx: 2, dy: 3, blur: 2.5, alpha: 0.3 };
  DS.SHADOW = SHADOW;
  function dashArray(st) {
    var sw = Math.max(0, Number(st.stroke_width) || 0), pat = DS.model.dashPattern(st);
    if (pat === 'dashed') return [Math.max(4, sw * 4), Math.max(3, sw * 3)];
    if (pat === 'dotted') return [Math.max(1, sw), Math.max(2, sw * 2)];
    if (pat === 'dash-dot') return [Math.max(6, sw * 6), Math.max(3, sw * 3), Math.max(1, sw), Math.max(3, sw * 3)];
    return [];
  }
  DS.dashArray = dashArray;
  function gradVector(angle) {
    var a = angle * Math.PI / 180, c = Math.cos(a), sn = Math.sin(a), k = (Math.abs(c) + Math.abs(sn)) / 2;
    var r = function (v) { return Math.round(v * 10000) / 10000; };
    return [r(0.5 - c * k), r(0.5 - sn * k), r(0.5 + c * k), r(0.5 + sn * k)];
  }
  DS.gradVector = gradVector;
  function gradientOf(st) {
    var g = st.gradient || {}, C = DS.model.COLOR_RE;
    if ((g.type === 'linear' || g.type === 'radial') && C.test(g.color || '') && C.test(st.fill || '')) return g;
    return null;
  }
  DS.gradientOf = gradientOf;


  function measure(fs, bold) { var k = bold ? 0.58 : 0.54; return function (str) { return str.length * fs * k; }; }
  function wrapLines(text, width, m) {
    var out = [];
    String(text).replace(/\r/g, '').split('\n').forEach(function (raw) {
      if (!raw.trim() || width <= 0 || m(raw) <= width) { out.push(raw); return; }
      var cur = '';
      raw.split(' ').forEach(function (word) {
        var cand = cur ? cur + ' ' + word : word;
        if (m(cand) <= width || !cur) {
          cur = cand;
          while (m(cur) > width && cur.length > 1) {
            var k = cur.length;
            while (k > 1 && m(cur.slice(0, k)) > width) k--;
            out.push(cur.slice(0, k)); cur = cur.slice(k);
          }
        } else { out.push(cur); cur = word; }
      });
      out.push(cur);
    });
    return out;
  }
  DS.wrapLines = wrapLines;

  // --------------------------------------------------- corner icon placement
  /* exporters/_common.py icon_safe_box / icon_box / make_room_for_icon, number for
   * number (tests/_diagram_icon_table.py holds this file's results): the small
   * icon of a non-symbol shape goes at the top-left of the part of the box that is
   * inside the outline, and text that would run under it moves clear. */
  var ICON_MAX = 18, ICON_PAD = 4, ICON_GAP = 2, MIN_TEXT_W = 24, SQRT_HALF = 0.7071067811865476;
  var SAFE_FRACTIONS = {
    ellipse: [(1 - SQRT_HALF) / 2, (1 - SQRT_HALF) / 2, (1 + SQRT_HALF) / 2, (1 + SQRT_HALF) / 2],
    diamond: [0.25, 0.25, 0.75, 0.75], hexagon: [0.25, 0, 0.75, 1], parallelogram: [0.2, 0, 0.8, 1],
    trapezoid: [0.2, 0, 0.8, 1], triangle: [0.25, 0.5, 0.75, 1], cloud: [0.2, 0.3, 0.8, 0.7], document: [0, 0, 1, 0.76]
  };
  DS.SAFE_FRACTIONS = SAFE_FRACTIONS;
  function iconSafeBox(e) {
    var shape = e.shape, w = Math.max(e.w, 0), h = Math.max(e.h, 0), fr = SAFE_FRACTIONS[shape], r = 0;
    if (fr) return [fr[0] * w, fr[1] * h, (fr[2] - fr[0]) * w, (fr[3] - fr[1]) * h];
    if (shape === 'round') r = Math.min(w, h) * 0.12;
    else if (shape === 'terminator' || shape === 'pill') r = Math.min(w, h) / 2;
    else if (shape === 'cylinder') { var ry = Math.max(1, Math.min(h * 0.15, h / 2 - 0.5)); return [0, 2 * ry, w, Math.max(0, h - 3 * ry)]; }
    else if (shape === 'note') { var f = Math.max(0, Math.min(14, w / 3, h / 3)); return [0, 0, Math.max(0, w - f), h]; }
    else if (shape === 'process') { var pf = Math.min(w * 0.1, 20); return [pf, 0, Math.max(0, w - 2 * pf), h]; }
    else if (['table', 'swimlane', 'actor', 'line', 'polygon', 'path'].indexOf(shape) < 0 && e.style && e.style.rounded) r = Math.min(w, h) * 0.12;
    if (r) { var i = r * (1 - SQRT_HALF); return [i, i, Math.max(0, w - 2 * i), Math.max(0, h - 2 * i)]; }
    return [0, 0, w, h];
  }
  DS.iconSafeBox = iconSafeBox;
  /* {x, y, size, big} in element-local px, or null (exporter icon_box). */
  function iconBox(e) {
    if (!e.symbol || e.kind === 'image') return null;
    var short = Math.min(e.w, e.h);
    if (e.shape === 'symbol') { var bs = short * 0.72; return { x: (e.w - bs) / 2, y: (e.h - bs) / 2, size: bs, big: true }; }
    var sb = iconSafeBox(e);
    var size = Math.min(ICON_MAX, short * 0.4, sb[2] - 2 * ICON_PAD, sb[3] - 2 * ICON_PAD);
    if (size < 8) return null;
    return { x: sb[0] + ICON_PAD, y: sb[1] + ICON_PAD, size: size, big: false };
  }
  DS.iconBox = iconBox;
  function makeRoomForIcon(e, blocks) {
    var ib = iconBox(e);
    if (!ib || ib.big) return blocks;
    var fs = Number(e.style && e.style.font_size) || 12, lh = fs * 1.2;
    return blocks.map(function (b) {
      if (b.below) return b;
      var m = measure(fs, !!b.bold), lines = wrapLines(b.text, b.w, m);
      if (!lines.length) return b;
      var total = lh * lines.length, lw = Math.max.apply(null, lines.map(m));
      var ty = b.valign === 'top' ? b.y : b.valign === 'bottom' ? b.y + b.h - total : b.y + (b.h - total) / 2;
      var tx = b.align === 'left' ? b.x : b.align === 'right' ? b.x + b.w - lw : b.x + (b.w - lw) / 2;
      if (ty >= ib.y + ib.size + ICON_GAP || ty + total <= ib.y || tx >= ib.x + ib.size + ICON_GAP || tx + lw <= ib.x) return b;
      b = Object.assign({}, b);
      var top = ib.y + ib.size + ICON_GAP, inset = ib.x + ib.size + ICON_GAP - b.x;
      var nw = b.w - (b.align === 'left' ? inset : 2 * inset);
      if (b.y + b.h - top >= total || nw < MIN_TEXT_W) { b.h = Math.max(0, b.y + b.h - top); b.y = top; if (b.h < total) b.valign = 'top'; }
      else { b.x = b.x + inset; b.w = nw; }
      return b;
    });
  }

  function textBlocks(e) { return makeRoomForIcon(e, baseTextBlocks(e)); }
  function baseTextBlocks(e) {
    var st = e.style, w = e.w, h = e.h;
    if (e.shape === 'table') {
      var hh = Math.min(HEADER_H, h);
      var blocks = [{ x: 0, y: 0, w: w, h: hh, text: e.text, bold: true, align: st.align, valign: 'middle' }];
      (e.rows || []).forEach(function (r, j) {
        if (hh + ROW_H * j >= h) return;
        blocks.push({ x: 6, y: hh + ROW_H * j, w: Math.max(0, w - 10), h: ROW_H, text: r.text, bold: !!r.bold, align: 'left', valign: 'middle' });
      });
      return blocks.filter(function (b) { return b.text; });
    }
    if (e.shape === 'swimlane') return e.text ? [{ x: 0, y: 0, w: w, h: Math.min(HEADER_H, h), text: e.text, bold: st.bold, align: st.align, valign: 'middle' }] : [];
    if (!e.text) return [];
    if (e.shape === 'symbol') return [{ x: -40, y: h + 2, w: w + 80, h: 0, text: e.text, bold: st.bold, align: 'center', valign: 'top', below: true }];
    return [{ x: 4, y: 2, w: Math.max(0, w - 8), h: Math.max(0, h - 4), text: e.text, bold: st.bold, align: st.align, valign: st.valign }];
  }
  DS.textBlocks = textBlocks;

  function textEl(b, e, parent) {
    var st = e.style, fs = st.font_size || 12, bold = !!b.bold;
    var lines = wrapLines(b.text, b.w, measure(fs, bold));
    if (!lines.length) return;
    var lh = fs * 1.2, total = lh * lines.length;
    var x, anchor;
    if (b.align === 'left') { x = b.x; anchor = 'start'; } else if (b.align === 'right') { x = b.x + b.w; anchor = 'end'; } else { x = b.x + b.w / 2; anchor = 'middle'; }
    var y0 = b.valign === 'top' ? b.y : b.valign === 'bottom' ? b.y + b.h - total : b.y + (b.h - total) / 2;
    y0 += fs * 0.95;
    var t = s('text', { 'font-family': st.font_family || DEFAULT_FONT, 'font-size': n(fs), 'font-weight': bold ? 'bold' : 'normal',
      'font-style': st.italic ? 'italic' : 'normal', 'text-anchor': anchor, fill: paint(st.font_color, '#111827'), 'xml:space': 'preserve', class: 'ds-text' }, parent);
    if (b.below) { t.setAttribute('stroke', '#FFFFFF'); t.setAttribute('stroke-width', '3'); t.setAttribute('paint-order', 'stroke'); }
    lines.forEach(function (ln, i) { s('tspan', { x: n(x), y: n(y0 + i * lh), text: ln }, t); });
  }

  // ------------------------------------------------------- symbol icons

  var ICON_TAGS = { path: 1, rect: 1, circle: 1, ellipse: 1, line: 1, polyline: 1, polygon: 1, g: 1 };
  var ICON_ATTRS = ['d', 'points', 'x', 'y', 'width', 'height', 'rx', 'ry', 'cx', 'cy', 'r', 'x1', 'y1', 'x2', 'y2', 'fill', 'fill-rule',
    'stroke', 'stroke-width', 'stroke-linecap', 'stroke-linejoin', 'stroke-dasharray', 'opacity', 'transform'];
  var iconCache = DS._iconCache = DS._iconCache || new Map();   // url -> Promise<{viewBox, nodes:[Element]}|null>

  function rebuildIcon(src, dst, depth) {
    if (depth > 10) return;
    Array.prototype.forEach.call(src.children, function (c) {
      var tag = (c.localName || '').toLowerCase();
      if (!ICON_TAGS[tag]) return;
      var e = document.createElementNS(DS.SVGNS, tag);
      ICON_ATTRS.forEach(function (a) {
        var v = c.getAttribute(a);
        if (v === null) return;
        if (/url\(|javascript:|expression|[<>]/i.test(v)) return;
        e.setAttribute(a, v);
      });
      dst.appendChild(e);
      if (tag === 'g') rebuildIcon(c, e, depth + 1);
    });
  }
  DS.loadIcon = function (url) {
    if (iconCache.has(url)) return iconCache.get(url);
    var p = fetch(url, { credentials: 'same-origin' }).then(function (r) { return r.ok ? r.text() : null; }).then(function (txt) {
      if (!txt || txt.length > 70000) return null;
      var doc = new DOMParser().parseFromString(txt, 'image/svg+xml');
      var root = doc.documentElement;
      if (!root || root.localName !== 'svg' || doc.getElementsByTagName('parsererror').length) return null;
      var g = document.createElementNS(DS.SVGNS, 'g');
      ['fill', 'stroke', 'stroke-width', 'stroke-linecap', 'stroke-linejoin'].forEach(function (a) {
        var v = root.getAttribute(a); if (v && !/url\(|[<>]/.test(v)) g.setAttribute(a, v);
      });
      rebuildIcon(root, g, 0);
      var vb = (root.getAttribute('viewBox') || '0 0 48 48').split(/[\s,]+/).map(Number);
      if (vb.length !== 4 || vb.some(isNaN)) vb = [0, 0, 48, 48];
      return { vb: vb, g: g };
    }).catch(function () { return null; });
    iconCache.set(url, p);
    return p;
  };

  // ------------------------------------------------------------- Renderer

  /* opts: {symbolUrl(lib, sym) -> url, decorate(e) -> class string, interactive} */
  function Renderer(svg, opts) {
    this.svg = svg;
    this.opts = opts || {};
    this.view = { k: 1, x: 0, y: 0 };
    this.els = new Map();
    this.conns = new Map();
    this.routes = new Map();
    this.layers = new Map();
    this.markers = new Map();
    this.page = null;
    this.byId = new Map();
    this.index = new G.Index(160);
    this.grid = { show: true, size: 10 };
    this.listeners = [];
    DS.clear(svg);
    svg.classList.add('ds-svg');
    // The <svg> sits in an HTML "stage": gestures move the stage on the
    // compositor (a transform on the <svg> root itself re-lays out its subtree).
    if (!svg.parentNode || !svg.parentNode.classList || !svg.parentNode.classList.contains('ds-stage')) {
      var stage = document.createElement('div');
      stage.className = 'ds-stage';
      if (svg.parentNode) svg.parentNode.insertBefore(stage, svg);
      stage.appendChild(svg);
    }
    this.stage = svg.parentNode;
    this.defs = s('defs', null, svg);
    var pat = s('pattern', { id: this._uid('grid'), width: 10, height: 10, patternUnits: 'userSpaceOnUse' }, this.defs);
    this.gridPath = s('path', { d: 'M10 0 L0 0 0 10', fill: 'none', class: 'ds-grid-line' }, pat);
    this.gridPattern = pat;
    var pat2 = s('pattern', { id: this._uid('grid5'), width: 50, height: 50, patternUnits: 'userSpaceOnUse' }, this.defs);
    s('rect', { width: 50, height: 50, fill: 'url(#' + pat.id + ')' }, pat2);
    this.gridPath5 = s('path', { d: 'M50 0 L0 0 0 50', fill: 'none', class: 'ds-grid-line5' }, pat2);
    this.gridPattern5 = pat2;
    this.vp = s('g', { class: 'ds-viewport' }, svg);
    this.pageRect = s('rect', { class: 'ds-page', x: 0, y: 0 }, this.vp);
    this.gridRect = s('rect', { class: 'ds-grid', x: 0, y: 0, fill: 'url(#' + pat2.id + ')' }, this.vp);
    this.content = s('g', { class: 'ds-content' }, this.vp);
    this.overlay = s('g', { class: 'ds-overlay' }, this.vp);
  }
  DS.Renderer = Renderer;
  var uidN = 0;
  Renderer.prototype._uid = function (p) { return 'ds' + (++uidN) + '-' + p; };

  Renderer.prototype.setGrid = function (show, size) {
    this.grid = { show: !!show, size: size || 10 };
    var g = this.grid.size, g5 = g * 5;
    this.gridPattern.setAttribute('width', g); this.gridPattern.setAttribute('height', g);
    this.gridPath.setAttribute('d', 'M' + g + ' 0 L0 0 0 ' + g);
    this.gridPattern5.setAttribute('width', g5); this.gridPattern5.setAttribute('height', g5);
    this.gridPattern5.firstChild.setAttribute('width', g5); this.gridPattern5.firstChild.setAttribute('height', g5);
    this.gridPath5.setAttribute('d', 'M' + g5 + ' 0 L0 0 0 ' + g5);
    this.gridRect.style.display = this.grid.show ? '' : 'none';
    if (this.gridKind === 'iso') this._isoGrid();
  };

  // ------------------------------------------------- isometric grid
  /* Grid kind: "square" (default) or "iso", a 2:1 isometric lattice with
   * vertices at x = (i - j)·g, y = (i + j)·g/2 (g = grid size); every fifth
   * line is darker, like the square grid. Same patterns, other paths. */
  Renderer.prototype.setGridKind = function (kind) {
    this.gridKind = kind === 'iso' ? 'iso' : 'square';
    this.setGrid(this.grid.show, this.grid.size);
  };
  Renderer.prototype._isoGrid = function () {
    var g = this.grid.size, w = 2 * g, w5 = 10 * g, h5 = 5 * g;
    this.gridPattern.setAttribute('width', w); this.gridPattern.setAttribute('height', g);
    this.gridPath.setAttribute('d', 'M0 0L' + w + ' ' + g + 'M0 ' + g + 'L' + w + ' 0');
    this.gridPattern5.setAttribute('width', w5); this.gridPattern5.setAttribute('height', h5);
    this.gridPattern5.firstChild.setAttribute('width', w5); this.gridPattern5.firstChild.setAttribute('height', h5);
    this.gridPath5.setAttribute('d', 'M0 0L' + w5 + ' ' + h5 + 'M0 ' + h5 + 'L' + w5 + ' 0');
  };

  /* Full render of a page (page switch, undo of a structural change). */
  Renderer.prototype.setPage = function (page) {
    this.page = page;
    DS.clear(this.content);
    this.els.clear(); this.conns.clear(); this.routes.clear(); this.layers.clear();
    this.index = new G.Index(160);
    this.byId = new Map();
    var self = this;
    page.elements.forEach(function (e) { self.byId.set(e.id, e); });
    this.pageRect.setAttribute('width', page.width); this.pageRect.setAttribute('height', page.height);
    this.pageRect.style.fill = page.background ? page.background : '';
    this.gridRect.setAttribute('width', page.width); this.gridRect.setAttribute('height', page.height);
    page.layers.forEach(function (l) { self._layer(l); });
    var frag = new Map();
    page.layers.forEach(function (l) { frag.set(l.id, { e: document.createDocumentFragment(), c: document.createDocumentFragment() }); });
    page.elements.forEach(function (e) {
      var g = self._drawEl(e);
      var f = frag.get(e.layer) || frag.get(page.layers[0].id);
      f.e.appendChild(g);
    });
    page.connectors.forEach(function (c) {
      var g = self._drawConn(c);
      var f = frag.get(c.layer) || frag.get(page.layers[0].id);
      f.c.appendChild(g);
    });
    frag.forEach(function (f, lid) { var L = self.layers.get(lid); L.els.appendChild(f.e); L.conns.appendChild(f.c); });
    this.applyLayerState();
    this.emit('render');
  };

  Renderer.prototype._layer = function (l) {
    var g = s('g', { class: 'ds-layer', 'data-layer': l.id }, this.content);
    var L = { g: g, els: s('g', { class: 'ds-layer-els' }, g), conns: s('g', { class: 'ds-layer-conns' }, g) };
    this.layers.set(l.id, L);
    return L;
  };
  Renderer.prototype.applyLayerState = function () {
    var self = this;
    if (!this.page) return;
    // keep the DOM layer order = page.layers order (first = bottom)
    this.page.layers.forEach(function (l) {
      var L = self.layers.get(l.id) || self._layer(l);
      self.content.appendChild(L.g);
      L.g.style.display = l.visible ? '' : 'none';
      L.g.classList.toggle('ds-locked', !!l.locked);
    });
    this.layers.forEach(function (L, id) {
      if (!self.page.layers.some(function (l) { return l.id === id; })) { L.g.remove(); self.layers.delete(id); }
    });
  };
  Renderer.prototype.isVisible = function (layerId) {
    var l = this.page && this.page.layers.filter(function (x) { return x.id === layerId; })[0];
    return !l || l.visible;
  };

  Renderer.prototype._drawEl = function (e, g) {
    var st = e.style;
    if (!g) {
      g = s('g', { class: 'ds-el', 'data-id': e.id });
      this.els.set(e.id, g);
    } else DS.clear(g);
    g.setAttribute('class', 'ds-el ds-' + e.shape + (e.kind === 'container' ? ' ds-container' : '') + (this.opts.decorate ? ' ' + (this.opts.decorate(e) || '') : ''));
    var tf = 'translate(' + n(e.x) + ' ' + n(e.y) + ')';
    if (e.rotation) tf += ' rotate(' + n(e.rotation) + ' ' + n(e.w / 2) + ' ' + n(e.h / 2) + ')';
    g.setAttribute('transform', tf);
    if (e.name || e.description) s('title', { text: e.name || e.description.slice(0, 80) }, g);
    var body = s('g', { 'stroke-width': n(st.stroke_width), 'stroke-linejoin': 'round' }, g);
    var dashes = dashArray(st);
    if (dashes.length) body.setAttribute('stroke-dasharray', dashes.map(n).join(' '));
    if (st.opacity < 1) body.setAttribute('opacity', n(st.opacity));
    if (e.kind === 'image') {
      if (/^data:image\/(png|jpeg|gif|webp);base64,/.test(e.image || '')) s('image', { x: 0, y: 0, width: n(e.w), height: n(e.h), preserveAspectRatio: 'none', href: e.image }, body);
      else s('rect', { x: 0, y: 0, width: n(e.w), height: n(e.h), fill: '#F1F5F9', stroke: '#64748B', 'stroke-dasharray': '4 3' }, body);
    } else {
      var fx = this._effects(st);
      outline(e).forEach(function (p) { prim(p, st, e.w, e.h, body, fx); });
    }
    if (e.symbol && this.opts.symbolUrl) this._icon(e, body);
    textBlocks(e).forEach(function (b) { textEl(b, e, g); });
    // invisible hit area so text-only / unfilled shapes are still grabbable
    s('rect', { class: 'ds-hit', x: 0, y: 0, width: n(Math.max(e.w, 4)), height: n(Math.max(e.h, 4)) }, g);
    this.index.set(e.id, G.bbox(e));
    return g;
  };

  Renderer.prototype._icon = function (e, parent) {
    var ref = DS.model.splitSymbol(e.symbol);
    if (!ref) return;
    var url = this.opts.symbolUrl(ref.lib, ref.sym);
    var ib = iconBox(e);
    if (!ib) return;
    var size = ib.size, x = ib.x, y = ib.y;
    var holder = s('g', { class: 'ds-icon', transform: 'translate(' + n(x) + ' ' + n(y) + ')' }, parent);
    holder.style.color = paint(e.style.stroke, '#1F2937') === 'none' ? '#1F2937' : paint(e.style.stroke, '#1F2937');
    DS.loadIcon(url).then(function (ic) {
      if (!ic || !holder.isConnected && !holder.parentNode) return;
      var k = size / Math.max(ic.vb[2], ic.vb[3]);
      var g = ic.g.cloneNode(true);
      g.setAttribute('transform', 'scale(' + n(k) + ') translate(' + n(-ic.vb[0]) + ' ' + n(-ic.vb[1]) + ')');
      g.setAttribute('stroke-dasharray', 'none');
      holder.appendChild(g);
    });
  };

  /* Paints of one element style: {fill, filled: attrs, line: attrs} (gradient,
   * shadow filter, fill/stroke opacity), the SVG exporter's _effects(). */
  Renderer.prototype._effects = function (st) {
    var fx = { fill: '', filled: {}, line: {} };
    var g = gradientOf(st);
    if (g) fx.fill = this._gradient(st.fill, g);
    if (st.fill_opacity !== undefined && st.fill_opacity < 1) fx.filled['fill-opacity'] = n(st.fill_opacity);
    if (st.stroke_opacity !== undefined && st.stroke_opacity < 1) fx.filled['stroke-opacity'] = fx.line['stroke-opacity'] = n(st.stroke_opacity);
    if (st.shadow && st.fill !== 'none') fx.filled.filter = this._shadow(st.shadow_color);
    return fx;
  };
  Renderer.prototype._gradient = function (fill, g) {
    var angle = g.type === 'linear' ? ((Math.round(g.angle) % 360) + 360) % 360 : 0;
    var key = 'g|' + g.type + '|' + fill.toUpperCase() + '|' + g.color.toUpperCase() + '|' + angle;
    var id = this.markers.get(key);
    if (!id) {
      id = this._uid('grad');
      this.markers.set(key, id);
      var gr;
      if (g.type === 'radial') gr = s('radialGradient', { id: id, cx: 0.5, cy: 0.5, r: 0.5, fx: 0.5, fy: 0.5 }, this.defs);
      else { var v = gradVector(angle); gr = s('linearGradient', { id: id, x1: v[0], y1: v[1], x2: v[2], y2: v[3] }, this.defs); }
      s('stop', { offset: 0, 'stop-color': fill.toUpperCase() }, gr);
      s('stop', { offset: 1, 'stop-color': g.color.toUpperCase() }, gr);
    }
    return 'url(#' + id + ')';
  };
  Renderer.prototype._shadowFilter = function (id, colour, region, parent) {
    var f = s('filter', Object.assign({ id: id, 'color-interpolation-filters': 'sRGB' }, region), parent);
    s('feDropShadow', { dx: SHADOW.dx, dy: SHADOW.dy, stdDeviation: SHADOW.blur, 'flood-color': colour, 'flood-opacity': SHADOW.alpha }, f);
    return f;
  };
  Renderer.prototype._shadow = function (colour) {
    colour = DS.model.COLOR_RE.test(colour || '') ? colour.toUpperCase() : '#000000';
    var key = 's|' + colour, id = this.markers.get(key);
    if (!id) {
      id = this._uid('shadow');
      this.markers.set(key, id);
      this._shadowFilter(id, colour, { x: -0.5, y: -0.5, width: 2, height: 2 }, this.defs);
    }
    return 'url(#' + id + ')';
  };

  // ----------------------------------------------------------- connectors

  Renderer.prototype._marker = function (kind, colour, start) {
    if (!kind || kind === 'none' || !R.ARROW_GLYPHS[kind]) return '';
    var key = kind + (start ? '-s-' : '-e-') + colour.replace('#', '');
    var id = this.markers.get(key);
    if (id) return 'url(#' + id + ')';
    id = this._uid('mk-' + key);
    this.markers.set(key, id);
    var stroke = colour === 'none' ? '#1F2937' : colour;
    var m = s('marker', { id: id, viewBox: start ? '-2 -8 18 16' : '-16 -8 18 16', markerWidth: 18, markerHeight: 16, refX: 0, refY: 0,
      markerUnits: 'userSpaceOnUse', orient: 'auto', overflow: 'visible' }, this.defs);
    var holder = start ? s('g', { transform: 'scale(-1,1)' }, m) : m;
    R.ARROW_GLYPHS[kind].forEach(function (g) {
      var fill = g.fill === 'stroke' ? stroke : g.fill === 'white' ? '#FFFFFF' : 'none';
      var a = { fill: fill, stroke: stroke, 'stroke-width': 1.2, 'stroke-linejoin': 'miter' };
      if (g.t === 'poly') { a.points = g.pts.map(function (p) { return p.join(','); }).join(' '); s('polygon', a, holder); }
      else if (g.t === 'line') { a.points = g.pts.map(function (p) { return p.join(','); }).join(' '); s('polyline', a, holder); }
      else { a.cx = g.c[0]; a.cy = g.c[1]; a.r = g.r; s('circle', a, holder); }
    });
    return 'url(#' + id + ')';
  };

  Renderer.prototype.obstacles = function () {
    var self = this;
    return function (win, srcId, tgtId) {
      var skip = new Set([srcId, tgtId]);
      // ancestors of both ends are containers the line must cross
      [srcId, tgtId].forEach(function (id) {
        var cur = self.byId.get(id), guard = 0;
        while (cur && cur.parent && guard++ < 16) { skip.add(cur.parent); cur = self.byId.get(cur.parent); }
      });
      return self.index.query(win).filter(function (id) {
        if (skip.has(id)) return false;
        var e = self.byId.get(id);
        if (!e || e.kind === 'container' || e.shape === 'zone' || e.shape === 'swimlane' || e.kind === 'text') return false;
        return self.isVisible(e.layer);
      }).map(function (id) { return self.index.boxes.get(id).box; });
    };
  };

  Renderer.prototype.route = function (c) {
    var r = R.route(c, this.byId, { obstacles: this.opts.avoid === false ? null : this.obstacles() });
    this.routes.set(c.id, r);
    return r;
  };

  Renderer.prototype._drawConn = function (c, g) {
    var st = c.style;
    if (!g) { g = s('g', { class: 'ds-conn', 'data-id': c.id }); this.conns.set(c.id, g); }
    else DS.clear(g);
    g.setAttribute('class', 'ds-conn' + (this.opts.decorateConn ? ' ' + (this.opts.decorateConn(c) || '') : ''));
    var r = this.route(c);
    var stroke = paint(st.stroke, '#1F2937');
    s('path', { class: 'ds-conn-hit', d: r.d }, g);
    var p = s('path', { class: 'ds-conn-line', d: r.d, fill: 'none', stroke: stroke, 'stroke-width': n(st.stroke_width) }, g);
    var dashes = dashArray(st);
    if (dashes.length) p.setAttribute('stroke-dasharray', dashes.map(n).join(' '));
    if (st.opacity < 1) p.setAttribute('opacity', n(st.opacity));
    if (st.stroke_opacity !== undefined && st.stroke_opacity < 1) p.setAttribute('stroke-opacity', n(st.stroke_opacity));
    if (st.shadow && r.flat && r.flat.length) {
      // a straight line has a zero-height box: the filter region is the line's own box, in
      // user space, and the filter lives in the connector's group (re-made with it)
      var xs = r.flat.map(function (q) { return q[0]; }), ys = r.flat.map(function (q) { return q[1]; });
      var m = 20 + (Number(st.stroke_width) || 0), x0 = Math.floor(Math.min.apply(null, xs) - m), y0 = Math.floor(Math.min.apply(null, ys) - m);
      var fid = this._uid('cshadow');
      this._shadowFilter(fid, DS.model.COLOR_RE.test(st.shadow_color || '') ? st.shadow_color : '#000000',
        { filterUnits: 'userSpaceOnUse', x: x0, y: y0, width: Math.ceil(Math.max.apply(null, xs) - x0 + m), height: Math.ceil(Math.max.apply(null, ys) - y0 + m) }, g);
      p.setAttribute('filter', 'url(#' + fid + ')');
    }
    var ms = this._marker(c.start_arrow, stroke, true), me = this._marker(c.end_arrow, stroke, false);
    if (ms) p.setAttribute('marker-start', ms);
    if (me) p.setAttribute('marker-end', me);
    var texts = [];
    if (c.label) texts.push({ text: c.label, pos: 0.5, idx: -1 });
    (c.labels || []).forEach(function (lb, i) { texts.push({ text: lb.text, pos: lb.pos, idx: i }); });
    texts.forEach(function (t) {
      var xy = R.pointAlong(r.flat, t.pos);
      s('text', { class: 'ds-conn-label', x: n(xy[0]), y: n(xy[1] - 4), 'font-family': DEFAULT_FONT, 'font-size': 11, 'text-anchor': 'middle',
        fill: paint(st.font_color, '#111827'), stroke: '#FFFFFF', 'stroke-width': 3, 'paint-order': 'stroke', 'data-label': t.idx, text: t.text }, g);
    });
    return g;
  };

  /* Re-draw these elements (and the connectors attached to them). */
  Renderer.prototype.updateEls = function (ids, opts) {
    var self = this, page = this.page;
    if (!page) return;
    var touched = new Set();
    ids.forEach(function (id) {
      var e = self.byId.get(id);
      if (!e) {
        e = page.elements.filter(function (x) { return x.id === id; })[0];
        if (e) self.byId.set(id, e);
      }
      var g = self.els.get(id);
      if (!e) { if (g) { g.remove(); self.els.delete(id); self.index.remove(id); self.byId.delete(id); } return; }
      var L = self.layers.get(e.layer) || self.layers.get(page.layers[0].id);
      if (!g) { g = self._drawEl(e); L.els.appendChild(g); }
      else { self._drawEl(e, g); if (g.parentNode !== L.els) L.els.appendChild(g); }
      touched.add(id);
    });
    if (opts && opts.noConns) return;
    var cids = page.connectors.filter(function (c) { return touched.has(c.source) || touched.has(c.target); }).map(function (c) { return c.id; });
    this.updateConns(cids);
  };
  Renderer.prototype.updateConns = function (ids) {
    var self = this, page = this.page;
    if (!page || !ids.length) return;
    var want = new Set(ids);
    var found = new Map();
    page.connectors.forEach(function (c) { if (want.has(c.id)) found.set(c.id, c); });
    ids.forEach(function (id) {
      var c = found.get(id), g = self.conns.get(id);
      if (!c) { if (g) { g.remove(); self.conns.delete(id); self.routes.delete(id); } return; }
      var L = self.layers.get(c.layer) || self.layers.get(page.layers[0].id);
      if (!g) { g = self._drawConn(c); L.conns.appendChild(g); }
      else { self._drawConn(c, g); if (g.parentNode !== L.conns) L.conns.appendChild(g); }
    });
  };
  /* DOM order = array order (z-order), after reorder commands. */
  Renderer.prototype.syncOrder = function () {
    var self = this;
    this.page.elements.forEach(function (e) {
      var g = self.els.get(e.id), L = self.layers.get(e.layer);
      if (g && L) L.els.appendChild(g);
    });
    this.page.connectors.forEach(function (c) {
      var g = self.conns.get(c.id), L = self.layers.get(c.layer);
      if (g && L) L.conns.appendChild(g);
    });
  };
  /* Re-route every connector (e.g. after obstacles moved). */
  Renderer.prototype.rerouteAll = function () { this.updateConns(this.page.connectors.map(function (c) { return c.id; })); };

  // ------------------------------------------------------------ viewport

  Renderer.prototype.on = function (fn) { this.listeners.push(fn); };
  Renderer.prototype.emit = function (what) { var self = this; this.listeners.forEach(function (fn) { fn(what, self); }); };
  /* The box of the canvas (its container: the <svg> itself may carry a
   * temporary CSS transform during a gesture). */
  Renderer.prototype.size = function () {
    var host = this.stage && this.stage.parentNode && this.stage.parentNode.nodeType === 1 ? this.stage.parentNode : this.svg;
    var r = host.getBoundingClientRect();
    return { w: r.width || 800, h: r.height || 600, left: r.left, top: r.top };
  };
  Renderer.prototype.setView = function (k, x, y) {
    if (this.live) this._endLive(false);
    this.view.k = Math.max(0.05, Math.min(8, k));
    this.view.x = x; this.view.y = y;
    this.vp.setAttribute('transform', 'translate(' + n(this.view.x) + ' ' + n(this.view.y) + ') scale(' + this.view.k + ')');
    this.emit('view');
  };
  /* Pan/zoom during a gesture: the SVG already painted is moved by the
   * compositor (CSS transform on the <svg>), so 1 000+ elements are not
   * re-painted every frame; the real transform is committed when the
   * gesture pauses (140 ms). */
  Renderer.prototype.setViewLive = function (k, x, y) {
    k = Math.max(0.05, Math.min(8, k));
    if (!this.live) {
      this.live = { k0: this.view.k, x0: this.view.x, y0: this.view.y };
      this.stage.style.transformOrigin = '0 0';
      this.stage.style.willChange = 'transform';
      this.stage.classList.add('ds-live');
    }
    this.view.k = k; this.view.x = x; this.view.y = y;
    var sc = k / this.live.k0;
    this.stage.style.transform = 'translate(' + (x - this.live.x0 * sc) + 'px,' + (y - this.live.y0 * sc) + 'px) scale(' + sc + ')';
    this.emit('liveview');
    var self = this;
    clearTimeout(this.liveTimer);
    this.liveTimer = setTimeout(function () { self._endLive(true); }, 140);
  };
  Renderer.prototype._endLive = function (emit) {
    clearTimeout(this.liveTimer);
    if (!this.live) return;
    this.live = null;
    this.stage.style.transform = '';
    this.stage.style.willChange = '';
    this.stage.classList.remove('ds-live');
    this.vp.setAttribute('transform', 'translate(' + n(this.view.x) + ' ' + n(this.view.y) + ') scale(' + this.view.k + ')');
    if (emit) this.emit('view');
  };
  Renderer.prototype.toWorld = function (clientX, clientY) {
    var r = this.size();
    return [(clientX - r.left - this.view.x) / this.view.k, (clientY - r.top - this.view.y) / this.view.k];
  };
  Renderer.prototype.toScreen = function (x, y) {
    var r = this.size();
    return [r.left + this.view.x + x * this.view.k, r.top + this.view.y + y * this.view.k];
  };
  Renderer.prototype.zoomAt = function (factor, clientX, clientY, live) {
    var r = this.size();
    var cx = clientX === undefined ? r.left + r.w / 2 : clientX, cy = clientY === undefined ? r.top + r.h / 2 : clientY;
    var w = this.toWorld(cx, cy);
    var k = Math.max(0.05, Math.min(8, this.view.k * factor));
    (live ? this.setViewLive : this.setView).call(this, k, cx - r.left - w[0] * k, cy - r.top - w[1] * k);
  };
  Renderer.prototype.contentBox = function () {
    var self = this;
    var boxes = [];
    if (this.page) {
      this.page.elements.forEach(function (e) { if (self.isVisible(e.layer)) boxes.push(G.bbox(e)); });
      this.routes.forEach(function (r) { r.pts.forEach(function (p) { boxes.push({ x: p[0], y: p[1], w: 0, h: 0 }); }); });
    }
    return G.union(boxes) || { x: 0, y: 0, w: this.page ? this.page.width : 800, h: this.page ? this.page.height : 600 };
  };
  Renderer.prototype.fit = function (box) {
    var b = box || this.contentBox();
    var r = this.size(), pad = 40;
    var k = Math.min((r.w - pad * 2) / Math.max(b.w, 1), (r.h - pad * 2) / Math.max(b.h, 1), 2);
    k = Math.max(0.05, k);
    this.setView(k, (r.w - b.w * k) / 2 - b.x * k, (r.h - b.h * k) / 2 - b.y * k);
  };
  Renderer.prototype.centerOn = function (box, keepZoom) {
    var r = this.size(), k = keepZoom ? this.view.k : Math.max(this.view.k, 1);
    this.setView(k, r.w / 2 - (box.x + box.w / 2) * k, r.h / 2 - (box.y + box.h / 2) * k);
  };

  // --------------------------------------------------------------- minimap

  /* A canvas minimap: element boxes + the visible window; click/drag pans. */
  DS.Minimap = function (canvas, renderer) {
    this.c = canvas; this.r = renderer;
    var self = this;
    var redraw = DS.debounce(function () { self.draw(); }, 60);
    var queued = false;
    renderer.on(function (what) {
      if (what !== 'view' && what !== 'liveview') { redraw(); return; }
      if (queued) return;
      queued = true;
      requestAnimationFrame(function () { queued = false; self.draw(true); });
    });
    this.accent = getComputedStyle(document.documentElement).getPropertyValue('--fw-accent').trim() || '#0A3F9F';
    var drag = false;
    function go(ev) {
      var t = self.t; if (!t) return;
      var rect = canvas.getBoundingClientRect();
      var wx = (ev.clientX - rect.left - t.ox) / t.k, wy = (ev.clientY - rect.top - t.oy) / t.k;
      var sz = renderer.size();
      renderer.setViewLive(renderer.view.k, sz.w / 2 - wx * renderer.view.k, sz.h / 2 - wy * renderer.view.k);
    }
    canvas.addEventListener('pointerdown', function (ev) { drag = true; canvas.setPointerCapture(ev.pointerId); go(ev); });
    canvas.addEventListener('pointermove', function (ev) { if (drag) go(ev); });
    canvas.addEventListener('pointerup', function () { drag = false; });
  };
  /* viewOnly: the view moved; reuse the cached element layer. */
  DS.Minimap.prototype.draw = function (viewOnly) {
    var c = this.c, r = this.r;
    if (!r.page || !c.isConnected) return;
    var dpr = window.devicePixelRatio || 1;
    if (!viewOnly || !this.W) { this.W = c.clientWidth || 180; this.H = c.clientHeight || 120; }
    var W = this.W, H = this.H;
    if (c.width !== W * dpr) { c.width = W * dpr; c.height = H * dpr; }
    var ctx = c.getContext('2d');
    // The element layer is drawn once into an offscreen canvas and copied
    // with drawImage on every view move: no pixel read-back from the canvas.
    if (!viewOnly || !this.layer || this.layer.width !== c.width || this.layer.height !== c.height) {
      var lay = this.layer || (this.layer = document.createElement('canvas'));
      lay.width = c.width; lay.height = c.height;
      var lc = lay.getContext('2d');
      lc.setTransform(dpr, 0, 0, dpr, 0, 0);
      lc.clearRect(0, 0, W, H);
      var b = G.union([r.contentBox(), { x: 0, y: 0, w: r.page.width, h: r.page.height }]);
      var k0 = Math.min((W - 8) / b.w, (H - 8) / b.h);
      var ox0 = (W - b.w * k0) / 2 - b.x * k0, oy0 = (H - b.h * k0) / 2 - b.y * k0;
      this.t = { k: k0, ox: ox0, oy: oy0 };
      lc.fillStyle = '#FFFFFF';
      lc.fillRect(ox0, oy0, r.page.width * k0, r.page.height * k0);
      lc.fillStyle = '#94A3B8';
      r.page.elements.forEach(function (e) {
        if (!r.isVisible(e.layer)) return;
        var bb = r.index.boxes.get(e.id); bb = bb ? bb.box : e;
        lc.fillRect(ox0 + bb.x * k0, oy0 + bb.y * k0, Math.max(1, bb.w * k0), Math.max(1, bb.h * k0));
      });
    }
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, c.width, c.height);
    ctx.drawImage(this.layer, 0, 0);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    var k = this.t.k, ox = this.t.ox, oy = this.t.oy;
    var sz = this.r._size || r.size();
    var vx = -r.view.x / r.view.k, vy = -r.view.y / r.view.k;
    ctx.strokeStyle = this.accent;
    ctx.lineWidth = 1.5;
    ctx.strokeRect(ox + vx * k, oy + vy * k, sz.w / r.view.k * k, sz.h / r.view.k * k);
  };

  // ------------------------------------------------------------- list view

  /* The accessible alternative of the canvas: one table of elements, one of
   * connectors. onPick(kind, id) when a row is activated. */
  DS.renderList = function (host, page, onPick, filter) {
    DS.clear(host);
    var names = new Map(page.elements.map(function (e) { return [e.id, e.name || e.text || e.id]; }));
    var layerName = new Map(page.layers.map(function (l) { return [l.id, l.name + (l.visible ? '' : ' (hidden)') + (l.locked ? ' (locked)' : '')]; }));
    var q = (filter || '').toLowerCase();
    function match(o) { return !q || JSON.stringify([o.name, o.text, o.label, o.category, o.properties]).toLowerCase().indexOf(q) >= 0; }
    function table(caption, heads, rows) {
      var t = DS.h('table', { class: 'fw-table ds-list-table' });
      t.appendChild(DS.h('caption', { text: caption }));
      t.appendChild(DS.h('thead', null, DS.h('tr', null, heads.map(function (x) { return DS.h('th', { scope: 'col', text: x }); }))));
      var tb = DS.h('tbody');
      rows.forEach(function (r) { tb.appendChild(r); });
      t.appendChild(tb);
      return DS.h('div', { class: 'fw-table-wrapper mb-3' }, t);
    }
    function row(kind, id, cells) {
      var tr = DS.h('tr', { tabindex: '0', 'data-kind': kind, 'data-id': id }, cells.map(function (c) { return DS.h('td', { text: c === undefined || c === null ? '' : String(c) }); }));
      tr.addEventListener('click', function () { onPick && onPick(kind, id); });
      tr.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); onPick && onPick(kind, id); } });
      return tr;
    }
    var els = page.elements.filter(match);
    var cons = page.connectors.filter(match);
    host.appendChild(table('Elements (' + els.length + ')', ['Name / text', 'Shape', 'Category', 'Layer', 'Position', 'Size', 'Confidence'],
      els.map(function (e) {
        return row('el', e.id, [e.name || e.text || e.id, e.shape + (e.kind !== 'shape' ? ' (' + e.kind + ')' : ''), e.category || 'unclassified',
          layerName.get(e.layer), Math.round(e.x) + ', ' + Math.round(e.y), Math.round(e.w) + ' × ' + Math.round(e.h),
          Math.round((e.confidence === undefined ? 1 : e.confidence) * 100) + ' %' + (e.confidence < DS.model.LOW_CONFIDENCE ? ' (low)' : '')]);
      })));
    host.appendChild(table('Connectors (' + cons.length + ')', ['Label', 'From', 'To', 'Routing', 'Arrows', 'Layer'],
      cons.map(function (c) {
        return row('conn', c.id, [c.label || (c.labels || []).map(function (l) { return l.text; }).join(' / ') || '—',
          c.source ? names.get(c.source) : 'free end (dangling)', c.target ? names.get(c.target) : 'free end (dangling)', c.routing,
          c.start_arrow + ' → ' + c.end_arrow, layerName.get(c.layer)]);
      })));
  };

  // ------------------------------------------------- read-only navigation

  /* Wheel zoom, drag pan (compositor-only while moving) and click picking
   * for the canvases that do not edit: the viewer and the review page.
   * opts.onPick({kind: 'el'|'conn'|'bg', id}, ev). */
  DS.attachNav = function (r, opts) {
    opts = opts || {};
    var svg = r.svg, drag = null;
    svg.addEventListener('wheel', function (ev) {
      ev.preventDefault();
      if (ev.shiftKey && !ev.ctrlKey) { r.setViewLive(r.view.k, r.view.x - ev.deltaY, r.view.y); return; }
      r.zoomAt(Math.exp(-ev.deltaY * (ev.deltaMode === 1 ? 0.05 : 0.0015)), ev.clientX, ev.clientY, true);
    }, { passive: false });
    svg.addEventListener('pointerdown', function (ev) {
      if (r.live) r._endLive(true);
      drag = { sx: ev.clientX, sy: ev.clientY, vx: r.view.x, vy: r.view.y, moved: false, target: ev.target };
      svg.setPointerCapture(ev.pointerId);
    });
    svg.addEventListener('pointermove', function (ev) {
      if (!drag) return;
      var dx = ev.clientX - drag.sx, dy = ev.clientY - drag.sy;
      if (!drag.moved && Math.hypot(dx, dy) < 4) return;
      drag.moved = true;
      svg.classList.add('ds-panning');
      r.setViewLive(r.view.k, drag.vx + dx, drag.vy + dy);
    });
    svg.addEventListener('pointerup', function (ev) {
      var d = drag; drag = null;
      svg.classList.remove('ds-panning');
      if (!d || d.moved || !opts.onPick) return;
      var t = d.target;
      var c = t.closest && t.closest('.ds-conn'), e = t.closest && t.closest('.ds-el');
      opts.onPick(c ? { kind: 'conn', id: c.getAttribute('data-id') } : e ? { kind: 'el', id: e.getAttribute('data-id') } : { kind: 'bg' }, ev);
    });
    svg.addEventListener('keydown', function (ev) {
      var step = ev.shiftKey ? 200 : 40;
      var mv = { ArrowLeft: [step, 0], ArrowRight: [-step, 0], ArrowUp: [0, step], ArrowDown: [0, -step] }[ev.key];
      if (mv) { ev.preventDefault(); r.setViewLive(r.view.k, r.view.x + mv[0], r.view.y + mv[1]); }
      else if (ev.key === '+' || ev.key === '=') r.zoomAt(1.2);
      else if (ev.key === '-') r.zoomAt(1 / 1.2);
      else if (ev.key === '0') r.fit();
      else if (ev.key === '1') { var sz = r.size(), w = r.toWorld(sz.left + sz.w / 2, sz.top + sz.h / 2); r.setView(1, sz.w / 2 - w[0], sz.h / 2 - w[1]); }
    });
  };
})();
