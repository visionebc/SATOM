/* svg_export.js — "Export to SVG" for every diagram in the console.
 *
 * Each diagram script hands SatomSvg.wire(button, collect) a function that
 * returns {svg, content, name}: the <svg> on the page, the group that holds
 * the drawing (the one the pan/zoom transform sits on) and a file name.
 *
 * The file is a picture of what is on screen — layer, overlay, highlights
 * and all — as a STANDALONE SVG: the page styles most diagrams with CSS
 * classes, and a copied <svg> outside the page has no stylesheet, so every
 * element gets its COMPUTED presentation (fill, stroke, fonts…) written onto
 * it and the classes are dropped. The pan/zoom transform is removed and the
 * view box is cropped to the drawing, so the file shows all of it at 1:1
 * whatever the zoom was. The canvas colour is page CSS too, so the file
 * gets a background in the colour the page shows (light in the console,
 * dark in Observability). Icon-font glyphs are left out (no font in a file).
 *
 * The same file ships twice, byte-identical: app/static/js/ for the console
 * and app/observability_lab/static/js/ for Observability, which serves its
 * own static files (tests/test_svg_export.py holds the two copies together).
 *
 * CSP-safe: external 'self' script, no eval, no inline handlers.
 */
(function () {
  'use strict';

  var NS = 'http://www.w3.org/2000/svg';
  var PAD = 24;

  /* Inherited presentation properties: written only where they differ from
   * the parent's computed value (the clone inherits the rest). */
  var INHERITED = ['fill', 'fill-opacity', 'fill-rule', 'stroke', 'stroke-width',
    'stroke-opacity', 'stroke-dasharray', 'stroke-dashoffset', 'stroke-linecap',
    'stroke-linejoin', 'font-family', 'font-size', 'font-weight', 'font-style',
    'text-anchor', 'letter-spacing', 'visibility', 'marker-start', 'marker-mid',
    'marker-end', 'paint-order', 'dominant-baseline'];
  /* Not inherited: written only where they are not the initial value. */
  var OWN = { opacity: '1', display: 'inline', filter: 'none' };

  /* url("https://host/page#id") -> url(#id): a computed paint server or
   * filter names the page it came from, which the file is not. */
  function localUrl(v) {
    return String(v).replace(/url\(\s*["']?[^"')#]*#([^"')]+)["']?\s*\)/g, 'url(#$1)');
  }

  function inlineStyles(src, dst) {
    var a = [src].concat(Array.prototype.slice.call(src.querySelectorAll('*')));
    var b = [dst].concat(Array.prototype.slice.call(dst.querySelectorAll('*')));
    var parentOf = new Map();
    for (var i = 0; i < a.length && i < b.length; i++) {
      var cs = window.getComputedStyle(a[i]);
      var mine = {};
      var parts = [];
      var pv = parentOf.get(a[i].parentNode) || null;
      INHERITED.forEach(function (p) {
        var v = cs.getPropertyValue(p);
        mine[p] = v;
        if (v !== '' && (!pv || pv[p] !== v)) parts.push(p + ':' + localUrl(v));
      });
      Object.keys(OWN).forEach(function (p) {
        var v = cs.getPropertyValue(p);
        if (v !== '' && v !== OWN[p]) parts.push(p + ':' + localUrl(v));
      });
      parentOf.set(a[i], mine);
      if (i === 0) continue;            // the <svg> itself: sized below
      if (parts.length) b[i].setAttribute('style', parts.join(';'));
      else b[i].removeAttribute('style');
      b[i].removeAttribute('class');
    }
    return parentOf.get(src);
  }

  /* The colour the drawing sits on: the first non-transparent background
   * from the <svg> up (the console canvas is light, Observability's is dark). */
  function canvasColour(svg) {
    for (var n = svg; n && n.nodeType === 1; n = n.parentNode) {
      var c = window.getComputedStyle(n).backgroundColor;
      if (c && c !== 'transparent' && !/rgba\([^)]*,\s*0\s*\)$/.test(c)) return c;
    }
    return '#FFFFFF';
  }

  /* Glyphs of an icon FONT (Bootstrap Icons) need the font, which a file
   * does not carry: they would print as empty boxes, so they are left out.
   * The element's type is written as text next to it in every diagram. */
  function isIconGlyph(el) {
    return el.tagName && el.tagName.toLowerCase() === 'text' &&
      /^\s*["']?bootstrap-icons/i.test(window.getComputedStyle(el).fontFamily || '');
  }

  function safeName(name) {
    return (String(name || 'diagram').replace(/[^A-Za-z0-9._-]+/g, '-')
      .replace(/^[-.]+|[-.]+$/g, '') || 'diagram').slice(0, 80) + '.svg';
  }

  /* The standalone SVG text for {svg, content, exclude?}. ``exclude`` lists
   * elements that are canvas, not drawing (a page-sized background grid):
   * they are left out of the frame and of the file. Throws when nothing is
   * drawn. */
  function serialize(d) {
    var svg = d.svg, content = d.content || d.svg, skip = d.exclude || [];
    if (!svg || !content) throw new Error('the diagram is not on the page');
    var saved = skip.map(function (n) { var v = n.style.display; n.style.display = 'none'; return v; });
    var box;
    try { box = content.getBBox(); } finally {
      skip.forEach(function (n, i) { n.style.display = saved[i]; });
    }
    if (!box || !(box.width > 0) || !(box.height > 0)) throw new Error('there is nothing drawn to export');
    var all = Array.prototype.slice.call(svg.querySelectorAll('*'));
    var at = all.indexOf(content);
    var drop = skip.map(function (n) { return all.indexOf(n); });
    all.forEach(function (n, i) { if (isIconGlyph(n)) drop.push(i); });
    var clone = svg.cloneNode(true);
    var rootStyle = inlineStyles(svg, clone);
    var cAll = clone.querySelectorAll('*');
    var target = at < 0 ? clone : cAll[at];
    drop.forEach(function (i) { if (i >= 0 && cAll[i].parentNode) cAll[i].parentNode.removeChild(cAll[i]); });
    target.removeAttribute('transform');
    var x = box.x - PAD, y = box.y - PAD, w = box.width + PAD * 2, h = box.height + PAD * 2;
    clone.removeAttribute('class');
    clone.removeAttribute('style');
    clone.removeAttribute('id');
    clone.setAttribute('xmlns', NS);
    clone.setAttribute('width', Math.ceil(w));
    clone.setAttribute('height', Math.ceil(h));
    clone.setAttribute('viewBox', x + ' ' + y + ' ' + w + ' ' + h);
    // the <svg>'s own inherited look carried onto it: its children only write
    // what differs from it, so all of it must be on the root of the file
    var top = [];
    INHERITED.forEach(function (p) {
      if (rootStyle && rootStyle[p]) top.push(p + ':' + localUrl(rootStyle[p]));
    });
    if (top.length) clone.setAttribute('style', top.join(';'));
    var bg = document.createElementNS(NS, 'rect');
    bg.setAttribute('x', x); bg.setAttribute('y', y);
    bg.setAttribute('width', w); bg.setAttribute('height', h);
    bg.setAttribute('fill', canvasColour(svg)); bg.setAttribute('stroke', 'none');
    clone.insertBefore(bg, clone.firstChild);
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + new XMLSerializer().serializeToString(clone);
  }

  function download(text, fname) {
    var href = window.URL.createObjectURL(new Blob([text], { type: 'image/svg+xml' }));
    var a = document.createElement('a');
    a.href = href;
    a.download = fname;
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { window.URL.revokeObjectURL(href); a.remove(); }, 1500);
  }

  /* collect() runs at click time and returns {svg, content, name}. */
  function wire(btn, collect) {
    if (!btn || btn.getAttribute('data-svg-wired')) return;
    btn.setAttribute('data-svg-wired', '1');
    btn.addEventListener('click', function () {
      try {
        var d = collect();
        download(serialize(d), safeName(d.name));
      } catch (e) {
        alert('Export to SVG failed: ' + e.message);
      }
    });
  }

  window.SatomSvg = { serialize: serialize, wire: wire };
})();
