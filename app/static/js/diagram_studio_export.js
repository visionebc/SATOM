/* diagram_studio_export.js — the "Export to" menu of Diagram Studio and the
 * published viewer: draw.io, SVG and PDF are written by the server
 * (POST /diagram-studio/api/export/<fmt> with the current document, or GET
 * /diagrams/<id>/export/<fmt> for a published diagram); PNG is drawn here
 * from the server's SVG at 1x/2x/4x.
 *
 * The SVG goes into an <img> as a data: URL, not an object URL: the page CSP
 * allows `img-src 'self' data: https:`, and blob: is not in that list.
 */
(function () {
  'use strict';
  var DS = window.DS;
  var FORMATS = {
    drawio: { label: 'draw.io (.drawio)', all: true, ext: 'drawio' },
    svg: { label: 'SVG (.svg)', all: false, ext: 'svg' },
    pdf: { label: 'PDF (.pdf)', all: true, ext: 'pdf' },
    png: { label: 'PNG (.png)', all: false, ext: 'png' }
  };
  var MAX_SIDE = 16384, MAX_AREA = 120e6;

  /* opts: {api, cfg, getDoc() -> doc to export (routes baked), currentPage() -> page id,
   *        pages() -> [{id,name}], name() -> string, published: {id} | null} */
  function Exporter(opts) { this.o = opts; }
  DS.Exporter = Exporter;
  Exporter.FORMATS = FORMATS;

  Exporter.prototype._fetch = function (fmt, page, options) {
    var o = this.o;
    if (o.published) {
      var q = '?page=' + encodeURIComponent(page) + (options.paper ? '&paper=' + encodeURIComponent(options.paper) : '') +
        (options.orientation ? '&orientation=' + encodeURIComponent(options.orientation) : '');
      var base = o.exportUrl || ('/diagrams/' + encodeURIComponent(o.published.id) + '/export/');
      if (base.slice(-1) !== '/') base += '/';
      return DS.http('GET', base + fmt + q, undefined, { raw: true });
    }
    return fetch(o.api.exportUrl(fmt), {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': DS.csrf() },
      body: JSON.stringify({ doc: o.getDoc(), page: page, options: options, diagram_id: (o.cfg && o.cfg.diagram && o.cfg.diagram.id) || undefined })
    }).then(function (r) { return { ok: r.ok, status: r.status, response: r }; },
      function () { throw new Error('The server could not be reached.'); });
  };

  function failText(res) {
    return res.response.json().catch(function () { return {}; }).then(function (j) {
      return DS.errorText({ status: res.status, data: j }, 'Export failed');
    });
  }

  /* The server's SVG of one page, as text. */
  Exporter.prototype.svgText = function (page) {
    return this._fetch('svg', page, {}).then(function (res) {
      if (!res.ok) return failText(res).then(function (m) { throw new Error(m); });
      return res.response.text();
    });
  };

  function svgDataUrl(txt) {
    var bytes = new TextEncoder().encode(txt);
    var bin = '';
    for (var i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return 'data:image/svg+xml;base64,' + btoa(bin);
  }
  DS.svgDataUrl = svgDataUrl;

  function svgSize(txt) {
    var m = /<svg[^>]*\sviewBox="([-\d.\s]+)"/.exec(txt);
    if (m) { var v = m[1].trim().split(/\s+/).map(Number); if (v.length === 4) return { w: v[2], h: v[3] }; }
    return { w: 1600, h: 1000 };
  }

  /* PNG: server SVG -> <img data:> -> canvas at `scale` -> toBlob. */
  Exporter.prototype.png = function (page, scale) {
    return this.svgText(page).then(function (txt) {
      return new Promise(function (resolve, reject) {
        var size = svgSize(txt);
        var k = scale || 1;
        while (k > 1 && (size.w * k > MAX_SIDE || size.h * k > MAX_SIDE || size.w * size.h * k * k > MAX_AREA)) k /= 2;
        var img = new Image();
        img.decoding = 'async';
        img.onload = function () {
          var cv = document.createElement('canvas');
          cv.width = Math.max(1, Math.round(size.w * k)); cv.height = Math.max(1, Math.round(size.h * k));
          var ctx = cv.getContext('2d');
          ctx.fillStyle = '#FFFFFF';
          ctx.fillRect(0, 0, cv.width, cv.height);
          ctx.drawImage(img, 0, 0, cv.width, cv.height);
          cv.toBlob(function (b) { b ? resolve({ blob: b, scale: k }) : reject(new Error('The browser could not encode the PNG.')); }, 'image/png');
        };
        img.onerror = function () { reject(new Error('The browser could not draw the SVG.')); };
        img.src = svgDataUrl(txt);
      });
    });
  };

  Exporter.prototype.run = function (fmt, sel) {
    var self = this, o = this.o;
    sel = sel || {};
    var page = sel.page || o.currentPage();
    var base = DS.safeName(o.name() || 'diagram', 100);
    if (fmt === 'png') {
      return this.png(page, sel.scale || 2).then(function (r) {
        DS.download(r.blob, base + (o.pages().length > 1 ? '-' + self._pageName(page) : '') + '.png');
        if (r.scale !== (sel.scale || 2)) DS.toast('The page is too large for that scale; exported at ' + r.scale + '×.', 'warning');
        return true;
      });
    }
    var options = {};
    if (fmt === 'pdf' && sel.paper) { options.paper = sel.paper; options.orientation = sel.orientation || 'auto'; }
    return this._fetch(fmt, page, options).then(function (res) {
      if (!res.ok) return failText(res).then(function (m) { throw new Error(m); });
      return res.response.blob().then(function (b) {
        DS.download(b, DS.filenameFrom(res.response, base + '.' + FORMATS[fmt].ext));
        return true;
      });
    });
  };
  Exporter.prototype._pageName = function (pid) {
    var p = this.o.pages().filter(function (x) { return x.id === pid; })[0];
    return DS.safeName(p ? p.name : pid, 60, 'page');
  };

  /* The export dialog: format, page, scale (PNG), paper + orientation (PDF), preview. */
  Exporter.prototype.dialog = function (fmt) {
    var self = this, o = this.o;
    var fmtSel = DS.h('select', { class: 'form-select form-select-sm', id: 'dsExpFmt', 'aria-label': 'Format' },
      Object.keys(FORMATS).map(function (k) { return DS.h('option', { value: k, text: FORMATS[k].label, selected: k === fmt }); }));
    var pageSel = DS.h('select', { class: 'form-select form-select-sm', id: 'dsExpPage', 'aria-label': 'Page' });
    var scaleSel = DS.h('select', { class: 'form-select form-select-sm', id: 'dsExpScale', 'aria-label': 'Scale' },
      [1, 2, 4].map(function (k) { return DS.h('option', { value: k, text: k + '×', selected: k === 2 }); }));
    var paperSel = DS.h('select', { class: 'form-select form-select-sm', id: 'dsExpPaper', 'aria-label': 'Paper' },
      [['', 'Page size (no sheet)'], ['A4', 'A4'], ['A3', 'A3'], ['Letter', 'Letter']].map(function (p) { return DS.h('option', { value: p[0], text: p[1], selected: p[0] === 'A4' }); }));
    var orientSel = DS.h('select', { class: 'form-select form-select-sm', id: 'dsExpOrient', 'aria-label': 'Orientation' },
      [['auto', 'Automatic'], ['landscape', 'Landscape'], ['portrait', 'Portrait']].map(function (p) { return DS.h('option', { value: p[0], text: p[1] }); }));
    var preview = DS.h('div', { class: 'ds-export-preview', 'aria-live': 'polite' }, DS.h('span', { class: 'text-muted small', text: 'Preview loading…' }));
    var note = DS.h('div', { class: 'form-text' });
    function field(label, ctl, cls) { return DS.h('div', { class: 'col-6 ' + (cls || '') }, [DS.h('label', { class: 'form-label small mb-1', for: ctl.id, text: label }), ctl]); }
    var rowScale = field('Scale', scaleSel, 'ds-exp-png');
    var rowPaper = field('Paper', paperSel, 'ds-exp-pdf');
    var rowOrient = field('Orientation', orientSel, 'ds-exp-pdf');
    var body = DS.h('div', null, [
      DS.h('div', { class: 'row g-2 mb-2' }, [field('Format', fmtSel), field('Page', pageSel), rowScale, rowPaper, rowOrient]),
      note, preview
    ]);
    function refreshPages() {
      var f = fmtSel.value, cur = pageSel.value || o.currentPage();
      DS.clear(pageSel);
      o.pages().forEach(function (p) { pageSel.appendChild(DS.h('option', { value: p.id, text: p.name + (p.id === o.currentPage() ? ' (current)' : ''), selected: p.id === cur })); });
      if (FORMATS[f].all && o.pages().length > 1) pageSel.appendChild(DS.h('option', { value: 'all', text: 'All pages', selected: cur === 'all' }));
      if (!FORMATS[f].all && pageSel.value === 'all') pageSel.value = o.currentPage();
      rowScale.hidden = f !== 'png';
      rowPaper.hidden = rowOrient.hidden = f !== 'pdf';
      note.textContent = f === 'svg' || f === 'png' ? 'An SVG or PNG file holds one page.' : f === 'drawio' ? 'Opens in draw.io / diagrams.net with every page, layer and property.' : 'Vector PDF, one page per diagram page.';
    }
    var previewSeq = 0;
    function refreshPreview() {
      var pg = pageSel.value === 'all' ? o.currentPage() : pageSel.value;
      var seq = ++previewSeq;
      DS.clear(preview).appendChild(DS.h('span', { class: 'text-muted small', text: 'Preview loading…' }));
      self.svgText(pg).then(function (txt) {
        if (seq !== previewSeq) return;
        var img = DS.h('img', { alt: 'Preview of the exported page', class: 'ds-export-img' });
        img.src = svgDataUrl(txt);
        DS.clear(preview).appendChild(img);
      }).catch(function (e) {
        if (seq !== previewSeq) return;
        DS.clear(preview).appendChild(DS.h('div', { class: 'fw-alert-danger small p-2', role: 'alert', text: 'No preview: ' + e.message }));
      });
    }
    fmtSel.addEventListener('change', function () { refreshPages(); });
    pageSel.addEventListener('change', refreshPreview);
    refreshPages();
    refreshPreview();
    return DS.dialog({ title: 'Export', body: body, size: 'lg', buttons: [
      { label: 'Cancel', value: null },
      { label: 'Export', primary: true, value: function () {
        return { fmt: fmtSel.value, page: pageSel.value, scale: Number(scaleSel.value), paper: paperSel.value, orientation: orientSel.value };
      } }
    ] }).then(function (sel) {
      if (!sel) return null;
      DS.toast('Exporting ' + FORMATS[sel.fmt].label + '…', 'info', 2500);
      return self.run(sel.fmt, sel).then(function () { DS.toast('Exported ' + FORMATS[sel.fmt].label + '.', 'success'); return sel; })
        .catch(function (e) { DS.toast(e.message, 'danger'); return null; });
    });
  };

  /* Wire every [data-ds-export] button in `root` to the dialog. */
  Exporter.prototype.wire = function (root) {
    var self = this;
    DS.$$('[data-ds-export]', root).forEach(function (b) {
      if (b.dataset.dsWired) return;
      b.dataset.dsWired = '1';
      b.addEventListener('click', function () { self.dialog(b.getAttribute('data-ds-export')); });
    });
  };
})();
