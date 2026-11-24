/* diagram_studio_style.js — colours & effects in the editor.
 *
 *  - the inspector's ONE "Style" section (built here, for elements,
 *    connectors and multi-selections): fill / line / text palette rows
 *    (theme swatches + recent colours + a custom picker), gradient (none /
 *    linear + angle / radial), line width, line pattern (solid / dashed /
 *    dotted / dash-dot -- the old "Dashed" flag follows it), fill, line and
 *    whole-item opacity, shadow, rounded corners, font, Copy / Paste /
 *    Reset style and the theme picker;
 *  - the theme picker: a non-modal panel over the canvas; hovering or
 *    focusing a theme previews it on the canvas (nothing is recorded),
 *    Apply makes it ONE undoable command for the selection, the page or
 *    the whole diagram; operators' own themes are saved in this browser
 *    and exported / imported as JSON files;
 *  - Ctrl+Alt+C / Ctrl+Alt+V copy and paste a style.
 *
 * The pure parts (resolution, apply, validation, clipboard) are in
 * diagram_studio_themes.js. Everything edits through ed.cmd / the
 * inspector setters, so read-only mode disables it all.
 */
(function () {
  'use strict';
  var DS = window.DS;
  if (!DS || !DS.themes) return;
  var h = DS.h, T = DS.themes, M = DS.model;
  var HEX = /^#[0-9A-Fa-f]{6}$/;
  var RECENT_KEY = 'satom.ds.recentColours';
  var DASH_LABELS = [['solid', 'Solid'], ['dashed', 'Dashed'], ['dotted', 'Dotted'], ['dash-dot', 'Dash-dot']];
  var FONTS = ['', 'Helvetica, Arial, sans-serif', 'Inter', 'Georgia, serif', 'Courier New, monospace'];

  DS.StyleUI = function (ed, hooks) {
    var store = ed.store, r = ed.r, cfg = ed.cfg;
    var userId = cfg.user && cfg.user.id;
    var shipped = (Array.isArray(cfg.themes) ? cfg.themes : []).filter(function (t) { return !T.validate(t).length; });
    var custom = T.loadCustom(userId);
    var themeKey = 'satom.ds.theme.d' + (ed.diagram && ed.diagram.id);

    function allThemes() { return shipped.concat(custom); }
    function themeById(id) { return allThemes().filter(function (t) { return t.id === id; })[0] || null; }
    function activeTheme() {
      var id = null;
      try { id = window.localStorage.getItem(themeKey); } catch (e) { /* private mode */ }
      return themeById(id) || shipped[0] || null;
    }
    function rememberTheme(id) { try { window.localStorage.setItem(themeKey, id); } catch (e) { /* private mode */ } }

    // ----------------------------------------------------------- recent colours
    function recent() {
      try { return (JSON.parse(window.localStorage.getItem(RECENT_KEY) || '[]') || []).filter(function (c) { return HEX.test(c); }).slice(0, 8); } catch (e) { return []; }
    }
    function addRecent(c) {
      if (!HEX.test(c || '')) return;
      var list = [c.toUpperCase()].concat(recent().filter(function (x) { return x.toUpperCase() !== c.toUpperCase(); })).slice(0, 8);
      try { window.localStorage.setItem(RECENT_KEY, JSON.stringify(list)); } catch (e) { /* private mode */ }
    }

    // ---------------------------------------------------------------- locking
    function lockedOn(o, page) {
      var l = page.layers.filter(function (x) { return x.id === o.layer; })[0] || page.layers[0];
      return !!(l && (l.locked || !l.visible));
    }
    function selection() { return { els: Array.from(ed.sel.els), conns: Array.from(ed.sel.conns) }; }

    // ------------------------------------------------------- style clipboard
    var clip = null;
    function copyStyle() {
      var e = ed.selectedEls()[0], c = ed.selectedConns()[0];
      if (!e && !c) { DS.toast('Select an element or a connector to copy its style.', 'info', 2500); return; }
      clip = e ? T.copyStyle(e, false) : T.copyStyle(c, true);
      DS.toast('Style copied. Select other items and press Ctrl+Alt+V to paste it.', 'info', 2500);
      if (ui.block) rebuild();
    }
    function pasteStyle() {
      if (!clip) { DS.toast('Copy a style first (Ctrl+Alt+C).', 'info', 2500); return; }
      var els = ed.editableEls(), cs = ed.selectedConns().filter(function (c) { return !ed.isLocked(c); });
      if (!els.length && !cs.length) { DS.toast('Select the items to paste the style on.', 'info', 2500); return; }
      ed.cmd('Paste style', function (tx) {
        els.forEach(function (e) { T.pasteStyle(tx.touch('el', e.id), clip, false); });
        cs.forEach(function (c) { T.pasteStyle(tx.touch('conn', c.id), clip, true); });
      });
      rebuild();
    }
    function resetStyle() {
      var els = ed.editableEls(), cs = ed.selectedConns().filter(function (c) { return !ed.isLocked(c); });
      if (!els.length && !cs.length) return;
      ed.cmd('Reset style', function (tx) {
        els.forEach(function (e) { T.resetStyle(tx.touch('el', e.id), false); });
        cs.forEach(function (c) { T.resetStyle(tx.touch('conn', c.id), true); });
      });
      rebuild();
    }
    ed.copyStyle = copyStyle; ed.pasteStyle = pasteStyle; ed.resetStyle = resetStyle;

    // Ctrl+Alt+C / Ctrl+Alt+V: captured before the editor's Ctrl+C / Ctrl+V.
    function inField(t) { return t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable); }
    DS.on(document, 'keydown', function (ev) {
      if (!(ev.ctrlKey || ev.metaKey) || !ev.altKey || ev.shiftKey) return;
      if (ev.code !== 'KeyC' && ev.code !== 'KeyV') return;
      var root = document.getElementById('dsEditor');
      if (!root || !document.body.contains(root) || inField(ev.target) || document.querySelector('.modal.show')) return;
      ev.preventDefault();
      ev.stopPropagation();
      if (ev.code === 'KeyC') copyStyle();
      else if (ed.canEdit) pasteStyle();
    }, { capture: true });

    // ---------------------------------------------------------- the block
    var ui = { block: null, args: null };

    function swatch(colour, label, onPick, current, key) {
      var b = h('button', { type: 'button', class: 'ds-swatch', title: label + ' ' + colour, 'aria-label': label + ' ' + colour,
        'aria-pressed': current && current.toUpperCase() === colour.toUpperCase() ? 'true' : 'false', 'data-colour': colour,
        'data-key': key + ':' + colour.toUpperCase() });
      b.style.backgroundColor = colour;
      b.disabled = !ed.canEdit;
      b.addEventListener('click', function () { onPick(colour); });
      return b;
    }
    /* One palette row: theme swatches, recent colours, a custom picker (+ None). */
    function paletteRow(label, key, current, themeColours, onPick, allowNone) {
      var row = h('div', { class: 'ds-palette', role: 'group', 'aria-label': label + ' colour' });
      var seen = {};
      themeColours.forEach(function (c) {
        if (!HEX.test(c) || seen[c]) return;
        seen[c] = 1;
        row.appendChild(swatch(c, label + ': theme colour', onPick, current, key));
      });
      var rec = recent().filter(function (c) { return !seen[c]; });
      if (rec.length) {
        row.appendChild(h('span', { class: 'ds-palette-sep', 'aria-hidden': 'true' }));
        rec.forEach(function (c) { row.appendChild(swatch(c, label + ': recent colour', onPick, current, key)); });
      }
      var pick = h('input', { type: 'color', class: 'ds-palette-custom', value: HEX.test(current || '') ? current : '#FFFFFF',
        title: label + ': custom colour', 'aria-label': label + ': custom colour', 'data-key': key + '-custom' });
      pick.disabled = !ed.canEdit;
      pick.addEventListener('change', function () { onPick(pick.value.toUpperCase()); });
      row.appendChild(pick);
      if (allowNone) {
        var none = h('button', { type: 'button', class: 'ds-swatch ds-swatch-none', title: label + ': none', 'aria-label': label + ': none',
          'aria-pressed': current === 'none' ? 'true' : 'false', 'data-key': key + ':none' });
        none.disabled = !ed.canEdit;
        none.addEventListener('click', function () { onPick('none'); });
        row.appendChild(none);
      }
      return h('div', { class: 'ds-field ds-field-wide' }, [h('span', { class: 'ds-label', text: label }), row]);
    }

    function themeColours(part) {
      var t = activeTheme();
      if (!t) return [];
      var out = T.FAMILIES.map(function (f) { return t.families[f][part]; });
      if (part === 'font') out = out.concat(['#111827', '#FFFFFF']);
      return out;
    }

    function rangeField(label, value, key, onSet) {
      var inp = h('input', { type: 'range', class: 'form-range', min: 0, max: 1, step: 0.05, value: String(value), 'data-key': key,
        'aria-valuetext': Math.round(value * 100) + ' %' });
      var out = h('output', { class: 'ds-range-out', text: Math.round(value * 100) + ' %' });
      inp.disabled = !ed.canEdit;
      inp.addEventListener('input', function () { out.textContent = Math.round(Number(inp.value) * 100) + ' %'; });
      inp.addEventListener('change', function () { onSet(Number(inp.value)); });
      var id = 'dsS' + Math.random().toString(36).slice(2, 8);
      inp.id = id;
      return h('div', { class: 'ds-field' }, [h('label', { for: id, text: label }), h('div', { class: 'ds-range' }, [inp, out])]);
    }
    function selectField(label, options, value, key, onSet) {
      var s = h('select', { class: 'form-select form-select-sm', 'data-key': key }, options.map(function (o) { return h('option', { value: o[0], text: o[1], selected: o[0] === value }); }));
      var id = 'dsS' + Math.random().toString(36).slice(2, 8);
      s.id = id; s.disabled = !ed.canEdit;
      s.addEventListener('change', function () { onSet(s.value); });
      return h('div', { class: 'ds-field' }, [h('label', { for: id, text: label }), s]);
    }

    function numberField(label, value, key, opts, onSet) {
      var inp = h('input', { type: 'number', class: 'form-control form-control-sm', min: opts.min, max: opts.max, step: opts.step, value: String(Math.round(value * 100) / 100), 'data-key': key });
      var id = 'dsS' + Math.random().toString(36).slice(2, 8);
      inp.id = id; inp.disabled = !ed.canEdit;
      inp.addEventListener('change', function () { var v = Number(inp.value); if (isFinite(v)) onSet(Math.max(opts.min, Math.min(opts.max, v))); });
      return h('div', { class: 'ds-field' }, [h('label', { for: id, text: label }), inp]);
    }
    function checks(items) {
      return h('div', { class: 'ds-field ds-field-wide ds-checks' }, items.map(function (it) {
        var box = h('input', { type: 'checkbox', class: 'form-check-input', checked: !!it.value, 'data-key': it.key });
        box.disabled = !ed.canEdit;
        box.addEventListener('change', function () { it.set(box.checked); });
        return h('label', { class: 'form-check form-check-inline ds-check-inline' }, [box, ' ', it.label]);
      }));
    }
    function sub(text) { return h('div', { class: 'ds-style-sub ds-field-wide', role: 'heading', 'aria-level': '3', text: text }); }

    /* args: {els: [..], conns: [..]} the inspected items (the first one shows the values).
     * ONE "Style" section: fill, gradient, line, width, pattern, opacities,
     * shadow, text -- the old Dashed box is the Line pattern select. */
    function buildBlock(args) {
      var setEls = hooks.setEls, setConns = hooks.setConns;
      var e0 = args.els[0], c0 = args.conns[0];
      var kids = [];
      // after(): the edit changes other controls (palette state, gradient fields,
      // shadow colour) -> rebuild in place; plain(): a value field that already
      // shows its value -> commit only, so Tab / a click on the next control
      // is never swallowed by a rebuild.
      function after(fn) { return function (v) { fn(v); rebuild(); }; }
      function plain(fn) { return function (v) { fn(v); }; }
      if (e0 && c0) kids.push(sub('Elements'));
      if (e0) {
        var st = e0.style;
        if (args.els.some(function (x) { return T.ownColours(x); })) {
          kids.push(h('p', { class: 'ds-style-note ds-field-wide', role: 'note', text: 'Full-colour and 3D symbols keep their own colours: themes leave them alone, and Fill and Line only draw a box around the icon.' }));
        }
        kids.push(paletteRow('Fill', 'fill', st.fill, themeColours('fill').concat(themeColours('fill2')), after(function (v) { addRecent(v); setEls('Fill', 'fill', function (o) { o.style.fill = v; }); }), true));
        var g = st.gradient || { type: 'none', color: '#FFFFFF', angle: 90 };
        kids.push(selectField('Gradient', [['none', 'None'], ['linear', 'Linear'], ['radial', 'Radial']], g.type, 'gtype', after(function (v) {
          setEls('Gradient', 'gtype', function (o) {
            var cur = o.style.gradient || {};
            var col = HEX.test(cur.color || '') && cur.color.toUpperCase() !== String(o.style.fill).toUpperCase() ? cur.color : (o.style.fill === '#FFFFFF' || !HEX.test(o.style.fill) ? '#BFDBFE' : '#FFFFFF');
            o.style.gradient = { type: v, color: col, angle: cur.angle === undefined ? 90 : cur.angle };
          });
        })));
        if (g.type !== 'none') {
          var gc = h('input', { type: 'color', class: 'form-control form-control-sm form-control-color', value: HEX.test(g.color) ? g.color : '#FFFFFF', 'data-key': 'gcolour' });
          gc.disabled = !ed.canEdit;
          gc.addEventListener('change', plain(function () { var v = gc.value.toUpperCase(); addRecent(v); setEls('Gradient colour', 'gcol', function (o) { o.style.gradient = Object.assign({}, o.style.gradient, { color: v }); }); }));
          var gid = 'dsS' + Math.random().toString(36).slice(2, 8); gc.id = gid;
          kids.push(h('div', { class: 'ds-field' }, [h('label', { for: gid, text: 'To colour' }), gc]));
          if (g.type === 'linear') {
            var ang = h('input', { type: 'number', class: 'form-control form-control-sm', min: 0, max: 359, step: 15, value: String(g.angle), 'data-key': 'gangle',
              title: '0 = left to right, 90 = top to bottom' });
            var aid = 'dsS' + Math.random().toString(36).slice(2, 8); ang.id = aid; ang.disabled = !ed.canEdit;
            ang.addEventListener('change', plain(function () {
              var v = Number(ang.value); if (!isFinite(v)) return;
              v = ((Math.round(v) % 360) + 360) % 360;
              setEls('Gradient angle', 'gang', function (o) { o.style.gradient = Object.assign({}, o.style.gradient, { angle: v }); });
            }));
            kids.push(h('div', { class: 'ds-field' }, [h('label', { for: aid, text: 'Angle °' }), ang]));
          }
        }
        kids.push(rangeField('Fill opacity', st.fill_opacity === undefined ? 1 : st.fill_opacity, 'fop', plain(function (v) { setEls('Fill opacity', 'fop', function (o) { o.style.fill_opacity = v; }); })));
        kids.push(paletteRow('Line', 'stroke', st.stroke, themeColours('stroke'), after(function (v) { addRecent(v); setEls('Stroke', 'stroke', function (o) { o.style.stroke = v; }); }), true));
        kids.push(numberField('Line width', st.stroke_width, 'sw', { min: 0, max: 50, step: 0.5 }, plain(function (v) { setEls('Stroke width', 'sw', function (o) { o.style.stroke_width = v; }); })));
        kids.push(selectField('Line pattern', DASH_LABELS, M.dashPattern(st), 'dash', plain(function (v) { setEls('Line pattern', 'dashp', function (o) { o.style.dash_pattern = v; o.style.dashed = v !== 'solid'; }); })));
        kids.push(rangeField('Line opacity', st.stroke_opacity === undefined ? 1 : st.stroke_opacity, 'sop', plain(function (v) { setEls('Line opacity', 'sop', function (o) { o.style.stroke_opacity = v; }); })));
        kids.push(rangeField('Opacity (whole element)', st.opacity === undefined ? 1 : st.opacity, 'op', plain(function (v) { setEls('Opacity', 'op', function (o) { o.style.opacity = v; }); })));
        kids.push(shadowField(st, function (fn) { setEls('Shadow', 'shadow', fn); }));
        kids.push(checks([{ label: 'Rounded corners', key: 'rnd', value: st.rounded, set: plain(function (v) { setEls('Rounded', 'rnd', function (o) { o.style.rounded = !!v; }); }) }]));
        kids.push(paletteRow('Text', 'font', st.font_color, themeColours('font'), after(function (v) { addRecent(v); setEls('Font colour', 'fc', function (o) { o.style.font_color = v; }); }), false));
        kids.push(numberField('Font size', st.font_size, 'fs', { min: 4, max: 200, step: 1 }, plain(function (v) { setEls('Font size', 'fs', function (o) { o.style.font_size = v; }); })));
        kids.push(selectField('Font', FONTS.map(function (f) { return [f, f || 'Default']; }).concat(FONTS.indexOf(st.font_family) < 0 ? [[st.font_family, st.font_family]] : []),
          st.font_family, 'ff', plain(function (v) { setEls('Font', 'ff', function (o) { o.style.font_family = v; }); })));
        kids.push(checks([
          { label: 'Bold', key: 'b', value: st.bold, set: plain(function (v) { setEls('Bold', 'b', function (o) { o.style.bold = !!v; }); }) },
          { label: 'Italic', key: 'i', value: st.italic, set: plain(function (v) { setEls('Italic', 'i', function (o) { o.style.italic = !!v; }); }) }]));
        kids.push(selectField('Align', [['left', 'Left'], ['center', 'Centre'], ['right', 'Right']], st.align, 'al', plain(function (v) { setEls('Align text', 'al', function (o) { o.style.align = v; }); })));
        kids.push(selectField('Vertical', [['top', 'Top'], ['middle', 'Middle'], ['bottom', 'Bottom']], st.valign, 'va', plain(function (v) { setEls('Align text', 'va', function (o) { o.style.valign = v; }); })));
      }
      if (e0 && c0) kids.push(sub('Connectors'));
      if (c0) {
        var cst = c0.style, cp = e0 ? 'Connector ' : '';   // label prefix in a mixed selection
        kids.push(paletteRow(e0 ? 'Connector line' : 'Line', 'cstroke', cst.stroke, connectorColours(), after(function (v) { addRecent(v); setConns('Line colour', 'stroke', function (o) { o.style.stroke = v; }); }), false));
        kids.push(numberField(e0 ? 'Connector width' : 'Line width', cst.stroke_width, 'csw', { min: 0, max: 50, step: 0.5 }, plain(function (v) { setConns('Stroke width', 'sw', function (o) { o.style.stroke_width = v; }); })));
        kids.push(selectField(e0 ? 'Connector pattern' : 'Line pattern', DASH_LABELS, M.dashPattern(cst), 'cdash', plain(function (v) { setConns('Line pattern', 'dashp', function (o) { o.style.dash_pattern = v; o.style.dashed = v !== 'solid'; }); })));
        kids.push(rangeField(e0 ? 'Connector line opacity' : 'Line opacity', cst.stroke_opacity === undefined ? 1 : cst.stroke_opacity, 'csop', plain(function (v) { setConns('Line opacity', 'sop', function (o) { o.style.stroke_opacity = v; }); })));
        kids.push(rangeField(e0 ? 'Connector opacity (whole)' : 'Opacity (whole connector)', cst.opacity === undefined ? 1 : cst.opacity, 'cop', plain(function (v) { setConns('Opacity', 'op', function (o) { o.style.opacity = v; }); })));
        kids.push(shadowField(cst, function (fn) { setConns('Shadow', 'shadow', fn); }, 'c', cp));
        kids.push(paletteRow(e0 ? 'Connector text' : 'Text', 'cfont', cst.font_color, themeColours('font'), after(function (v) { addRecent(v); setConns('Font colour', 'fc', function (o) { o.style.font_color = v; }); }), false));
      }
      var copyB = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', title: 'Copy style (Ctrl+Alt+C)', 'data-key': 'copy' }, [DS.icon('clipboard'), ' Copy style']);
      var pasteB = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', title: 'Paste style (Ctrl+Alt+V)', 'data-key': 'paste' }, [DS.icon('clipboard-check'), ' Paste style']);
      var resetB = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', title: 'Back to the default style', 'data-key': 'reset' }, [DS.icon('eraser'), ' Reset style']);
      var themeB = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', title: 'Colour by meaning with a theme', 'data-key': 'theme' }, [DS.icon('palette'), ' Theme…']);
      copyB.addEventListener('click', copyStyle);
      pasteB.addEventListener('click', function () { pasteStyle(); });
      resetB.addEventListener('click', function () { resetStyle(); });
      themeB.addEventListener('click', function () { openPicker(themeB); });
      pasteB.disabled = !ed.canEdit || !clip; resetB.disabled = !ed.canEdit;
      kids.push(h('div', { class: 'ds-field ds-field-wide ds-btnrow' }, [copyB, pasteB, resetB, themeB]));
      var d = h('details', { class: 'ds-insp-group ds-style-block', open: 'open', 'data-ds-block': 'style' });
      d.appendChild(h('summary', { text: 'Style' }));
      d.appendChild(h('div', { class: 'ds-insp-grid' }, kids));
      return d;
    }
    function connectorColours() {
      var t = activeTheme();
      if (!t) return [];
      var out = [], seen = {};
      Object.keys(t.connectors).forEach(function (k) { var c = t.connectors[k].stroke; if (!seen[c]) { seen[c] = 1; out.push(c); } });
      return out.slice(0, 10);
    }
    function shadowField(st, set, prefix, labelPrefix) {
      prefix = prefix || '';
      labelPrefix = labelPrefix || '';
      var box = h('input', { type: 'checkbox', class: 'form-check-input', checked: !!st.shadow, 'data-key': prefix + 'shadow' });
      var col = h('input', { type: 'color', class: 'form-control form-control-sm form-control-color', value: HEX.test(st.shadow_color || '') ? st.shadow_color : '#000000',
        title: 'Shadow colour', 'aria-label': labelPrefix + 'Shadow colour', 'data-key': prefix + 'shadowc' });
      box.disabled = col.disabled = !ed.canEdit;
      col.disabled = col.disabled || !st.shadow;
      box.addEventListener('change', function () { set(function (o) { o.style.shadow = box.checked; }); rebuild(); });
      col.addEventListener('change', function () { var v = col.value.toUpperCase(); set(function (o) { o.style.shadow_color = v; }); });
      return h('div', { class: 'ds-field ds-field-wide', role: 'group', 'aria-label': labelPrefix + 'Shadow' }, [h('span', { class: 'ds-label', text: labelPrefix ? labelPrefix + 'shadow' : 'Shadow' }),
        h('div', { class: 'ds-colour' }, [h('label', { class: 'form-check form-check-inline ds-check-inline' }, [box, ' Drop shadow']), col])]);
    }

    /* The block for the inspector (panels.js appends it). */
    ui.block = null;
    ui.blockFor = function (els, conns) {
      ui.args = { els: els, conns: conns };
      ui.block = buildBlock(ui.args);
      return ui.block;
    };
    /* Rebuild in place after an edit, keeping the focus on the same control. */
    function rebuild() {
      if (!ui.block || !ui.block.isConnected || !ui.args) return;
      var key = document.activeElement && ui.block.contains(document.activeElement) ? document.activeElement.getAttribute('data-key') : null;
      var fresh = function (o, kind) { return kind === 'el' ? store.el(o.id) : store.conn(o.id); };
      ui.args = { els: ui.args.els.map(function (e) { return fresh(e, 'el'); }).filter(Boolean), conns: ui.args.conns.map(function (c) { return fresh(c, 'conn'); }).filter(Boolean) };
      if (!ui.args.els.length && !ui.args.conns.length) return;
      var next = buildBlock(ui.args);
      next.open = ui.block.open;
      ui.block.replaceWith(next);
      ui.block = next;
      if (key) { var f = next.querySelector('[data-key="' + key + '"]'); if (f) f.focus({ preventScroll: true }); }
    }

    // ------------------------------------------------------------ the picker
    var panel = null, preview = null, chosen = null;

    function restorePreview() {
      if (!preview) return;
      var p = preview; preview = null;
      Object.keys(p.els).forEach(function (id) { var e = store.el(id); if (e) e.style = p.els[id]; });
      Object.keys(p.conns).forEach(function (id) { var c = store.conn(id); if (c) c.style = p.conns[id]; });
      r.updateEls(Object.keys(p.els));
      r.updateConns(Object.keys(p.conns));
    }
    function showPreview(t, scope) {
      restorePreview();
      if (!t) return;
      var ps = T.previewStyles(store, t, scope === 'diagram' ? 'page' : scope, selection(), lockedOn);
      var saved = { els: {}, conns: {} };
      Object.keys(ps.els).forEach(function (id) { var e = store.el(id); if (e) { saved.els[id] = e.style; e.style = ps.els[id]; } });
      Object.keys(ps.conns).forEach(function (id) { var c = store.conn(id); if (c) { saved.conns[id] = c.style; c.style = ps.conns[id]; } });
      preview = saved;
      r.updateEls(Object.keys(ps.els));
      r.updateConns(Object.keys(ps.conns));
    }
    // A save or an export never sees a previewed style.
    ['save', 'docForSave'].forEach(function (k) {
      var orig = ed[k];
      if (typeof orig === 'function') ed[k] = function () { restorePreview(); return orig.apply(this, arguments); };
    });
    store.onChange(function () { if (preview) preview = null; });   // a real edit wins; the next hover re-previews

    function card(t) {
      var strip = h('span', { class: 'ds-theme-strip', 'aria-hidden': 'true' });
      ['network', 'infra', 'security', 'flow', 'software', 'generic'].forEach(function (f) {
        var sw = h('span', { class: 'ds-theme-chip' });
        sw.style.background = t.gradient ? 'linear-gradient(180deg,' + t.families[f].fill + ',' + t.families[f].fill2 + ')' : t.families[f].fill;
        sw.style.borderColor = t.families[f].stroke;
        strip.appendChild(sw);
      });
      var tags = [];
      if (t.gradient) tags.push('gradient');
      if (t.shadow) tags.push('shadow');
      if (t.id.indexOf('custom-') === 0) tags.push('yours');
      var b = h('button', { type: 'button', class: 'ds-theme-card', 'data-theme': t.id, 'aria-pressed': chosen === t.id ? 'true' : 'false',
        title: t.description || t.name }, [strip, h('span', { class: 'ds-theme-name', text: t.name }),
        h('span', { class: 'ds-theme-tags', text: tags.join(' · ') })]);
      return b;
    }

    function openPicker(anchor) {
      if (panel) { closePicker(); return; }
      var wrap = document.getElementById('dsCanvasWrap');
      if (!wrap) return;
      var nSel = ed.sel.els.size + ed.sel.conns.size;
      var scope = nSel ? 'selection' : 'page';
      chosen = (activeTheme() || {}).id || null;
      panel = h('div', { class: 'ds-theme-panel fw-card', id: 'dsThemePanel', role: 'dialog', 'aria-label': 'Colour themes' });
      var head = h('div', { class: 'ds-theme-head' }, [DS.icon('palette'), h('h2', { text: 'Colour themes' })]);
      var close = h('button', { type: 'button', class: 'btn-close ms-auto', 'aria-label': 'Close themes' });
      close.addEventListener('click', closePicker);
      head.appendChild(close);
      panel.appendChild(head);
      panel.appendChild(h('p', { class: 'ds-theme-hint', text: 'Colours each item by its category family (network, security, flow…), then by its shape. Point at a theme to preview it.' }));
      var scopes = h('div', { class: 'ds-theme-scope', role: 'radiogroup', 'aria-label': 'Apply to' });
      [['selection', 'Selection' + (nSel ? ' (' + nSel + ')' : '')], ['page', 'This page'], ['diagram', 'Whole diagram']].forEach(function (s) {
        var id = 'dsTs' + s[0];
        var rb = h('input', { type: 'radio', class: 'form-check-input', name: 'dsThemeScope', id: id, value: s[0], checked: s[0] === scope });
        if (s[0] === 'selection' && !nSel) rb.disabled = true;
        rb.addEventListener('change', function () { if (rb.checked) { scope = s[0]; if (chosen) showPreview(themeById(chosen), scope); } });
        scopes.appendChild(h('div', { class: 'form-check form-check-inline' }, [rb, h('label', { class: 'form-check-label', for: id, text: s[1] })]));
      });
      panel.appendChild(scopes);
      var grid = h('div', { class: 'ds-theme-grid', role: 'group', 'aria-label': 'Themes' });
      function fillGrid() {
        DS.clear(grid);
        allThemes().forEach(function (t) {
          var b = card(t);
          b.addEventListener('mouseenter', function () { showPreview(t, scope); });
          b.addEventListener('focus', function () { showPreview(t, scope); });
          b.addEventListener('click', function () {
            chosen = t.id;
            DS.$$('.ds-theme-card', grid).forEach(function (x) { x.setAttribute('aria-pressed', x.getAttribute('data-theme') === t.id ? 'true' : 'false'); });
            delBtn.disabled = t.id.indexOf('custom-') !== 0;
          });
          b.addEventListener('dblclick', function () { chosen = t.id; apply(); });
          grid.appendChild(b);
        });
      }
      grid.addEventListener('mouseleave', function () { restorePreview(); });
      panel.appendChild(grid);
      var applyB = h('button', { type: 'button', class: 'btn btn-sm btn-fw-primary' }, [DS.icon('check2'), ' Apply']);
      applyB.disabled = !ed.canEdit;
      applyB.addEventListener('click', apply);
      var cancelB = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', text: 'Cancel' });
      cancelB.addEventListener('click', closePicker);
      panel.appendChild(h('div', { class: 'ds-btnrow ds-theme-actions' }, [applyB, cancelB]));
      // own themes: save from the diagram, import / export JSON, delete
      var saveB = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', title: 'Keep the colours of this diagram as a theme in this browser' }, [DS.icon('bookmark-plus'), ' Save diagram as theme']);
      var impB = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', title: 'Add themes from a .json file' }, [DS.icon('upload'), ' Import']);
      var expB = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', title: 'Download the chosen theme as a .json file' }, [DS.icon('download'), ' Export']);
      var delBtn = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', title: 'Delete the chosen theme (yours only)' }, [DS.icon('trash'), ' Delete']);
      delBtn.disabled = !chosen || chosen.indexOf('custom-') !== 0;
      var file = h('input', { type: 'file', accept: '.json,application/json', hidden: 'hidden', 'aria-label': 'Theme file' });
      saveB.addEventListener('click', function () {
        DS.prompt('Save diagram as theme', 'Theme name', 'My theme', { max: 60, ok: 'Save' }).then(function (name) {
          if (!name) return;
          var t = T.fromDiagram(store.doc, themeById(chosen) || shipped[0], name);
          custom = [t].concat(custom).slice(0, T.MAX_CUSTOM);
          if (!T.saveCustom(userId, custom)) { DS.toast('This browser does not let SATOM keep themes (private mode?).', 'warning'); return; }
          chosen = t.id; fillGrid();
          var warn = T.validate(t, true);
          DS.toast('Theme "' + t.name + '" saved in this browser.' + (warn.length ? ' Note: some text has low contrast (' + warn[0] + ').' : ''), warn.length ? 'warning' : 'success', 6000);
        });
      });
      impB.addEventListener('click', function () { file.click(); });
      file.addEventListener('change', function () {
        var f = file.files && file.files[0];
        file.value = '';
        if (!f) return;
        if (f.size > 512 * 1024) { DS.toast('A theme file is at most 512 KiB.', 'danger'); return; }
        f.text().then(function (txt) {
          var res = T.parseFile(txt, allThemes().map(function (t) { return t.id; }));
          var ok = res.filter(function (x) { return x.theme; }).map(function (x) { return x.theme; });
          var bad = res.filter(function (x) { return x.error; });
          if (ok.length) {
            custom = ok.concat(custom).slice(0, T.MAX_CUSTOM);
            T.saveCustom(userId, custom);
            chosen = ok[0].id; fillGrid();
          }
          DS.toast(ok.length ? 'Imported ' + ok.length + ' theme(s).' + (bad.length ? ' Refused: ' + bad[0].error : '') : 'Nothing imported: ' + (bad[0] ? bad[0].error : 'no theme in the file.'),
            bad.length ? (ok.length ? 'warning' : 'danger') : 'success', 8000);
        });
      });
      expB.addEventListener('click', function () {
        var t = themeById(chosen);
        if (!t) return;
        DS.download(new Blob([T.toFile([t])], { type: 'application/json' }), DS.safeName(t.name, 60, 'theme') + '.theme.json');
      });
      delBtn.addEventListener('click', function () {
        var t = themeById(chosen);
        if (!t || t.id.indexOf('custom-') !== 0) return;
        DS.confirm('Delete theme', 'Delete "' + t.name + '" from this browser? Diagrams keep their colours.', 'Delete', true).then(function (yes) {
          if (!yes) return;
          custom = custom.filter(function (x) { return x.id !== t.id; });
          T.saveCustom(userId, custom);
          chosen = (shipped[0] || {}).id || null; fillGrid(); delBtn.disabled = true;
        });
      });
      panel.appendChild(h('div', { class: 'ds-theme-own' }, [h('span', { class: 'ds-label', text: 'Your themes (kept in this browser)' }),
        h('div', { class: 'ds-btnrow' }, [saveB, impB, expB, delBtn, file])]));
      saveB.disabled = !allThemes().length;
      fillGrid();
      panel.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') { ev.stopPropagation(); closePicker(); } });
      wrap.appendChild(panel);
      var first = grid.querySelector('[aria-pressed="true"]') || grid.querySelector('.ds-theme-card');
      if (first) first.focus({ preventScroll: true });
      panel._anchor = anchor || null;

      function apply() {
        var t = themeById(chosen);
        if (!t || !ed.canEdit) return;
        restorePreview();
        var n = T.apply(store, t, scope, selection(), lockedOn);
        rememberTheme(t.id);
        DS.toast('Applied "' + t.name + '" to ' + n + ' item(s). Ctrl+Z undoes it.', 'success', 3000);
        closePicker();
      }
    }
    function closePicker() {
      restorePreview();
      if (!panel) return;
      var a = panel._anchor;
      panel.remove(); panel = null;
      if (a && a.isConnected) a.focus({ preventScroll: true });
      if (ui.block) rebuild();
    }
    ed.openThemes = openPicker;
    ed.on('escape', closePicker);
    ed.on('page', function () { if (panel) closePicker(); });

    var tb = document.getElementById('dsThemeBtn');
    if (tb) tb.addEventListener('click', function () { openPicker(tb); });
    return ui;
  };
})();
