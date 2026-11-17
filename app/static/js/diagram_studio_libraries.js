/* diagram_studio_libraries.js — Symbol libraries page.
 *
 * One collapsible card per library (collapsed by default; the open set is
 * kept in localStorage), each an icon grid; search across all of them;
 * import form for operator libraries (ZIP) and delete for operator ones.
 */
(function () {
  'use strict';
  var DS = window.DS, h = DS.h;
  var root = document.getElementById('dsLibs');
  if (!root || root.dataset.dsBooted) return;
  root.dataset.dsBooted = '1';
  var cfg = DS.config(), api = DS.Api(cfg);
  var listEl = document.getElementById('dlList'), q = document.getElementById('dlQ');
  var libs = [];
  var KEY = 'satom.ds.libs.open';
  var open = {};
  try { open = JSON.parse(localStorage.getItem(KEY) || '{}') || {}; } catch (e) { open = {}; }

  function load() {
    DS.http('GET', api.libraries()).then(function (res) {
      if (!res.ok) { DS.clear(listEl).appendChild(h('div', { class: 'fw-alert-danger p-2', role: 'alert', text: DS.errorText(res, 'Loading the libraries failed') })); return; }
      libs = Array.isArray(res.data) ? res.data : [];
      render();
      fillFamilies();
    }, function (e) { DS.clear(listEl).appendChild(h('div', { class: 'fw-alert-danger p-2', role: 'alert', text: e.message })); });
  }
  function render() {
    var v = q.value.trim().toLowerCase();
    DS.clear(listEl);
    if (!libs.length) { listEl.appendChild(h('div', { class: 'ds-empty' }, [DS.icon('boxes'), h('div', { text: 'No libraries.' })])); return; }
    libs.slice().sort(function (a, b) { return (b.builtin ? 1 : 0) - (a.builtin ? 1 : 0) || a.label.localeCompare(b.label); }).forEach(function (lib) {
      var syms = (lib.symbols || []).filter(function (s) { return !v || (s.label + ' ' + s.id + ' ' + s.category + ' ' + (s.keywords || []).join(' ')).toLowerCase().indexOf(v) >= 0; });
      if (v && !syms.length) return;
      var fams = {};
      (lib.symbols || []).forEach(function (s) { var f = (s.category || '').split('.')[0]; fams[f] = (fams[f] || 0) + 1; });
      var d = h('details', { class: 'fw-card ds-lib-card mb-2', open: v || open[lib.id] ? 'open' : null });
      d.addEventListener('toggle', function () { if (v) return; if (d.open) open[lib.id] = 1; else delete open[lib.id]; try { localStorage.setItem(KEY, JSON.stringify(open)); } catch (e) { /* private mode */ } });
      var del = null;
      if (!lib.builtin && cfg.mayLibraries) {
        del = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', 'aria-label': 'Delete library ' + lib.label }, [DS.icon('trash'), ' Delete']);
        del.addEventListener('click', function (ev) { ev.preventDefault(); remove(lib); });
      }
      d.appendChild(h('summary', null, [DS.icon('chevron-right'), h('h2', { text: lib.label }),
        lib.builtin ? DS.badge('secondary', 'Built-in', 'lock') : DS.badge('info', 'Operator', 'person'),
        h('span', { class: 'small ds-muted', text: (lib.symbols || []).length + ' symbols · ' + Object.keys(fams).length + ' families' + (lib.version ? ' · v' + lib.version : '') }), del]));
      var grid = h('div', { class: 'ds-icon-grid' });
      syms.forEach(function (s) {
        grid.appendChild(h('div', { class: 'ds-icon-cell', title: (s.keywords || []).join(', ') }, [
          h('img', { src: api.symbolSvg(lib.id, s.id), alt: '', loading: 'lazy', width: 36, height: 36 }), h('span', { text: s.label }), h('small', { text: s.category })
        ]));
      });
      var body = h('div', { class: 'ds-lib-body' }, [lib.license ? h('p', { class: 'small ds-muted', text: 'Licence: ' + lib.license }) : null, grid]);
      d.appendChild(body);
      listEl.appendChild(d);
    });
    if (!listEl.children.length) listEl.appendChild(h('div', { class: 'ds-empty' }, [DS.icon('search'), h('div', { text: 'No symbol matches "' + q.value + '".' })]));
  }
  function remove(lib) {
    DS.confirm('Delete library', 'Delete "' + lib.label + '" (' + (lib.symbols || []).length + ' symbols)? Diagrams that use its symbols keep their shapes and categories but lose the icons.', 'Delete', true).then(function (ok) {
      if (!ok) return;
      DS.http('DELETE', api.library(lib.id)).then(function (res) {
        if (!res.ok) { DS.toast(DS.errorText(res, 'Deleting failed'), 'danger'); return; }
        DS.toast('Library deleted.', 'success'); load();
      });
    });
  }
  function fillFamilies() {
    var sel = document.getElementById('dlFamily');
    if (!sel) return;
    DS.http('GET', api.categories()).then(function (res) {
      if (!res.ok || !res.data) return;
      var cur = sel.value;
      DS.clear(sel);
      (res.data.families || []).forEach(function (f) { sel.appendChild(h('option', { value: f.id, text: f.label, selected: f.id === cur })); });
      if (!sel.value) sel.appendChild(h('option', { value: 'generic', text: 'Generic', selected: true }));
    });
  }
  q.addEventListener('input', DS.debounce(render, 150));

  var form = document.getElementById('dlForm');
  if (form) form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var err = document.getElementById('dlErr');
    err.hidden = true;
    var file = document.getElementById('dlFile'), id = document.getElementById('dlId'), label = document.getElementById('dlLabel');
    var bad = [];
    [file, id, label].forEach(function (x) { var ok = x.checkValidity(); x.classList.toggle('is-invalid', !ok); if (!ok) bad.push(x); });
    if (file.files[0] && file.files[0].size > 20 * 1048576) { file.classList.add('is-invalid'); bad.push(file); }
    if (bad.length) { err.hidden = false; err.textContent = 'Check the highlighted fields: a ZIP file (max 20 MiB), an id in lower-case letters, digits, - or _, and a label.'; bad[0].focus(); return; }
    var fd = new FormData(form);
    var btn = document.getElementById('dlSubmit');
    btn.disabled = true;
    DS.http('POST', api.libraries(), fd).then(function (res) {
      btn.disabled = false;
      if (!res.ok) { err.hidden = false; err.textContent = DS.errorText(res, 'Import failed'); return; }
      var w = (res.data && res.data.warnings) || [];
      DS.toast('Imported "' + (res.data.label || label.value) + '" with ' + (res.data.symbols || 0) + ' symbol(s)' + (w.length ? '; ' + w.length + ' file(s) skipped' : '') + '.', w.length ? 'warning' : 'success', 7000);
      form.reset();
      open[res.data.id || id.value] = 1;
      load();
    }, function (e) { btn.disabled = false; err.hidden = false; err.textContent = e.message; });
  });
  load();
})();
