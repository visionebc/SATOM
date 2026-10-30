/* Icon picker: every <input data-icon-picker="<url of icons.json>"> gets a
 * preview, a button and a searchable grid of the Bootstrap icons a plugin or
 * app may use (GET /studio/icons.json: the vendored font's names filtered by
 * the package icon pattern). The SATOM Builder ships the same picker over the
 * same font, so what is picked there exists here. Picking writes the name into
 * the input and fires "input" and "change", so page scripts see it; the input
 * stays editable by hand. A page script that sets the value itself calls
 * SatomIconPicker.sync() (or fires "input") to refresh the preview. */
(function () {
  'use strict';
  var MAX_SHOWN = 360;
  var lists = {};          // url -> Promise<names[]>
  var pickers = [];        // each picker's preview refresh
  function icons(url) {
    if (!lists[url]) {
      lists[url] = fetch(url, {credentials: 'same-origin'})
        .then(function (r) { return r.ok ? r.json() : []; })
        .catch(function () { return []; });
    }
    return lists[url];
  }
  function make(tag, cls, attrs) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    return e;
  }

  function enhance(input) {
    if (input.getAttribute('data-icon-picker-ready')) { return; }
    input.setAttribute('data-icon-picker-ready', '1');
    var url = input.getAttribute('data-icon-picker') || '/studio/icons.json';
    var small = input.classList.contains('form-control-sm');
    var wrap = make('div', 'input-group ip-icon-picker' + (small ? ' input-group-sm' : ''));
    var preview = make('span', 'input-group-text', {'aria-hidden': 'true'});
    var glyph = make('i', 'bi ' + (input.value || 'bi-puzzle'));
    preview.appendChild(glyph);
    var btn = make('button', 'btn btn-outline-secondary', {type: 'button', 'aria-expanded': 'false',
                                                         'aria-label': 'Pick an icon', title: 'Pick an icon'});
    btn.innerHTML = '<i class="bi bi-grid-3x3-gap"></i>';
    input.parentNode.insertBefore(wrap, input);
    input.classList.remove('form-control-sm');
    wrap.appendChild(preview);
    wrap.appendChild(input);
    wrap.appendChild(btn);
    var panel = make('div', 'ip-icon-panel', {role: 'dialog', 'aria-label': 'Icons'});
    panel.hidden = true;
    var search = make('input', 'form-control form-control-sm mb-2',
                      {type: 'search', placeholder: 'Search icons (e.g. shield, globe, table)',
                       'aria-label': 'Search icons'});
    var grid = make('div', 'ip-icon-grid', {role: 'listbox', 'aria-label': 'Icons'});
    var note = make('div', 'form-text mt-1');
    panel.appendChild(search);
    panel.appendChild(grid);
    panel.appendChild(note);
    wrap.parentNode.insertBefore(panel, wrap.nextSibling);

    function syncPreview() { glyph.className = 'bi ' + (/^bi-[a-z0-9-]+$/.test(input.value) ? input.value : 'bi-question-square'); }
    function render(all) {
      var q = search.value.trim().toLowerCase().replace(/^bi-/, '');
      var hits = q ? all.filter(function (n) { return n.indexOf(q) !== -1; }) : all;
      grid.innerHTML = '';
      hits.slice(0, MAX_SHOWN).forEach(function (n) {
        var b = make('button', 'ip-icon-cell' + (n === input.value ? ' is-selected' : ''),
                     {type: 'button', role: 'option', title: n, 'aria-label': n, 'data-icon': n,
                      'aria-selected': n === input.value ? 'true' : 'false'});
        b.appendChild(make('i', 'bi ' + n));
        b.addEventListener('click', function () {
          input.value = n;
          input.dispatchEvent(new Event('input', {bubbles: true}));
          input.dispatchEvent(new Event('change', {bubbles: true}));
          syncPreview();
          close();
          input.focus();
        });
        grid.appendChild(b);
      });
      note.textContent = hits.length > MAX_SHOWN
        ? hits.length + ' icons match: the first ' + MAX_SHOWN + ' are shown, type to narrow.'
        : hits.length + ' icon(s).';
    }
    function open() {
      syncPreview();
      panel.hidden = false;
      btn.setAttribute('aria-expanded', 'true');
      icons(url).then(function (all) { render(all); search.focus(); });
    }
    function close() { panel.hidden = true; btn.setAttribute('aria-expanded', 'false'); }
    btn.addEventListener('click', function () { if (panel.hidden) { open(); } else { close(); } });
    search.addEventListener('input', function () { icons(url).then(render); });
    panel.addEventListener('keydown', function (e) { if (e.key === 'Escape') { close(); btn.focus(); } });
    input.addEventListener('input', syncPreview);
    input.addEventListener('change', syncPreview);
    input.addEventListener('focus', syncPreview);
    pickers.push(syncPreview);
    document.addEventListener('click', function (e) {
      if (!panel.hidden && !panel.contains(e.target) && !wrap.contains(e.target)) { close(); }
    });
  }

  function init(root) {
    (root || document).querySelectorAll('input[data-icon-picker]').forEach(enhance);
  }
  window.SatomIconPicker = {init: init, sync: function () { pickers.forEach(function (f) { f(); }); }};
  window.addEventListener('load', function () { pickers.forEach(function (f) { f(); }); });
  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', function () { init(); }); }
  else { init(); }
})();
