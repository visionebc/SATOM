/* diagram_studio_library.js — Diagram Studio library page.
 *
 * Folder tree (create, rename, move by drag & drop, delete when empty) and
 * the diagrams table (search, published filter, folder filter, sort) with
 * open, rename, move, duplicate, delete, publish/unpublish (folder picker
 * for the Diagrams menu) and the versions panel (list, preview, restore,
 * diff A↔B through the diff endpoint).
 */
(function () {
  'use strict';
  var DS = window.DS, h = DS.h;
  var root = document.getElementById('dsLibraryPage');
  if (!root || root.dataset.dsBooted) return;
  root.dataset.dsBooted = '1';
  var cfg = DS.config(), api = DS.Api(cfg);
  var canEdit = !!cfg.mayEdit, canPublish = !!cfg.mayPublish;
  var tree = document.getElementById('dsTree');
  var rowsEl = document.getElementById('dsRows');
  var status = document.getElementById('dsListStatus');
  var q = document.getElementById('dsQ'), pub = document.getElementById('dsPub'), sortSel = document.getElementById('dsSort'), sub = document.getElementById('dsSub');
  var state = { folders: [], diagrams: [], folder: 'all', sort: 'name', open: {} };
  try { state.open = JSON.parse(localStorage.getItem('satom.ds.tree.open') || '{}') || {}; } catch (e) { state.open = {}; }

  function fById(id) { for (var i = 0; i < state.folders.length; i++) if (state.folders[i].id === id) return state.folders[i]; return null; }
  function kids(pid) { return state.folders.filter(function (f) { return (f.parent_id || null) === (pid || null); }).sort(function (a, b) { return (a.position - b.position) || a.name.localeCompare(b.name); }); }
  function path(id) { var out = [], f = fById(id), guard = 0; while (f && guard++ < 10) { out.unshift(f.name); f = fById(f.parent_id); } return out.join(' › '); }
  function descendants(id) { var out = new Set([id]), stack = [id]; while (stack.length) { var c = stack.pop(); kids(c).forEach(function (k) { if (!out.has(k.id)) { out.add(k.id); stack.push(k.id); } }); } return out; }
  function folderOptions(sel, includeNone, noneLabel) {
    var s = h('select', { class: 'form-select form-select-sm' });
    if (includeNone) s.appendChild(h('option', { value: '', text: noneLabel || '(no folder)' }));
    (function walk(pid, depth) { kids(pid).forEach(function (f) { s.appendChild(h('option', { value: String(f.id), text: '  '.repeat(depth) + f.name, selected: f.id === sel })); walk(f.id, depth + 1); }); })(null, 0);
    return s;
  }

  // ------------------------------------------------------------- loading
  function load() {
    status.textContent = 'Loading…';
    return Promise.all([DS.http('GET', api.folders()), DS.http('GET', api.list())]).then(function (rs) {
      if (!rs[0].ok || !rs[1].ok) { status.textContent = ''; showError(DS.errorText(rs[0].ok ? rs[1] : rs[0], 'Loading the library failed')); return; }
      state.folders = Array.isArray(rs[0].data) ? rs[0].data : [];
      state.diagrams = Array.isArray(rs[1].data) ? rs[1].data : (rs[1].data && rs[1].data.diagrams) || [];
      renderTree(); renderRows();
    }, function (e) { showError(e.message); });
  }
  function showError(msg) {
    DS.clear(rowsEl).appendChild(h('tr', null, h('td', { colspan: 8 }, h('div', { class: 'fw-alert-danger small p-2', role: 'alert' }, [DS.icon('x-octagon'), ' ', msg]))));
  }

  // ---------------------------------------------------------------- tree
  function renderTree() {
    DS.clear(tree);
    var total = state.diagrams.length, unfiled = state.diagrams.filter(function (d) { return !d.folder_id; }).length;
    tree.appendChild(node({ id: 'all', name: 'All diagrams', icon: 'collection', count: total, root: true }, 0));
    tree.appendChild(node({ id: 'none', name: 'Unfiled', icon: 'inbox', count: unfiled, root: true }, 0));
    (function walk(pid, parentUl, depth) {
      kids(pid).forEach(function (f) {
        var li = node(f, depth);
        var ch = kids(f.id);
        if (ch.length) {
          var ul = h('ul', { role: 'group', hidden: !state.open[f.id] });
          walk(f.id, ul, depth + 1);
          li.appendChild(ul);
        }
        parentUl.appendChild(li);
      });
    })(null, tree, 0);
  }
  function countIn(f) {
    if (!sub.checked) return f.count !== undefined ? f.count : state.diagrams.filter(function (d) { return d.folder_id === f.id; }).length;
    var ids = descendants(f.id);
    return state.diagrams.filter(function (d) { return ids.has(d.folder_id); }).length;
  }
  function node(f, depth) {
    var isRoot = !!f.root;
    var hasKids = !isRoot && kids(f.id).length > 0;
    var active = String(state.folder) === String(f.id);
    var li = h('li', { role: 'treeitem', 'aria-selected': active ? 'true' : 'false', 'aria-expanded': hasKids ? (state.open[f.id] ? 'true' : 'false') : null, 'aria-level': depth + 1 });
    var toggle = h('button', { type: 'button', class: 'ds-tree-toggle', 'aria-label': (state.open[f.id] ? 'Collapse ' : 'Expand ') + f.name, tabindex: '-1' }, hasKids ? DS.icon(state.open[f.id] ? 'chevron-down' : 'chevron-right') : null);
    if (!hasKids) toggle.style.visibility = 'hidden';
    var row = h('div', { class: 'ds-tree-row' + (active ? ' active' : ''), tabindex: active ? '0' : '-1', 'data-folder': String(f.id), draggable: canEdit && !isRoot ? 'true' : null }, [
      toggle, DS.icon(isRoot ? f.icon : (state.open[f.id] && hasKids ? 'folder2-open' : 'folder2')),
      h('span', { class: 'ds-tree-name', text: f.name }), h('span', { class: 'ds-tree-count', text: String(isRoot ? f.count : countIn(f)), 'aria-label': 'diagrams' })
    ]);
    if (canEdit && !isRoot) {
      var acts = h('span', { class: 'ds-tree-actions' });
      var add = h('button', { type: 'button', class: 'btn btn-sm ds-icon-btn', title: 'New sub-folder', 'aria-label': 'New sub-folder in ' + f.name }, DS.icon('folder-plus'));
      var ren = h('button', { type: 'button', class: 'btn btn-sm ds-icon-btn', title: 'Rename', 'aria-label': 'Rename folder ' + f.name }, DS.icon('pencil'));
      var del = h('button', { type: 'button', class: 'btn btn-sm ds-icon-btn', title: 'Delete (only when empty)', 'aria-label': 'Delete folder ' + f.name }, DS.icon('trash'));
      add.addEventListener('click', function (ev) { ev.stopPropagation(); newFolder(f.id); });
      ren.addEventListener('click', function (ev) { ev.stopPropagation(); renameFolder(f); });
      del.addEventListener('click', function (ev) { ev.stopPropagation(); deleteFolder(f); });
      [add, ren, del].forEach(function (b) { acts.appendChild(b); });
      row.appendChild(acts);
    }
    toggle.addEventListener('click', function (ev) { ev.stopPropagation(); state.open[f.id] = !state.open[f.id]; saveOpen(); renderTree(); });
    row.addEventListener('click', function () { state.folder = f.id; renderTree(); renderRows(); var r2 = tree.querySelector('.ds-tree-row.active'); if (r2) r2.focus(); });
    row.addEventListener('keydown', function (ev) { treeKey(ev, f, hasKids); });
    // drag & drop: folders onto folders, diagram rows onto folders
    if (canEdit) {
      row.addEventListener('dragstart', function (ev) { ev.dataTransfer.setData('application/x-ds-folder', String(f.id)); ev.dataTransfer.effectAllowed = 'move'; });
      row.addEventListener('dragover', function (ev) {
        var types = Array.prototype.slice.call(ev.dataTransfer.types);
        if (types.indexOf('application/x-ds-folder') < 0 && types.indexOf('application/x-ds-diagram') < 0) return;
        if (f.id === 'all' && types.indexOf('application/x-ds-diagram') >= 0) return;
        ev.preventDefault(); row.classList.add('ds-drop');
      });
      row.addEventListener('dragleave', function () { row.classList.remove('ds-drop'); });
      row.addEventListener('drop', function (ev) {
        ev.preventDefault(); row.classList.remove('ds-drop');
        var fid = ev.dataTransfer.getData('application/x-ds-folder'), did = ev.dataTransfer.getData('application/x-ds-diagram');
        var target = (f.id === 'all' || f.id === 'none') ? null : f.id;
        if (fid) moveFolder(Number(fid), target);
        else if (did) moveDiagram(Number(did), target);
      });
    }
    li.appendChild(row);
    return li;
  }
  function saveOpen() { try { localStorage.setItem('satom.ds.tree.open', JSON.stringify(state.open)); } catch (e) { /* private mode */ } }
  function treeKey(ev, f, hasKids) {
    var rows = DS.$$('.ds-tree-row', tree).filter(function (r) { return r.offsetParent !== null; });
    var i = rows.indexOf(ev.currentTarget);
    if (ev.key === 'ArrowDown' && rows[i + 1]) { ev.preventDefault(); rows[i + 1].focus(); }
    else if (ev.key === 'ArrowUp' && rows[i - 1]) { ev.preventDefault(); rows[i - 1].focus(); }
    else if (ev.key === 'ArrowRight' && hasKids && !state.open[f.id]) { ev.preventDefault(); state.open[f.id] = true; saveOpen(); renderTree(); focusFolder(f.id); }
    else if (ev.key === 'ArrowLeft' && hasKids && state.open[f.id]) { ev.preventDefault(); state.open[f.id] = false; saveOpen(); renderTree(); focusFolder(f.id); }
    else if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); ev.currentTarget.click(); }
    else if (ev.key === 'F2' && canEdit && !f.root) { ev.preventDefault(); renameFolder(f); }
  }
  function focusFolder(id) { var r = tree.querySelector('[data-folder="' + id + '"]'); if (r) r.focus(); }

  function validName(v) { return v.length > 64 ? 'At most 64 characters.' : ''; }
  function newFolder(parent) {
    DS.prompt(parent ? 'New sub-folder in "' + fById(parent).name + '"' : 'New folder', 'Folder name', '', { max: 64, ok: 'Create', validate: validName }).then(function (v) {
      if (!v) return;
      DS.http('POST', api.folders(), { name: v, parent_id: parent || null }).then(function (res) {
        if (!res.ok) { DS.toast(DS.errorText(res, 'Creating the folder failed'), 'danger'); return; }
        if (parent) { state.open[parent] = true; saveOpen(); }
        DS.toast('Folder "' + v + '" created.', 'success'); load();
      }, function (e) { DS.toast(e.message, 'danger'); });
    });
  }
  function renameFolder(f) {
    DS.prompt('Rename folder', 'Folder name', f.name, { max: 64, ok: 'Rename', validate: validName }).then(function (v) {
      if (!v || v === f.name) return;
      DS.http('PATCH', api.folder(f.id), { name: v }).then(function (res) {
        if (!res.ok) { DS.toast(DS.errorText(res, 'Renaming failed'), 'danger'); return; }
        load();
      }, function (e) { DS.toast(e.message, 'danger'); });
    });
  }
  function deleteFolder(f) {
    var n = state.diagrams.filter(function (d) { return d.folder_id === f.id; }).length;
    if (n || kids(f.id).length) { DS.toast('"' + f.name + '" is not empty: move its diagrams and sub-folders out first.', 'warning'); return; }
    DS.confirm('Delete folder', 'Delete the empty folder "' + f.name + '"?', 'Delete', true).then(function (ok) {
      if (!ok) return;
      DS.http('DELETE', api.folder(f.id)).then(function (res) {
        if (!res.ok) { DS.toast(DS.errorText(res, 'Deleting failed'), 'danger'); return; }
        if (String(state.folder) === String(f.id)) state.folder = 'all';
        DS.toast('Folder deleted.', 'success'); load();
      }, function (e) { DS.toast(e.message, 'danger'); });
    });
  }
  function moveFolder(id, parent) {
    if (parent !== null && descendants(id).has(parent)) { DS.toast('A folder cannot move into itself or one of its sub-folders.', 'warning'); return; }
    var f = fById(id); if (!f || (f.parent_id || null) === parent) return;
    DS.http('PATCH', api.folder(id), { parent_id: parent }).then(function (res) {
      if (!res.ok) { DS.toast(DS.errorText(res, 'Moving the folder failed'), 'danger'); return; }
      if (parent) { state.open[parent] = true; saveOpen(); }
      DS.toast('Moved "' + f.name + '".', 'success'); load();
    }, function (e) { DS.toast(e.message, 'danger'); });
  }
  function moveDiagram(id, folder) {
    DS.http('PATCH', api.diagram(id), { folder_id: folder }).then(function (res) {
      if (!res.ok) { DS.toast(DS.errorText(res, 'Moving the diagram failed'), 'danger'); return; }
      DS.toast('Moved to ' + (folder ? '"' + path(folder) + '"' : 'Unfiled') + '.', 'success'); load();
    }, function (e) { DS.toast(e.message, 'danger'); });
  }

  // ---------------------------------------------------------------- table
  function visible() {
    var term = q.value.trim().toLowerCase();
    var ids = null;
    if (state.folder !== 'all' && state.folder !== 'none') ids = sub.checked ? descendants(state.folder) : new Set([state.folder]);
    var list = state.diagrams.filter(function (d) {
      if (state.folder === 'none' && d.folder_id) return false;
      if (ids && !ids.has(d.folder_id)) return false;
      if (pub.value === 'yes' && !d.published) return false;
      if (pub.value === 'no' && d.published) return false;
      if (term && (d.name + ' ' + (d.description || '') + ' ' + (d.owner || '') + ' ' + path(d.folder_id)).toLowerCase().indexOf(term) < 0) return false;
      return true;
    });
    var key = state.sort.replace(/^-/, ''), dir = state.sort[0] === '-' ? -1 : 1;
    list.sort(function (a, b) {
      var va = key === 'folder' ? path(a.folder_id) : a[key], vb = key === 'folder' ? path(b.folder_id) : b[key];
      if (typeof va === 'string' || typeof vb === 'string') return dir * String(va || '').localeCompare(String(vb || ''));
      return dir * ((va || 0) - (vb || 0));
    });
    return list;
  }
  function renderRows() {
    var list = visible();
    DS.clear(rowsEl);
    var where = state.folder === 'all' ? 'all folders' : state.folder === 'none' ? 'Unfiled' : '"' + path(state.folder) + '"';
    status.textContent = list.length + ' of ' + state.diagrams.length + ' diagram(s) — ' + where;
    DS.$$('#dsTable th[data-sort]').forEach(function (th) {
      var k = th.getAttribute('data-sort');
      th.setAttribute('aria-sort', state.sort.replace(/^-/, '') === k ? (state.sort[0] === '-' ? 'descending' : 'ascending') : 'none');
    });
    if (!list.length) {
      var empty = h('div', { class: 'ds-empty' }, [DS.icon('diagram-3'), h('div', { text: state.diagrams.length ? 'No diagram matches the filters.' : 'No diagrams yet.' }),
        canEdit && !state.diagrams.length ? h('div', { class: 'small mt-1', text: 'Create one with "New diagram", or bring one in with "Import".' }) : null]);
      rowsEl.appendChild(h('tr', null, h('td', { colspan: 8 }, empty)));
      return;
    }
    list.forEach(function (d) { rowsEl.appendChild(row(d)); });
  }
  function row(d) {
    var tr = h('tr', { 'data-id': String(d.id), draggable: canEdit ? 'true' : null });
    var open = h('a', { href: d.url || api.editorPage(d.id), text: d.name });
    var nameCell = h('td', { class: 'ds-name' }, [open, d.description ? h('div', { class: 'small ds-muted', text: d.description.slice(0, 120) }) : null]);
    var pubCell = h('td', null, d.published ? DS.badge('success', 'Published', 'broadcast') : DS.badge('secondary', 'Draft', 'pencil'));
    var acts = h('td', { class: 'actions-col' }, h('div', { class: 'ds-btnrow flex-nowrap' }, [
      h('a', { class: 'btn btn-sm btn-fw-secondary', href: d.url || api.editorPage(d.id), title: canEdit ? 'Open in the editor' : 'Open (read-only)' }, [DS.icon(canEdit ? 'pencil-square' : 'eye'), ' Open']),
      moreMenu(d)
    ]));
    [nameCell, h('td', { text: d.folder_id ? path(d.folder_id) : '—' }), pubCell, h('td', { text: DS.fmtDate(d.updated_at), title: d.updated_by ? 'by ' + d.updated_by : null }),
      h('td', { text: d.owner || '—' }), h('td', { class: 'text-end', text: String(d.elements || 0) }), h('td', { class: 'text-end', text: String(d.versions || 0) }), acts].forEach(function (c) { tr.appendChild(c); });
    if (canEdit) tr.addEventListener('dragstart', function (ev) { ev.dataTransfer.setData('application/x-ds-diagram', String(d.id)); ev.dataTransfer.effectAllowed = 'move'; });
    return tr;
  }
  function moreMenu(d) {
    var items = [];
    function item(label, icon, fn, opts) { var b = h('button', { type: 'button', class: 'dropdown-item' + (opts && opts.danger ? ' text-danger' : '') }, [DS.icon(icon, 'me-2'), label]); b.addEventListener('click', fn); items.push(h('li', null, b)); }
    item('Versions…', 'clock-history', function () { versions(d); });
    if (d.published) items.push(h('li', null, h('a', { class: 'dropdown-item', href: d.view_url || (cfg.viewerBase || '/diagrams/') + d.id }, [DS.icon('broadcast', 'me-2'), 'View published'])));
    if (canEdit) {
      item('Rename…', 'pencil', function () { rename(d); });
      item('Move to folder…', 'folder-symlink', function () { move(d); });
      item('Duplicate', 'copy', function () { duplicate(d); });
    }
    if (canPublish) item(d.published ? 'Unpublish' : 'Publish…', d.published ? 'eye-slash' : 'broadcast', function () { publish(d); });
    if (canEdit) { items.push(h('li', null, h('hr', { class: 'dropdown-divider' }))); item('Delete…', 'trash', function () { remove(d); }, { danger: true }); }
    return h('div', { class: 'dropdown fw-row-more' }, [
      h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary dropdown-toggle', 'data-bs-toggle': 'dropdown', 'aria-expanded': 'false', 'data-bs-popper-config': '{"strategy":"fixed"}', 'aria-label': 'More actions for ' + d.name }, DS.icon('three-dots')),
      h('ul', { class: 'dropdown-menu dropdown-menu-end' }, items)
    ]);
  }
  function rename(d) {
    DS.prompt('Rename diagram', 'Name', d.name, { max: 200, ok: 'Rename' }).then(function (v) {
      if (!v || v === d.name) return;
      DS.http('PATCH', api.diagram(d.id), { name: v }).then(function (res) { if (!res.ok) DS.toast(DS.errorText(res, 'Renaming failed'), 'danger'); else { DS.toast('Renamed.', 'success'); load(); } });
    });
  }
  function move(d) {
    var s = folderOptions(d.folder_id, true, 'Unfiled');
    DS.dialog({ title: 'Move "' + d.name + '"', body: h('div', null, [h('label', { class: 'form-label', text: 'Folder' }), s]), buttons: [{ label: 'Cancel', value: null }, { label: 'Move', primary: true, value: function () { return s.value; } }] })
      .then(function (v) { if (v === null || v === undefined) return; moveDiagram(d.id, v ? Number(v) : null); });
  }
  function duplicate(d) {
    DS.http('POST', api.duplicate(d.id), {}).then(function (res) { if (!res.ok) DS.toast(DS.errorText(res, 'Duplicating failed'), 'danger'); else { DS.toast('Duplicated.', 'success'); load(); } });
  }
  function remove(d) {
    DS.confirm('Delete diagram', 'Delete "' + d.name + '" and its ' + (d.versions || 0) + ' version(s)?' + (d.published ? ' It also disappears from the Diagrams menu.' : '') + ' This cannot be undone.', 'Delete', true).then(function (ok) {
      if (!ok) return;
      DS.http('DELETE', api.diagram(d.id)).then(function (res) { if (!res.ok) DS.toast(DS.errorText(res, 'Deleting failed'), 'danger'); else { DS.toast('Deleted "' + d.name + '".', 'success'); load(); } });
    });
  }
  function publish(d) {
    if (d.published) {
      DS.confirm('Unpublish', 'Remove "' + d.name + '" from the Diagrams menu? The diagram itself stays here.', 'Unpublish').then(function (ok) {
        if (!ok) return;
        DS.http('POST', api.publish(d.id), { published: false }).then(function (res) { if (!res.ok) DS.toast(DS.errorText(res, 'Unpublishing failed'), 'danger'); else { DS.toast('Unpublished.', 'success'); load(); } });
      });
      return;
    }
    var s = folderOptions(d.folder_id, true, 'Top level of the Diagrams menu');
    var body = h('div', null, [
      h('p', { class: 'small', text: 'The current version (' + d.version + ') appears in the sidebar under Diagrams, in the folder you choose. Later saves are published when you publish again.' }),
      h('label', { class: 'form-label', text: 'Menu folder' }), s,
      h('div', { class: 'form-text', text: 'The menu uses the same folder tree as this library; the diagram is filed there.' })
    ]);
    DS.dialog({ title: 'Publish "' + d.name + '"', body: body, buttons: [{ label: 'Cancel', value: null }, { label: 'Publish', primary: true, value: function () { return { f: s.value }; } }] }).then(function (v) {
      if (!v) return;
      DS.http('POST', api.publish(d.id), { published: true, menu_folder_id: v.f ? Number(v.f) : null }).then(function (res) {
        if (!res.ok) DS.toast(DS.errorText(res, 'Publishing failed'), 'danger'); else { DS.toast('Published to the Diagrams menu.', 'success'); load(); }
      });
    });
  }

  // ------------------------------------------------------------- versions
  function versions(d) {
    var body = h('div', null, h('p', { class: 'ds-muted small', text: 'Loading versions…' }));
    DS.dialog({ title: 'Versions of "' + d.name + '"', body: body, size: 'xl', scroll: true, buttons: [{ label: 'Close', value: null, primary: true }] });
    DS.http('GET', api.versions(d.id)).then(function (res) {
      DS.clear(body);
      if (!res.ok) { body.appendChild(h('div', { class: 'fw-alert-danger small p-2', role: 'alert', text: DS.errorText(res, 'Versions') })); return; }
      var list = (Array.isArray(res.data) ? res.data : res.data.versions || []).slice().sort(function (a, b) { return b.number - a.number; });
      if (!list.length) { body.appendChild(h('p', { text: 'No versions.' })); return; }
      var selA = h('select', { class: 'form-select form-select-sm', 'aria-label': 'Version A' }), selB = h('select', { class: 'form-select form-select-sm', 'aria-label': 'Version B' });
      list.forEach(function (v, i) { selA.appendChild(h('option', { value: v.number, text: 'Version ' + v.number, selected: i === 1 })); selB.appendChild(h('option', { value: v.number, text: 'Version ' + v.number, selected: i === 0 })); });
      var diffBtn = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary' }, [DS.icon('file-diff'), ' Compare']);
      var out = h('div', { class: 'mt-2', 'aria-live': 'polite' });
      var preview = h('div', { class: 'mt-3' });
      diffBtn.addEventListener('click', function () { diff(d, selA.value, selB.value, out); });
      var t = h('table', { class: 'fw-table' }, [h('thead', null, h('tr', null, ['Version', 'Saved', 'By', 'Note', 'Contents', ''].map(function (x) { return h('th', { scope: 'col', text: x }); }))), h('tbody', null, list.map(function (v) {
        var st = v.stats || {};
        var pv = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary' }, [DS.icon('eye'), ' Preview']);
        var rs = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary' }, [DS.icon('arrow-counterclockwise'), ' Restore']);
        rs.disabled = !canEdit || v.number === d.version;
        pv.addEventListener('click', function () { previewVersion(d, v.number, preview); });
        rs.addEventListener('click', function () { restore(d, v.number); });
        return h('tr', null, [h('td', null, [h('strong', { text: String(v.number) }), v.number === d.version ? h('span', null, [' ', DS.badge('primary', 'current')]) : null]), h('td', { text: DS.fmtDate(v.created_at) }), h('td', { text: v.created_by || '' }),
          h('td', { text: v.note || '' }), h('td', { text: st.elements !== undefined ? st.elements + ' el., ' + st.connectors + ' conn.' : '' }), h('td', { class: 'actions-col' }, h('div', { class: 'ds-btnrow flex-nowrap' }, [pv, rs]))]);
      }))]);
      body.appendChild(h('div', { class: 'fw-table-wrapper' }, t));
      body.appendChild(h('div', { class: 'ds-btnrow mt-3' }, [h('span', { class: 'small', text: 'Compare' }), selA, h('span', { class: 'small', text: 'with' }), selB, diffBtn]));
      body.appendChild(out);
      body.appendChild(preview);
    });
  }
  function previewVersion(d, n, host) {
    DS.clear(host).appendChild(h('p', { class: 'ds-muted small', text: 'Loading version ' + n + '…' }));
    DS.http('GET', api.version(d.id, n)).then(function (res) {
      if (!res.ok) { DS.clear(host).appendChild(h('div', { class: 'fw-alert-danger small p-2', role: 'alert', text: DS.errorText(res, 'Preview') })); return; }
      var doc = DS.model.fillDoc(res.data.doc || res.data);
      var svg = DS.s('svg', { class: 'ds-preview-svg', role: 'img', 'aria-label': 'Version ' + n + ', page 1' });
      DS.clear(host).appendChild(h('h3', { class: 'h6', text: 'Version ' + n + ' — ' + doc.pages[0].name + (doc.pages.length > 1 ? ' (page 1 of ' + doc.pages.length + ')' : '') }));
      var box = h('div', { class: 'ds-preview-box' }, svg);
      host.appendChild(box);
      var r = new DS.Renderer(svg, { symbolUrl: function (l, s2) { return api.symbolSvg(l, s2); } });
      r.setPage(doc.pages[0]); r.setGrid(false);
      requestAnimationFrame(function () { r.fit(); });
    });
  }
  function restore(d, n) {
    DS.confirm('Restore version', 'Restore version ' + n + ' of "' + d.name + '"? It becomes a new version; nothing is deleted.', 'Restore').then(function (ok) {
      if (!ok) return;
      DS.http('POST', api.restore(d.id, n), {}).then(function (res) { if (!res.ok) DS.toast(DS.errorText(res, 'Restore failed'), 'danger'); else { DS.toast('Version ' + n + ' restored as version ' + (res.data && res.data.version) + '.', 'success'); load(); } });
    });
  }
  function diff(d, a, b, out) {
    DS.clear(out).appendChild(h('p', { class: 'ds-muted small', text: 'Comparing…' }));
    DS.http('GET', api.diff(d.id, a, b)).then(function (res) {
      DS.clear(out);
      if (!res.ok) { out.appendChild(h('div', { class: 'fw-alert-danger small p-2', role: 'alert', text: DS.errorText(res, 'Compare') })); return; }
      var r = res.data || {};
      out.appendChild(h('div', { class: 'ds-btnrow mb-2' }, [
        h('strong', { text: 'Version ' + a + ' → ' + b + ':' }),
        r.identical ? DS.badge('success', 'Identical', 'check-circle') : DS.badge('warning', 'Changed', 'exclamation-triangle'),
        r.score !== undefined ? h('span', { class: 'small', text: 'similarity ' + r.score + ' %' }) : null
      ]));
      var cats = r.categories || {};
      var keys = Object.keys(cats).filter(function (k) { return cats[k].problems; });
      if (keys.length) {
        out.appendChild(h('table', { class: 'fw-table' }, [h('thead', null, h('tr', null, ['Category', 'Checked', 'Differences', 'Details'].map(function (x) { return h('th', { scope: 'col', text: x }); }))),
          h('tbody', null, keys.map(function (k) {
            var det = (cats[k].details || []).slice(0, 8).map(function (x) { return h('li', { text: typeof x === 'string' ? x : JSON.stringify(x) }); });
            return h('tr', null, [h('td', { text: k }), h('td', { class: 'text-end', text: String(cats[k].checked) }), h('td', { class: 'text-end', text: String(cats[k].problems) }), h('td', null, h('ul', { class: 'ds-diff-list mb-0' }, det))]);
          }))]));
      }
      var items = r.not_preserved || r.differences || [];
      if (items.length) out.appendChild(h('details', { class: 'mt-2' }, [h('summary', { text: items.length + ' difference(s)' + (r.truncated ? ' (first ones shown)' : '') }),
        h('ul', { class: 'ds-diff-list' }, items.slice(0, 200).map(function (x) { return h('li', { text: typeof x === 'string' ? x : [x.where, x.what, x.why].filter(Boolean).join(' — ') || JSON.stringify(x) }); }))]));
      if (!keys.length && !items.length && !r.identical) out.appendChild(h('pre', { class: 'fw-code-block small', text: JSON.stringify(r, null, 1).slice(0, 4000) }));
    });
  }

  // ----------------------------------------------------------------- wiring
  [q].forEach(function (x) { x.addEventListener('input', DS.debounce(renderRows, 150)); });
  [pub, sub].forEach(function (x) { x.addEventListener('change', function () { renderTree(); renderRows(); }); });
  sortSel.addEventListener('change', function () { state.sort = sortSel.value; renderRows(); });
  DS.$$('#dsTable th[data-sort] .ds-sort').forEach(function (b) {
    b.addEventListener('click', function () {
      var k = b.parentNode.getAttribute('data-sort');
      var cur = state.sort.replace(/^-/, '');
      state.sort = cur === k ? (state.sort[0] === '-' ? k : '-' + k) : (k === 'updated_at' || k === 'elements' ? '-' + k : k);
      if (Array.prototype.some.call(sortSel.options, function (o) { return o.value === state.sort; })) sortSel.value = state.sort;
      renderRows();
    });
  });
  var nf = document.getElementById('dsNewFolder');
  if (nf) nf.addEventListener('click', function () { newFolder(state.folder !== 'all' && state.folder !== 'none' ? state.folder : null); });
  var nb = document.getElementById('dsNewBtn');
  if (nb) nb.addEventListener('click', function () {
    var name = h('input', { type: 'text', class: 'form-control', maxlength: 200, value: 'Untitled diagram' });
    var fsel = folderOptions(state.folder !== 'all' && state.folder !== 'none' ? state.folder : null, true, 'Unfiled');
    var err = h('div', { class: 'invalid-feedback', text: 'A name is required.' });
    DS.dialog({ title: 'New diagram', body: h('div', null, [h('label', { class: 'form-label', text: 'Name' }), name, err, h('label', { class: 'form-label mt-2', text: 'Folder' }), fsel]),
      buttons: [{ label: 'Cancel', value: null }, { label: 'Create and open', primary: true, validate: function () { var ok = !!name.value.trim(); name.classList.toggle('is-invalid', !ok); return ok; }, value: function () { return { name: name.value.trim(), folder: fsel.value }; } }] })
      .then(function (v) {
        if (!v) return;
        DS.http('POST', api.diagrams(), { name: v.name, folder_id: v.folder ? Number(v.folder) : null }).then(function (res) {
          if (!res.ok) { DS.toast(DS.errorText(res, 'Creating the diagram failed'), 'danger'); return; }
          var url = (res.data && res.data.url) || api.editorPage(res.data.id);
          if (window.Turbo) window.Turbo.visit(url); else window.location.assign(url);
        }, function (e) { DS.toast(e.message, 'danger'); });
      });
  });
  load();
})();
