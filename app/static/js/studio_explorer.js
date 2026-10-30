/* Plugin Studio > Explorer (studio/index.html) as a tree, 2026-10-30.
 * An entry with objects (Apps, Data stores, Connections, API Catalog) has a
 * caret that unfolds them right below it; Apps unfold by menu group, each
 * group a <details> of its own. Clicking the entry still shows its pane
 * (Bootstrap list tab) and unfolds it; the caret only folds and unfolds.
 * Folded by default: the browser remembers the OPEN set (localStorage), so
 * an empty store means "everything folded" without a first-run flag.
 * Bound to the Explorer element, which a Turbo visit replaces with the body,
 * so listeners never stack.
 */
(function () {
  'use strict';
  var list = document.getElementById('studio-explorer-list');
  if (!list) return;
  var KEY = 'satom.studio.explorer.open';
  function load() {
    try { return JSON.parse(window.localStorage.getItem(KEY) || '[]') || []; } catch (e) { return []; }
  }
  function save(open) {
    try { window.localStorage.setItem(KEY, JSON.stringify(open)); } catch (e) { /* private mode */ }
  }
  var open = load();
  function isOpen(id) { return open.indexOf(id) >= 0; }
  function remember(id, on) {
    open = open.filter(function (x) { return x !== id; });
    if (on) open.push(id);
    save(open);
  }
  function setEntry(key, on) {
    var a = list.querySelector('[data-ex="' + key + '"]');
    if (!a) return;
    a.classList.toggle('ex-open', on);
    var c = a.querySelector('[data-ex-toggle]');
    if (c) c.setAttribute('aria-expanded', on ? 'true' : 'false');
    remember('entry:' + key, on);
  }
  list.querySelectorAll('[data-ex]').forEach(function (a) {
    var key = a.getAttribute('data-ex');
    if (isOpen('entry:' + key)) setEntry(key, true);
  });
  list.querySelectorAll('details[data-ex-group]').forEach(function (d) {
    var id = 'group:' + d.getAttribute('data-ex-group');
    if (isOpen(id)) d.open = true;
    d.addEventListener('toggle', function () { remember(id, d.open); });
  });
  function toggleFrom(ev) {
    var c = ev.target.closest ? ev.target.closest('[data-ex-toggle]') : null;
    if (!c || !list.contains(c)) return false;
    // keep the click off the entry: Bootstrap's tab handler is delegated on document
    ev.preventDefault();
    ev.stopPropagation();
    var key = c.getAttribute('data-ex-toggle');
    var a = list.querySelector('[data-ex="' + key + '"]');
    setEntry(key, !(a && a.classList.contains('ex-open')));
    return true;
  }
  list.addEventListener('click', function (ev) {
    if (toggleFrom(ev)) return;
    var a = ev.target.closest ? ev.target.closest('[data-ex]') : null;
    if (a && list.contains(a)) setEntry(a.getAttribute('data-ex'), true);
  });
  list.addEventListener('keydown', function (ev) {
    if (ev.key !== 'Enter' && ev.key !== ' ') return;
    toggleFrom(ev);
  });
})();
