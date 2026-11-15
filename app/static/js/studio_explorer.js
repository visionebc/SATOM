/* Plugin Studio > Explorer (studio/index.html) as a tree, 2026-10-30.
 * An entry with objects (Apps, Data stores, Connections, API Catalog) has a
 * caret that unfolds them right below it; Apps unfold by menu group, each
 * group a <details> of its own.
 *
 * An ACCORDION (operator, same day): opening an entry -- a click on it or on
 * its caret -- shows its pane (Bootstrap list tab, which moves the .active
 * highlight), unfolds it and folds every other entry; the caret of the entry
 * already open only folds it. The server draws the entry of the current pane
 * open, so the highlighted entry is the open one. Inside Apps one menu group
 * is open at a time; the last one opened is remembered in this browser.
 * Bound to the Explorer element, which a Turbo visit replaces with the body,
 * so listeners never stack.
 */
(function () {
  'use strict';
  var list = document.getElementById('studio-explorer-list');
  if (!list) return;
  var GROUP_KEY = 'satom.studio.explorer.group';
  function entries() { return list.querySelectorAll('[data-ex]'); }
  function setOpen(a, on) {
    a.classList.toggle('ex-open', on);
    var c = a.querySelector('[data-ex-toggle]');
    if (c) c.setAttribute('aria-expanded', on ? 'true' : 'false');
  }
  function openOnly(a) {
    entries().forEach(function (x) { setOpen(x, x === a); });
  }
  function showPane(a) {
    if (window.bootstrap && window.bootstrap.Tab) window.bootstrap.Tab.getOrCreateInstance(a).show();
  }
  // the panes without objects (Console, Examples) fold the tree too
  list.querySelectorAll('[data-bs-toggle="list"]').forEach(function (t) {
    t.addEventListener('shown.bs.tab', function () {
      if (!t.hasAttribute('data-ex')) openOnly(null);
    });
  });
  list.addEventListener('click', function (ev) {
    var c = ev.target.closest ? ev.target.closest('[data-ex-toggle]') : null;
    if (c && list.contains(c)) {
      // keep the click off the entry: Bootstrap's tab handler is delegated on document
      ev.preventDefault();
      ev.stopPropagation();
      var a = c.closest('[data-ex]');
      if (a.classList.contains('ex-open')) { setOpen(a, false); return; }
      openOnly(a);
      showPane(a);
      return;
    }
    var e = ev.target.closest ? ev.target.closest('[data-ex]') : null;
    if (e && list.contains(e)) openOnly(e);
  });
  list.addEventListener('keydown', function (ev) {
    if ((ev.key === 'Enter' || ev.key === ' ') && ev.target.matches && ev.target.matches('[data-ex-toggle]')) {
      ev.target.click();
      ev.preventDefault();
      ev.stopPropagation();
    }
  });
  // menu groups inside Apps: one open at a time
  var groups = list.querySelectorAll('details[data-ex-group]');
  var last = null;
  try { last = window.localStorage.getItem(GROUP_KEY); } catch (e) { /* private mode */ }
  groups.forEach(function (d) {
    if (last !== null && d.getAttribute('data-ex-group') === last) d.open = true;
    d.addEventListener('toggle', function () {
      if (!d.open) {
        try { if (window.localStorage.getItem(GROUP_KEY) === d.getAttribute('data-ex-group')) window.localStorage.removeItem(GROUP_KEY); } catch (e) { /* */ }
        return;
      }
      groups.forEach(function (o) { if (o !== d) o.open = false; });
      try { window.localStorage.setItem(GROUP_KEY, d.getAttribute('data-ex-group')); } catch (e) { /* */ }
    });
  });
})();
