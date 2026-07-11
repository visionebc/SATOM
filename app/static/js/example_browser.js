/* Shared Studio example browser.
 * Reusable menu(group) + submenu(subgroup) + search + collapsible-code picker
 * used by Lua Studio, Plugin Studio and the Python Console.
 *
 * Usage (per page, after this file is loaded):
 *   ExampleBrowser.init({
 *     catalogElId: 'ex-catalog',   // <script type=application/json> with the array
 *     modalElId:   'exb-modal',    // the modal from _example_browser.html
 *     openBtnId:   'btn-examples', // the "Browse examples" button
 *     previewField:'code',         // which field to show in the code preview
 *     onInsert: function(ex){ ... } // page-specific insert of the raw example
 *   });
 *
 * Each example object is tolerant: group|category, subgroup, title|name,
 * description, tags[], datasets[], icon, plus code/jinja/etc.
 * CSP-safe: external 'self' script, addEventListener only, event delegation.
 */
window.ExampleBrowser = (function () {
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  function norm(ex) {
    return {
      raw: ex,
      id: String(ex.id),
      group: ex.group || ex.category || 'General',
      subgroup: ex.subgroup || '',
      title: ex.title || ex.name || ex.id,
      desc: ex.description || '',
      tags: Array.isArray(ex.tags) ? ex.tags : [],
      datasets: Array.isArray(ex.datasets) ? ex.datasets : [],
      icon: ex.icon || ''
    };
  }

  function init(cfg) {
    cfg = cfg || {};
    var previewField = cfg.previewField || 'code';
    var onInsert = cfg.onInsert || function () {};
    var catEl = document.getElementById(cfg.catalogElId || 'ex-catalog');
    var modal = document.getElementById(cfg.modalElId || 'exb-modal');
    if (!modal || !catEl) return null;

    var catalog = [];
    try { catalog = JSON.parse(catEl.textContent || '[]'); } catch (e) { catalog = []; }
    if (!Array.isArray(catalog)) catalog = [];
    var items = catalog.map(norm);

    var nav = modal.querySelector('.exb-nav');
    var cards = modal.querySelector('.exb-cards');
    var search = modal.querySelector('.exb-search');
    var closeBtn = modal.querySelector('.exb-close');
    var openBtn = document.getElementById(cfg.openBtnId || 'btn-examples');

    var sel = { group: null, subgroup: null };   // group=null -> "All"
    var collapsed = {};

    function matches(it, q) {
      if (!q) return true;
      var hay = (it.title + ' ' + it.desc + ' ' + it.group + ' ' + it.subgroup + ' ' +
        it.tags.join(' ') + ' ' + (it.raw[previewField] || '')).toLowerCase();
      return hay.indexOf(q) >= 0;
    }
    function filtered() {
      var q = (search.value || '').toLowerCase().trim();
      return items.filter(function (it) { return matches(it, q); });
    }
    function buildTree(list) {
      var t = {}, order = [];
      list.forEach(function (it) {
        if (!t[it.group]) { t[it.group] = { subs: {}, suborder: [], count: 0 }; order.push(it.group); }
        t[it.group].count++;
        var sg = it.subgroup || '';
        if (!(sg in t[it.group].subs)) { t[it.group].subs[sg] = 0; t[it.group].suborder.push(sg); }
        t[it.group].subs[sg]++;
      });
      return { t: t, order: order };
    }
    function renderNav() {
      var list = filtered();
      var tr = buildTree(list);
      var h = '<button type="button" class="exb-navitem exb-all' +
        (sel.group === null ? ' active' : '') + '" data-all="1">All examples' +
        '<span class="exb-badge">' + list.length + '</span></button>';
      tr.order.forEach(function (g) {
        var gd = tr.t[g];
        var isC = !!collapsed[g];
        var gact = (sel.group === g && sel.subgroup === null) ? ' active' : '';
        h += '<div class="exb-group">';
        h += '<button type="button" class="exb-ghead' + gact + '" data-g="' + esc(g) + '">' +
          '<i class="bi bi-chevron-' + (isC ? 'right' : 'down') + '"></i>' +
          '<span class="exb-gname">' + esc(g) + '</span>' +
          '<span class="exb-badge">' + gd.count + '</span></button>';
        if (!isC) {
          gd.suborder.forEach(function (sg) {
            if (sg === '') return;   // blank-subgroup items show under the group itself
            var sact = (sel.group === g && sel.subgroup === sg) ? ' active' : '';
            h += '<button type="button" class="exb-sub' + sact + '" data-g="' + esc(g) +
              '" data-s="' + esc(sg) + '">' + esc(sg) +
              '<span class="exb-badge">' + gd.subs[sg] + '</span></button>';
          });
        }
        h += '</div>';
      });
      nav.innerHTML = h;
    }
    function renderCards() {
      var q = (search.value || '').toLowerCase().trim();
      var list = items.filter(function (it) {
        if (!matches(it, q)) return false;
        if (sel.group === null) return true;
        if (it.group !== sel.group) return false;
        if (sel.subgroup !== null && (it.subgroup || '') !== sel.subgroup) return false;
        return true;
      });
      if (!list.length) { cards.innerHTML = '<div class="exb-empty">No examples match.</div>'; return; }
      var h = '';
      list.forEach(function (it) {
        var code = it.raw[previewField] || it.raw.code || it.raw.jinja || '';
        h += '<div class="exb-card">';
        h += '<div class="exb-card-h"><div class="exb-title">' +
          (it.icon ? '<i class="bi ' + esc(it.icon) + '"></i>' : '') + esc(it.title) + '</div>' +
          '<button type="button" class="exb-ins" data-id="' + esc(it.id) + '">Insert</button></div>';
        h += '<div class="exb-meta">' + esc(it.group) + (it.subgroup ? ' · ' + esc(it.subgroup) : '') + '</div>';
        if (it.desc) h += '<div class="exb-desc">' + esc(it.desc) + '</div>';
        if (it.datasets.length) h += '<div class="exb-ds">' +
          it.datasets.map(function (d) { return '<code>' + esc(d) + '</code>'; }).join('') + '</div>';
        if (it.tags.length) h += '<div class="exb-tags">' +
          it.tags.map(function (t) { return '<span>' + esc(t) + '</span>'; }).join('') + '</div>';
        h += '<details class="exb-codewrap"><summary>Show code</summary>' +
          '<pre class="exb-code">' + esc(code) + '</pre></details>';
        h += '</div>';
      });
      cards.innerHTML = h;
    }
    function renderAll() { renderNav(); renderCards(); }

    nav.addEventListener('click', function (e) {
      var all = e.target.closest('.exb-all');
      if (all) { sel = { group: null, subgroup: null }; renderAll(); return; }
      var gh = e.target.closest('.exb-ghead');
      if (gh) {
        var g = gh.getAttribute('data-g');
        if (sel.group === g && sel.subgroup === null) { collapsed[g] = !collapsed[g]; }
        else { sel = { group: g, subgroup: null }; collapsed[g] = false; }
        renderAll(); return;
      }
      var sb = e.target.closest('.exb-sub');
      if (sb) { sel = { group: sb.getAttribute('data-g'), subgroup: sb.getAttribute('data-s') }; renderAll(); return; }
    });
    cards.addEventListener('click', function (e) {
      var b = e.target.closest('.exb-ins');
      if (!b) return;
      var id = b.getAttribute('data-id');
      var it = items.filter(function (x) { return x.id === id; })[0];
      if (it) { onInsert(it.raw); close(); }
    });
    search.addEventListener('input', function () {
      if (search.value) sel = { group: null, subgroup: null };
      renderAll();
    });

    function open() {
      modal.style.display = 'flex';
      search.value = ''; sel = { group: null, subgroup: null }; collapsed = {};
      renderAll();
      try { search.focus(); } catch (e) {}
    }
    function close() { modal.style.display = 'none'; }

    if (openBtn) openBtn.addEventListener('click', open);
    if (closeBtn) closeBtn.addEventListener('click', close);
    modal.addEventListener('click', function (e) { if (e.target === modal) close(); });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && modal.style.display === 'flex') close();
    });

    return { open: open, close: close };
  }

  return { init: init };
})();
