// Operations › Wiki — the "Publish to Confluence" dialog
// (wiki/_confluence_modal.html). Each Confluence button carries its
// article's feed URLs; opening the dialog reads the article's state, lists
// the chosen connection's spaces, and, once a space is picked, its page tree
// (one level at a time) or the pages whose title matches the search. The
// form then posts like any other (views/wiki.confluence_publish).
//
// CSP-safe: no inline handlers, and nothing that came from Confluence is
// ever written as HTML — titles go in through textContent.
(function () {
  const VERSION = (document.currentScript && document.currentScript.src) || 'inline';
  if (window.FWWikiCF && window.FWWikiCF.version === VERSION) { window.FWWikiCF.init(); return; }

  function fmt(s, vals) {
    return String(s || '').replace(/\{(\w+)\}/g, function (m, k) { return vals[k] != null ? vals[k] : m; });
  }
  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function show(node, on) { if (node) node.classList.toggle('d-none', !on); }
  function getJSON(url) {
    return fetch(url, { headers: { Accept: 'application/json' }, credentials: 'same-origin' })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      });
  }
  function withQuery(base, q) {
    const u = new URL(base, window.location.origin);
    Object.keys(q).forEach(function (k) { u.searchParams.set(k, q[k]); });
    return u.pathname + u.search;
  }

  function Dialog(root) {
    const $ = function (sel) { return root.querySelector(sel); };
    const T = root.dataset;
    const form = $('[data-cf-form]');
    const ui = {
      name: $('[data-cf-name]'), loading: $('[data-cf-loading]'), error: $('[data-cf-error]'),
      links: $('[data-cf-links]'), linkList: $('[data-cf-link-list]'),
      findings: $('[data-cf-findings]'), findingList: $('[data-cf-finding-list]'),
      pickers: $('[data-cf-pickers]'), connWrap: $('[data-cf-conn-wrap]'), conn: $('[data-cf-conn]'),
      space: $('[data-cf-space]'), spaceFilter: $('[data-cf-space-filter]'),
      parentWrap: $('[data-cf-parent-wrap]'), updateNote: $('[data-cf-update-note]'),
      picker: $('[data-cf-picker]'), search: $('[data-cf-search]'), tree: $('[data-cf-tree]'),
      picked: $('[data-cf-picked]'), parent: $('[data-cf-parent]'),
      ackWrap: $('[data-cf-ack-wrap]'), ack: $('[data-cf-ack]'),
      overrideWrap: $('[data-cf-override-wrap]'), override: $('[data-cf-override]'),
      submit: $('[data-cf-submit]')
    };
    let urls = {}, state = null, spaces = [], seq = 0, searchTimer = null;

    function fail(msg) {
      ui.error.textContent = msg;
      show(ui.error, true);
      show(ui.loading, false);
    }
    function clearError() { show(ui.error, false); ui.error.textContent = ''; }

    function linkFor(conn, space) {
      return (state.links || []).find(function (l) { return String(l.connection) === String(conn) && l.space === space; });
    }

    function refreshSubmit() {
      const space = ui.space.value;
      const blocked = state && state.findings.length && !(state.may_override && ui.override.checked);
      const needAck = state && state.narrow && !ui.ack.checked;
      ui.submit.disabled = !state || !space || blocked || needAck;
      if (state) {
        ui.submit.textContent = fmt(linkFor(ui.conn.value, space) ? T.tUpdate : T.tPublish, { n: state.revision });
      }
    }

    function renderLinks() {
      ui.linkList.replaceChildren();
      (state.links || []).forEach(function (l) {
        const li = el('li', 'mb-1');
        li.appendChild(el('strong', null, l.connection_name + ' · ' + l.space));
        li.appendChild(document.createTextNode(': '));
        const a = el('a', null, fmt(T.tPage, { id: l.page_id }));
        if (/^https:\/\//i.test(l.page_url)) { a.href = l.page_url; a.target = '_blank'; a.rel = 'noopener noreferrer'; }
        li.appendChild(a);
        li.appendChild(document.createTextNode(' — '));
        li.appendChild(el('span', 'fw-badge ' + (l.current ? 'fw-badge-success' : 'fw-badge-warning'),
          l.current ? T.tCurrent : fmt(T.tHolds, { n: l.revision, m: state.revision })));
        li.appendChild(el('span', 'text-muted ms-1', (l.at ? l.at + ' UTC · ' : '') + (l.by || '')));
        const b = el('button', 'btn btn-link btn-sm p-0 ms-2', T.tForget);
        b.type = 'button';
        b.addEventListener('click', function () {
          if (!window.confirm(T.tForgetConfirm)) return;
          const f = el('form');
          f.method = 'post';
          f.action = l.forget;
          [['csrf_token', form.querySelector('[name="csrf_token"]').value],
           ['next', form.querySelector('[name="next"]').value]].forEach(function (kv) {
            const i = el('input'); i.type = 'hidden'; i.name = kv[0]; i.value = kv[1]; f.appendChild(i);
          });
          document.body.appendChild(f);
          f.submit();
        });
        li.appendChild(b);
        ui.linkList.appendChild(li);
      });
      show(ui.links, (state.links || []).length > 0);
    }

    function renderFindings() {
      ui.findingList.replaceChildren();
      state.findings.forEach(function (f) { ui.findingList.appendChild(el('li', null, fmt(T.tFinding, f))); });
      show(ui.findings, state.findings.length > 0);
      show(ui.overrideWrap, state.findings.length > 0 && state.may_override);
      show(ui.ackWrap, !!state.narrow);
    }

    function fillSpaces() {
      const term = (ui.spaceFilter.value || '').trim().toLowerCase();
      const keep = ui.space.value;
      ui.space.replaceChildren(el('option', null, T.tPickSpace));
      ui.space.firstChild.value = '';
      spaces.filter(function (s) {
        return !term || s.name.toLowerCase().indexOf(term) >= 0 || s.key.toLowerCase().indexOf(term) >= 0;
      }).forEach(function (s) {
        const o = el('option', null, s.name + ' (' + s.key + ')');
        o.value = s.key;
        ui.space.appendChild(o);
      });
      if (keep && Array.from(ui.space.options).some(function (o) { return o.value === keep; })) ui.space.value = keep;
    }

    function loadSpaces() {
      const mine = ++seq;
      spaces = [];
      ui.space.disabled = true;
      ui.space.replaceChildren(el('option', null, T.tLoading));
      show(ui.parentWrap, false);
      clearError();
      return getJSON(withQuery(urls.spaces, { connection: ui.conn.value })).then(function (j) {
        if (mine !== seq) return;
        if (!j.ok) { fail(j.error); ui.space.replaceChildren(); return; }
        spaces = j.spaces || [];
        ui.space.disabled = false;
        fillSpaces();
        refreshSubmit();
      }).catch(function (e) { if (mine === seq) fail(String(e)); });
    }

    function pick(id, title, button) {
      ui.parent.value = id;
      ui.picked.textContent = title;
      ui.tree.querySelectorAll('.wiki-cf-pick.active').forEach(function (b) { b.classList.remove('active'); b.setAttribute('aria-selected', 'false'); });
      if (button) { button.classList.add('active'); button.setAttribute('aria-selected', 'true'); }
    }

    function node(page, isRoot) {
      const wrap = el('div', 'wiki-cf-node');
      wrap.setAttribute('role', 'treeitem');
      const row = el('div', 'wiki-cf-row');
      const twisty = el('button', 'wiki-cf-twisty');
      twisty.type = 'button';
      twisty.setAttribute('aria-expanded', 'false');
      twisty.title = T.tExpand;
      twisty.appendChild(el('i', 'bi bi-chevron-right'));
      const label = el('button', 'wiki-cf-pick', page.title);
      label.type = 'button';
      label.setAttribute('aria-selected', 'false');
      if (page.path && page.path.length) label.appendChild(el('span', 'wiki-cf-path', page.path.join(' › ')));
      const kids = el('div', 'wiki-cf-children d-none');
      kids.setAttribute('role', 'group');
      row.appendChild(twisty);
      row.appendChild(label);
      wrap.appendChild(row);
      wrap.appendChild(kids);
      label.addEventListener('click', function () { pick(page.id, page.title, label); });
      let loaded = false;
      function toggle(open) {
        twisty.setAttribute('aria-expanded', open ? 'true' : 'false');
        twisty.firstChild.className = open ? 'bi bi-chevron-down' : 'bi bi-chevron-right';
        show(kids, open);
        if (!open || loaded) return;
        loaded = true;
        kids.replaceChildren(el('div', 'text-muted small ps-3', T.tLoading));
        getJSON(withQuery(urls.pages, { connection: ui.conn.value, space: ui.space.value, parent: page.id }))
          .then(function (j) {
            kids.replaceChildren();
            if (!j.ok) { kids.appendChild(el('div', 'text-danger small ps-3', j.error)); loaded = false; return; }
            if (!j.pages.length) { kids.appendChild(el('div', 'text-muted small ps-3', T.tEmpty)); return; }
            j.pages.forEach(function (p) { kids.appendChild(node(p, false)); });
          })
          .catch(function (e) { kids.replaceChildren(el('div', 'text-danger small ps-3', String(e))); loaded = false; });
      }
      twisty.addEventListener('click', function () { toggle(twisty.getAttribute('aria-expanded') !== 'true'); });
      if (isRoot) toggle(true);
      return { wrap: wrap, label: label };
    }

    function loadTree() {
      ui.tree.replaceChildren();
      const root = node({ id: '', title: T.tTop }, true);
      root.wrap.classList.add('wiki-cf-root');
      ui.tree.appendChild(root.wrap);
      pick('', T.tTop, root.label);
    }

    function runSearch() {
      const q = (ui.search.value || '').trim();
      if (!q) { loadTree(); return; }
      const mine = ++seq;
      ui.tree.replaceChildren(el('div', 'text-muted small', T.tLoading));
      getJSON(withQuery(urls.pages, { connection: ui.conn.value, space: ui.space.value, q: q }))
        .then(function (j) {
          if (mine !== seq) return;
          ui.tree.replaceChildren();
          if (!j.ok) { ui.tree.appendChild(el('div', 'text-danger small', j.error)); return; }
          if (!j.pages.length) { ui.tree.appendChild(el('div', 'text-muted small', T.tNohits)); return; }
          const top = node({ id: '', title: T.tTop }, false);
          top.wrap.querySelector('.wiki-cf-twisty').classList.add('invisible');
          ui.tree.appendChild(top.wrap);
          j.pages.forEach(function (p) { ui.tree.appendChild(node(p, false).wrap); });
          pick('', T.tTop, top.label);
        })
        .catch(function (e) { if (mine === seq) ui.tree.replaceChildren(el('div', 'text-danger small', String(e))); });
    }

    function onSpace() {
      const space = ui.space.value;
      ui.search.value = '';
      ui.parent.value = '';
      show(ui.parentWrap, !!space);
      if (space) {
        const existing = linkFor(ui.conn.value, space);
        show(ui.updateNote, !!existing);
        show(ui.picker, !existing);
        if (!existing) loadTree();
      }
      refreshSubmit();
    }

    ui.conn.addEventListener('change', function () { loadSpaces().then(onSpace); });
    ui.space.addEventListener('change', onSpace);
    ui.spaceFilter.addEventListener('input', function () { fillSpaces(); onSpace(); });
    ui.search.addEventListener('input', function () { clearTimeout(searchTimer); searchTimer = setTimeout(runSearch, 300); });
    ui.search.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') { ev.preventDefault(); clearTimeout(searchTimer); runSearch(); } });
    ui.ack.addEventListener('change', refreshSubmit);
    ui.override.addEventListener('change', refreshSubmit);

    this.open = function (button) {
      const d = button.dataset;
      urls = { state: d.cfState, spaces: d.cfSpaces, pages: d.cfPages };
      form.action = d.cfPublish;
      ui.name.textContent = d.cfTitle || '';
      state = null;
      seq++;
      [ui.links, ui.findings, ui.pickers, ui.parentWrap, ui.ackWrap, ui.overrideWrap].forEach(function (n) { show(n, false); });
      ui.ack.checked = false;
      ui.override.checked = false;
      ui.spaceFilter.value = '';
      ui.submit.disabled = true;
      clearError();
      show(ui.loading, true);
      getJSON(urls.state).then(function (j) {
        if (!j.ok) { fail(j.error || ''); return; }
        state = j;
        show(ui.loading, false);
        renderLinks();
        renderFindings();
        ui.conn.replaceChildren();
        j.connections.forEach(function (c) {
          const o = el('option', null, c.name);
          o.value = c.id;
          ui.conn.appendChild(o);
        });
        show(ui.connWrap, j.connections.length > 1);
        show(ui.pickers, j.connections.length > 0);
        if (j.connections.length) loadSpaces().then(onSpace);
      }).catch(function (e) { fail(String(e)); });
    };
  }

  function init() {
    const root = document.querySelector('[data-cf-modal]');
    if (!root || root.dataset.bound) return;
    root.dataset.bound = '1';
    const dlg = new Dialog(root);
    root.addEventListener('show.bs.modal', function (ev) {
      if (ev.relatedTarget) dlg.open(ev.relatedTarget);
    });
  }

  window.FWWikiCF = { init: init, version: VERSION };
  init();
})();
