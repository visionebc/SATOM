/* SATOM Documentation Center — behaviour.
   Theme switch, sidebar groups + mobile drawer, search (bar dropdown, home
   hero, search page), keyboard shortcuts, TOC scrollspy, #hash → open the
   <details> that holds the target. No dependencies; site.js is NOT loaded. */
(function () {
  'use strict';

  var d = document, root = d.documentElement;
  var $ = function (s, c) { return (c || d).querySelector(s); };
  var $$ = function (s, c) { return Array.prototype.slice.call((c || d).querySelectorAll(s)); };
  var store = {
    get: function (k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private mode */ } }
  };
  var THEMES = ['aurora', 'abyss', 'classic'];
  var THEME_KEY = 'satom.site.theme', OPEN_KEY = 'satom.dc.open';
  var mqDrawer = window.matchMedia('(max-width: 900px)');

  /* ------------------------------------------------------------ theme */
  function syncTheme() {
    var t = root.getAttribute('data-theme');
    if (THEMES.indexOf(t) < 0) t = 'aurora';
    $$('[data-theme-set]').forEach(function (b) {
      b.setAttribute('aria-pressed', b.getAttribute('data-theme-set') === t ? 'true' : 'false');
    });
  }
  function initTheme() {
    $$('[data-theme-set]').forEach(function (b) {
      b.addEventListener('click', function () {
        var t = b.getAttribute('data-theme-set');
        if (THEMES.indexOf(t) < 0) return;
        root.setAttribute('data-theme', t);
        store.set(THEME_KEY, t);
        syncTheme();
      });
    });
    window.addEventListener('storage', function (e) {
      if (e.key === THEME_KEY && THEMES.indexOf(e.newValue) >= 0) {
        root.setAttribute('data-theme', e.newValue); syncTheme();
      }
    });
    syncTheme();
  }

  /* ------------------------------------------------------------ sidebar groups */
  function initGroups() {
    var saved = [];
    try { saved = JSON.parse(store.get(OPEN_KEY) || '[]') || []; } catch (e) { saved = []; }
    if (!Array.isArray(saved)) saved = [];
    var grps = $$('.dc-grp');
    grps.forEach(function (g) {
      var btn = $('.dc-grp-h', g);
      if (!btn) return;
      var list = $('ul', g);
      if (list) {
        if (!list.id) list.id = 'dc-grp-' + (g.getAttribute('data-grp') || Math.random().toString(36).slice(2));
        btn.setAttribute('aria-controls', list.id);
      }
      btn.addEventListener('click', function () {
        var open = !g.classList.contains('open');
        // accordion (owner, 2026-10-11): opening one group closes every other
        if (open) grps.forEach(function (x) { if (x !== g) setGroup(x, false); });
        setGroup(g, open);
        store.set(OPEN_KEY, JSON.stringify(open ? [g.getAttribute('data-grp')] : []));
      });
    });
    // on load exactly one group is open: the one holding the current page, else the
    // last one the reader opened
    var here = grps.filter(function (g) { return $('.dc-lnk.active', g); })[0] ||
               grps.filter(function (g) { return saved.indexOf(g.getAttribute('data-grp')) >= 0; }).pop();
    grps.forEach(function (g) { setGroup(g, g === here); });
    // bring the current page into view inside the sidebar's own scroller
    var side = $('#dc-side'), act = side && $('.dc-lnk.active', side);
    if (side && act && !mqDrawer.matches) {
      var top = act.getBoundingClientRect().top - side.getBoundingClientRect().top;
      if (top > side.clientHeight * 0.7) side.scrollTop = top - side.clientHeight / 3;
    }
  }
  function setGroup(g, open) {
    g.classList.toggle('open', open);
    var b = $('.dc-grp-h', g);
    if (b) b.setAttribute('aria-expanded', open ? 'true' : 'false');
  }

  /* ------------------------------------------------------------ mobile drawer */
  function initDrawer() {
    var btn = $('.dc-menu-btn'), side = $('#dc-side'), scrim = $('.dc-scrim');
    if (!btn || !side) return;
    var lastFocus = null;
    function isOpen() { return side.classList.contains('open'); }
    function open() {
      lastFocus = d.activeElement;
      side.classList.add('open');
      if (scrim) scrim.hidden = false;
      btn.setAttribute('aria-expanded', 'true');
      d.body.classList.add('dc-lock');
      side.setAttribute('role', 'dialog');
      side.setAttribute('aria-modal', 'true');
      var target = $('.dc-lnk.active', side) || $('a, button', side);
      if (target) setTimeout(function () { target.focus({ preventScroll: false }); }, 30);
    }
    function close(restore) {
      if (!isOpen()) return;
      side.classList.remove('open');
      if (scrim) scrim.hidden = true;
      btn.setAttribute('aria-expanded', 'false');
      d.body.classList.remove('dc-lock');
      side.removeAttribute('role');
      side.removeAttribute('aria-modal');
      if (restore !== false) (lastFocus && lastFocus.focus ? lastFocus : btn).focus();
    }
    btn.addEventListener('click', function () { isOpen() ? close() : open(); });
    if (scrim) scrim.addEventListener('click', function () { close(); });
    side.addEventListener('click', function (e) {
      if (e.target.closest('a') && mqDrawer.matches) close(false);
    });
    d.addEventListener('keydown', function (e) {
      if (!isOpen()) return;
      if (e.key === 'Escape') { e.preventDefault(); close(); return; }
      if (e.key === 'Tab') {   // keep focus inside the drawer
        var f = $$('a[href], button:not([disabled])', side).filter(function (el) { return el.offsetParent !== null; });
        if (!f.length) return;
        var first = f[0], last = f[f.length - 1];
        if (e.shiftKey && d.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && d.activeElement === last) { e.preventDefault(); first.focus(); }
        else if (!side.contains(d.activeElement)) { e.preventDefault(); first.focus(); }
      }
    });
    var onMq = function () { if (!mqDrawer.matches) close(false); };
    if (mqDrawer.addEventListener) mqDrawer.addEventListener('change', onMq); else mqDrawer.addListener(onMq);
  }

  /* ------------------------------------------------------------ search: index */
  var indexP = null, IDX = null;
  function loadIndex() {
    if (!indexP) {
      indexP = fetch('search-index.json', { credentials: 'same-origin' })
        .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
        .then(function (data) { IDX = prepare(data); return IDX; })
        .catch(function (err) { indexP = null; throw err; });
    }
    return indexP;
  }
  function norm(s) {
    s = String(s || '').toLowerCase();
    return s.normalize ? s.normalize('NFD').replace(/[\u0300-\u036f]/g, '') : s;
  }
  var SPLIT = /[^a-z0-9\u00c0-\uffff]+/;
  // light English stemming so "policy" finds "policies" and "backup" finds "backups"
  function stem(w) {
    if (w.length > 4 && /ies$/.test(w)) return w.slice(0, -3) + 'y';
    if (w.length > 3 && /[^su]s$/.test(w)) return w.slice(0, -1);
    return w;
  }
  function words(s) { return norm(s).split(SPLIT).filter(Boolean).map(stem); }
  var FIELDS = [['t', 100], ['h', 55], ['k', 30], ['s', 16], ['x', 6]];
  function prepare(data) {
    var syn = Object.create(null);
    var raw = (data && data.syn) || {};
    Object.keys(raw).forEach(function (k) {
      var group = [k].concat(raw[k] || []).map(function (w) { return words(w).join(' '); }).filter(Boolean);
      group.forEach(function (w) {
        syn[w] = syn[w] || [];
        group.forEach(function (o) { if (o !== w && syn[w].indexOf(o) < 0) syn[w].push(o); });
      });
    });
    var docs = ((data && data.docs) || []).map(function (e, i) {
      var f = {};
      FIELDS.forEach(function (fw) {
        var v = e[fw[0]] || '';
        f[fw[0]] = { s: ' ' + words(v).join(' ') + ' ', w: words(v) };
      });
      var slug = String(e.u || '').split('#')[0];
      return { e: e, f: f, i: i, root: !e.h, slug: slug, slugW: words(slug.replace(/\.html$/, '')) };
    });
    return { syn: syn, docs: docs };
  }

  /* ------------------------------------------------------------ search: query */
  function parseQuery(q, idx) {
    var toks = [];
    words(q).forEach(function (t) { if (toks.indexOf(t) < 0) toks.push(t); });
    return toks.map(function (t) {
      var vars = [{ w: t, syn: false }];
      (idx.syn[t] || []).forEach(function (s) { vars.push({ w: s, syn: true }); });
      return { t: t, vars: vars };
    });
  }
  // quality of a single variant in a field: 1 exact word, .7 prefix, 0 none
  function fieldHit(field, v) {
    var w = v.w;
    if (w.indexOf(' ') >= 0) return field.s.indexOf(' ' + w + ' ') >= 0 ? 1 : 0;
    var best = 0, arr = field.w;
    for (var i = 0; i < arr.length; i++) {
      if (arr[i] === w) return 1;
      if (w.length >= 3 && arr[i].lastIndexOf(w, 0) === 0) best = 0.7;
    }
    return best;
  }
  function scoreDoc(doc, terms, phrase) {
    var total = 0, ownHit = false;
    for (var ti = 0; ti < terms.length; ti++) {
      var term = terms[ti], tScore = 0;
      for (var fi = 0; fi < FIELDS.length; fi++) {
        var key = FIELDS[fi][0], weight = FIELDS[fi][1];
        // a section entry inherits its article title; it must earn its place with its own text
        if (key === 't' && !doc.root) weight = 22;
        var best = 0;
        for (var vi = 0; vi < term.vars.length; vi++) {
          var q = fieldHit(doc.f[key], term.vars[vi]) * (term.vars[vi].syn ? 0.35 : 1);
          if (q > best) best = q;
        }
        if (best > 0) {
          tScore += weight * best;
          // an article whose short title IS the term beats a long title that merely mentions it
          if (key === 't' && doc.root && best === 1) tScore += 80 / Math.max(1, doc.f.t.w.length);
          if (key === 'h' || key === 'x') ownHit = true;
        }
      }
      if (tScore === 0) return 0;          // AND: every token must match somewhere
      total += tScore;
    }
    if (!doc.root && !ownHit) return 0;
    if (phrase) {
      if (doc.f.t.s.indexOf(phrase) >= 0) total += 120;
      if (doc.f.h.s.indexOf(phrase) >= 0) total += 70;
      if (doc.f.k.s.indexOf(phrase) >= 0) total += 30;
      if (doc.f.s.s.indexOf(phrase) >= 0 || doc.f.x.s.indexOf(phrase) >= 0) total += 20;
    }
    if (doc.root) {
      total += 4;
      // the article's own slug names the topic ("backups", "rediscovery", "error-messages")
      for (var si = 0; si < terms.length; si++) if (doc.slugW.indexOf(terms[si].t) >= 0) total += 45;
    }
    return total;
  }
  function search(q, limit) {
    var idx = IDX;
    if (!idx) return { hits: [], terms: [], total: 0 };
    var terms = parseQuery(q, idx);
    if (!terms.length) return { hits: [], terms: [], total: 0 };
    var phrase = terms.length > 1 ? ' ' + terms.map(function (t) { return t.t; }).join(' ') + ' ' : '';
    var hits = [];
    idx.docs.forEach(function (doc) {
      var s = scoreDoc(doc, terms, phrase);
      if (s > 0) hits.push({ doc: doc, score: s });
    });
    hits.sort(function (a, b) { return b.score - a.score || a.doc.i - b.doc.i; });
    // at most 3 entries per article so one long page cannot flood the list
    var per = Object.create(null), out = [];
    hits.forEach(function (h) {
      per[h.doc.slug] = (per[h.doc.slug] || 0) + 1;
      if (per[h.doc.slug] <= 3) out.push(h);
    });
    return { hits: limit ? out.slice(0, limit) : out, terms: terms, total: out.length };
  }

  /* ------------------------------------------------------------ search: rendering */
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function reEsc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  function hiRegex(terms) {
    var list = [];
    terms.forEach(function (t) { t.vars.forEach(function (v) { if (list.indexOf(v.w) < 0) list.push(v.w); }); });
    if (!list.length) return null;
    list.sort(function (a, b) { return b.length - a.length; });
    var alt = list.map(function (w) {
      if (w.length > 4) w = w.replace(/y$/, '');         // highlight "polic" → policy / policies
      return reEsc(w).replace(/ /g, '[^\\p{L}\\p{N}]+');
    }).join('|');
    try { return new RegExp('(?<![\\p{L}\\p{N}])(?:' + alt + ')[\\p{L}\\p{N}]*', 'giu'); }
    catch (e) { return new RegExp('\\b(?:' + alt + ')\\w*', 'gi'); }
  }
  // escape every slice first, then wrap the (escaped) matches in <mark>
  function highlight(text, re) {
    text = String(text || '');
    if (!re) return esc(text);
    re.lastIndex = 0;
    var out = '', last = 0, m;
    while ((m = re.exec(text))) {
      if (!m[0].length) { re.lastIndex++; continue; }
      out += esc(text.slice(last, m.index)) + '<mark>' + esc(m[0]) + '</mark>';
      last = m.index + m[0].length;
    }
    return out + esc(text.slice(last));
  }
  function snippet(e, re, len) {
    len = len || 170;
    var src = e.x || e.s || '';
    if (!src) return '';
    var at = -1;
    if (re) {
      [e.x, e.s].some(function (t) {
        if (!t) return false;
        re.lastIndex = 0;
        var m = re.exec(t);
        if (m) { src = t; at = m.index; return true; }
        return false;
      });
    }
    var start = 0;
    if (at > 50) {
      start = at - 50;
      var sp = src.indexOf(' ', start);
      if (sp > -1 && sp < at) start = sp + 1;
    }
    var end = Math.min(src.length, start + len);
    if (end < src.length) { var sp2 = src.lastIndexOf(' ', end); if (sp2 > start + 40) end = sp2; }
    var cut = src.slice(start, end);
    return (start > 0 ? '… ' : '') + highlight(cut, re) + (end < src.length ? ' …' : '');
  }
  function titleHtml(e, re) {
    return '<span class="dc-r-t">' + highlight(e.t, re) +
      (e.h ? '<span class="dc-r-sep">›</span><span class="dc-r-h">' + highlight(e.h, re) + '</span>' : '') + '</span>';
  }
  // group hits by category, groups ordered by their best hit
  function grouped(hits) {
    var order = [], map = Object.create(null);
    hits.forEach(function (h) {
      var c = h.doc.e.c || 'Other';
      if (!map[c]) { map[c] = []; order.push(c); }
      map[c].push(h);
    });
    return order.map(function (c) { return { c: c, hits: map[c] }; });
  }
  function searchUrl(q) { return 'search.html?q=' + encodeURIComponent(q.trim()); }

  /* ------------------------------------------------------------ search: bar dropdown */
  function initBarSearch() {
    var input = $('#dc-q'), box = $('#dc-results');
    if (!input || !box) return;
    var active = -1, timer = 0, lastQ = null;
    input.setAttribute('role', 'combobox');
    input.setAttribute('aria-autocomplete', 'list');
    input.setAttribute('aria-controls', 'dc-results');
    input.setAttribute('aria-expanded', 'false');
    box.setAttribute('aria-label', 'Search results');

    function opts() { return $$('[role="option"]', box); }
    function show() { box.hidden = false; input.setAttribute('aria-expanded', 'true'); }
    function hide() {
      box.hidden = true; input.setAttribute('aria-expanded', 'false');
      input.removeAttribute('aria-activedescendant'); active = -1;
    }
    function setActive(i) {
      var o = opts();
      if (!o.length) return;
      if (i < 0) i = o.length - 1;
      if (i >= o.length) i = 0;
      o.forEach(function (el, k) { el.setAttribute('aria-selected', k === i ? 'true' : 'false'); });
      active = i;
      input.setAttribute('aria-activedescendant', o[i].id);
      o[i].scrollIntoView({ block: 'nearest' });
    }
    function render() {
      var q = input.value.trim();
      if (q === lastQ && !box.hidden) return;
      lastQ = q;
      if (!q) { box.innerHTML = ''; hide(); return; }
      if (!IDX) {
        box.innerHTML = '<div class="dc-r-empty">Loading search index…</div>'; show();
        loadIndex().then(function () { lastQ = null; render(); }, function () {
          box.innerHTML = '<div class="dc-r-empty">Search is unavailable — the index could not be loaded.</div>';
        });
        return;
      }
      var res = search(q, 12), re = hiRegex(res.terms), n = 0, html = '';
      if (!res.hits.length) {
        html = '<div class="dc-r-empty">No results for <b>“' + esc(q) + '”</b>. Try fewer or different words.</div>';
      } else {
        grouped(res.hits).forEach(function (g, gi) {
          html += '<div role="group" aria-labelledby="dc-rg-' + gi + '"><div class="dc-r-grp" id="dc-rg-' + gi + '" role="presentation">' + esc(g.c) + '</div>';
          g.hits.forEach(function (h) {
            html += '<a class="dc-r-opt" role="option" aria-selected="false" tabindex="-1" id="dc-opt-' + (n++) + '" href="' + esc(h.doc.e.u) + '">' +
              titleHtml(h.doc.e, re) + '<span class="dc-r-x">' + snippet(h.doc.e, re, 140) + '</span></a>';
          });
          html += '</div>';
        });
      }
      html += '<a class="dc-r-all" role="option" aria-selected="false" tabindex="-1" id="dc-opt-' + n + '" href="' + esc(searchUrl(q)) + '">' +
        (res.total > res.hits.length ? 'See all ' + res.total + ' results' : 'See all results') + ' for “' + esc(q) + '” →</a>';
      box.innerHTML = html;
      active = -1; input.removeAttribute('aria-activedescendant');
      show();
    }
    input.addEventListener('focus', function () {
      loadIndex().catch(function () {});
      if (input.value.trim()) { lastQ = null; render(); }
    });
    input.addEventListener('input', function () {
      clearTimeout(timer); timer = setTimeout(render, 70);
    });
    input.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowDown') { e.preventDefault(); if (box.hidden) { lastQ = null; render(); } setActive(active + 1); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); setActive(active - 1); }
      else if (e.key === 'Enter') {
        e.preventDefault();
        var o = opts()[active];
        if (o) { location.href = o.getAttribute('href'); }
        else if (input.value.trim()) { location.href = searchUrl(input.value); }
      } else if (e.key === 'Escape') {
        if (!box.hidden) { e.preventDefault(); e.stopPropagation(); hide(); }
        else if (input.value) { input.value = ''; lastQ = null; }
        else input.blur();
      }
    });
    box.addEventListener('mousedown', function (e) { e.preventDefault(); });  // keep focus in the input
    box.addEventListener('mousemove', function (e) {
      var o = e.target.closest('[role="option"]');
      if (o) { var i = opts().indexOf(o); if (i !== active) setActive(i); }
    });
    d.addEventListener('click', function (e) { if (!e.target.closest('.dc-search')) hide(); });
    input.addEventListener('blur', function () { setTimeout(function () { if (d.activeElement !== input) hide(); }, 120); });
  }

  /* ------------------------------------------------------------ search: hero + page */
  function initHeroSearch() {
    var input = $('#dc-q-hero');
    if (!input) return;
    input.addEventListener('focus', function () { loadIndex().catch(function () {}); });
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && input.value.trim()) { e.preventDefault(); location.href = searchUrl(input.value); }
    });
  }
  function initPageSearch() {
    var input = $('#dc-q-page'), out = $('#dc-page-results');
    if (!input || !out) return;
    out.setAttribute('aria-live', 'polite');
    var timer = 0;
    var q0 = new URLSearchParams(location.search).get('q') || '';
    input.value = q0;
    function render() {
      var q = input.value.trim();
      try { history.replaceState(null, '', q ? searchUrl(q) : 'search.html'); } catch (e) { /* file:// */ }
      d.title = (q ? '“' + q + '” — ' : '') + 'Search — SATOM Documentation';
      if (!q) { out.innerHTML = '<p class="dc-sr-empty">Type a feature, setting, permission key or error message.</p>'; return; }
      if (!IDX) { out.innerHTML = '<p class="dc-sr-empty">Loading search index…</p>'; return; }
      var res = search(q, 0), re = hiRegex(res.terms);
      if (!res.hits.length) {
        out.innerHTML = '<p class="dc-sr-empty">No results for <b>“' + esc(q) + '”</b>. Check the spelling, use fewer words, or browse the <a href="index.html">documentation home</a>.</p>';
        return;
      }
      var html = '<p class="dc-sr-count">' + res.total + ' result' + (res.total === 1 ? '' : 's') + ' for <b>“' + esc(q) + '”</b></p>';
      grouped(res.hits).forEach(function (g) {
        html += '<h2 class="dc-sr-grp">' + esc(g.c) + ' <span>(' + g.hits.length + ')</span></h2>';
        g.hits.forEach(function (h) {
          html += '<a class="dc-sr-hit" href="' + esc(h.doc.e.u) + '">' + titleHtml(h.doc.e, re) +
            '<span class="dc-r-x">' + snippet(h.doc.e, re, 240) + '</span></a>';
        });
      });
      out.innerHTML = html;
    }
    input.addEventListener('input', function () { clearTimeout(timer); timer = setTimeout(render, 90); });
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); clearTimeout(timer); render(); var a = $('.dc-sr-hit', out); if (a && e.ctrlKey) a.click(); }
    });
    render();
    loadIndex().then(render, function () {
      out.innerHTML = '<p class="dc-sr-empty">Search is unavailable — the index could not be loaded.</p>';
    });
    if (!q0) input.focus();
  }

  /* ------------------------------------------------------------ shortcuts */
  function typing(el) {
    if (!el) return false;
    var t = el.tagName;
    return t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT' || el.isContentEditable;
  }
  function initShortcuts() {
    d.addEventListener('keydown', function (e) {
      var q = $('#dc-q');
      if (!q || e.defaultPrevented) return;
      var isK = (e.ctrlKey || e.metaKey) && !e.altKey && (e.key === 'k' || e.key === 'K');
      var isSlash = e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey && !typing(d.activeElement);
      if (isK || isSlash) { e.preventDefault(); q.focus(); q.select(); }
    });
  }

  /* ------------------------------------------------------------ TOC scrollspy */
  function initScrollspy() {
    var links = $$('.dc-toc a[href^="#"]');
    if (!links.length) return;
    var items = links.map(function (a) {
      var id = decodeURIComponent(a.getAttribute('href').slice(1));
      return { a: a, el: d.getElementById(id) };
    }).filter(function (x) { return x.el; });
    if (!items.length) return;
    var current = null, ticking = false;
    function offset() {
      var v = getComputedStyle(root).getPropertyValue('--dc-top');
      var bar = $('.dc-bar'), nav = $('body > nav');
      return (nav ? nav.offsetHeight : 0) + (bar ? bar.offsetHeight : 0) + 28 || parseInt(v, 10) || 140;
    }
    function update() {
      ticking = false;
      var y = offset(), pick = null;
      for (var i = 0; i < items.length; i++) {
        if (items[i].el.offsetParent === null) continue;          // inside a closed <details>
        if (items[i].el.getBoundingClientRect().top <= y) pick = items[i]; else break;
      }
      var atEnd = window.innerHeight + window.scrollY >= d.documentElement.scrollHeight - 4;
      if (atEnd) {
        for (var j = items.length - 1; j >= 0; j--) {
          if (items[j].el.offsetParent !== null) {
            if (items[j].el.getBoundingClientRect().top < window.innerHeight) pick = items[j];
            break;
          }
        }
      }
      if (!pick) pick = items[0];
      if (pick !== current) {
        if (current) { current.a.classList.remove('active'); current.a.removeAttribute('aria-current'); }
        pick.a.classList.add('active'); pick.a.setAttribute('aria-current', 'location');
        current = pick;
        var toc = $('.dc-toc');
        if (toc && toc.scrollHeight > toc.clientHeight) {
          var r = pick.a.getBoundingClientRect(), tr = toc.getBoundingClientRect();
          if (r.top < tr.top + 40 || r.bottom > tr.bottom - 40) toc.scrollTop += r.top - tr.top - tr.height / 3;
        }
      }
    }
    window.addEventListener('scroll', function () { if (!ticking) { ticking = true; requestAnimationFrame(update); } }, { passive: true });
    window.addEventListener('resize', update);
    update();
  }

  /* ------------------------------------------------------------ #hash inside a closed <details> */
  function revealHash() {
    var h = location.hash;
    if (!h || h.length < 2) return;
    var el;
    try { el = d.getElementById(decodeURIComponent(h.slice(1))); } catch (e) { return; }
    if (!el) return;
    var opened = false, p = el.parentElement;
    if (el.tagName === 'DETAILS' && !el.open) { el.open = true; opened = true; }
    while (p) {
      if (p.tagName === 'DETAILS' && !p.open) { p.open = true; opened = true; }
      p = p.parentElement;
    }
    if (opened) el.scrollIntoView({ block: 'start', behavior: 'instant' });
  }
  function initInlineToc() {
    $$('details.dc-toc-m a').forEach(function (a) {
      a.addEventListener('click', function () { var dt = a.closest('details'); if (dt) dt.open = false; });
    });
  }

  /* ------------------------------------------------------------ boot */
  function boot() {
    initTheme();
    initGroups();
    initDrawer();
    initBarSearch();
    initHeroSearch();
    initPageSearch();
    initShortcuts();
    initInlineToc();
    revealHash();
    window.addEventListener('hashchange', revealHash);
    initScrollspy();
  }
  if (d.readyState === 'loading') d.addEventListener('DOMContentLoaded', boot); else boot();
})();
