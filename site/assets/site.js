/* SATOM site — progressive enhancement (no external deps) */
(function () {
  'use strict';

  // Tells the head bootstrap that the code able to UN-hide .reveal actually
  // ran. If this file 404s or is served stale, the bootstrap drops html.js
  // after 2.5 s and the CSS falls back to showing everything.
  window.__satomReveal = true;

  // --- scroll reveal ---
  var reveals = document.querySelectorAll('.reveal');
  if ('IntersectionObserver' in window && reveals.length) {
    // threshold MUST stay 0. The ratio is intersecting-area / ELEMENT-area, so a
    // section taller than the viewport can never reach a fractional threshold and
    // would stay invisible for ever however far you scroll. A documentation page
    // is many viewports tall: 0.12 blanked every long manual on the site.
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); }
      });
    }, { threshold: 0, rootMargin: '0px 0px -40px 0px' });
    reveals.forEach(function (el) { io.observe(el); });
    // Safety net: anything already on screen that the observer never reported is
    // shown anyway. Scoped to the viewport so below-the-fold sections keep their
    // scroll animation instead of all firing at once.
    window.addEventListener('load', function () {
      setTimeout(function () {
        reveals.forEach(function (el) {
          if (!el.classList.contains('in') &&
              el.getBoundingClientRect().top < window.innerHeight) {
            el.classList.add('in');
          }
        });
      }, 400);
    });
  } else {
    reveals.forEach(function (el) { el.classList.add('in'); });
  }

  // --- mobile nav toggle ---
  var nav = document.querySelector('nav');
  var toggle = document.getElementById('nav-toggle');
  if (toggle && nav) {
    toggle.addEventListener('click', function () { nav.classList.toggle('open'); });
    nav.querySelectorAll('.nav-links a').forEach(function (a) {
      a.addEventListener('click', function () { nav.classList.remove('open'); });
    });
  }

  // --- TOC scrollspy (features page) ---
  var tocLinks = Array.prototype.slice.call(document.querySelectorAll('.toc a[href^="#"]'));
  if (tocLinks.length && 'IntersectionObserver' in window) {
    var map = {};
    tocLinks.forEach(function (a) {
      var t = document.getElementById(a.getAttribute('href').slice(1));
      if (t) map[t.id] = a;
    });
    var spy = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) {
          tocLinks.forEach(function (a) { a.classList.remove('active'); });
          if (map[e.target.id]) map[e.target.id].classList.add('active');
        }
      });
    }, { rootMargin: '-84px 0px -70% 0px', threshold: 0 });
    Object.keys(map).forEach(function (id) { spy.observe(document.getElementById(id)); });
  }

  // --- screenshots: empty-state detection + lightbox ---
  var frames = Array.prototype.slice.call(document.querySelectorAll('.shot .frame'));
  if (frames.length) {
    // build a single lightbox overlay
    var lb = document.createElement('div');
    lb.className = 'lb';
    lb.innerHTML = '<button class="lb-close" aria-label="Close">✕</button><img alt="">';
    document.body.appendChild(lb);
    var lbImg = lb.querySelector('img');
    function closeLb() { lb.classList.remove('open'); lbImg.src = ''; }
    lb.addEventListener('click', function (e) { if (e.target === lb || e.target.classList.contains('lb-close')) closeLb(); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeLb(); });

    frames.forEach(function (fr) {
      var img = fr.querySelector('img[data-shot]');
      if (img) {
        var markEmpty = function () { fr.classList.add('is-empty'); };
        var markReady = function () { if (img.naturalWidth > 0) fr.classList.remove('is-empty'); };
        if (img.complete) { if (img.naturalWidth === 0) markEmpty(); else markReady(); }
        img.addEventListener('error', markEmpty);
        img.addEventListener('load', markReady);
      }
      fr.addEventListener('click', function (e) {
        e.preventDefault();
        if (fr.classList.contains('is-empty')) return;
        var href = fr.getAttribute('href') || (img && img.getAttribute('src'));
        if (!href) return;
        lbImg.src = href; lb.classList.add('open');
      });
    });
  }

  // --- back to top ---
  var top = document.getElementById('top');
  if (top) {
    window.addEventListener('scroll', function () {
      if (window.scrollY > 560) top.classList.add('show'); else top.classList.remove('show');
    }, { passive: true });
  }

  // --- theme picker ---
  // The <head> bootstrap already applied the stored theme; this only wires the
  // buttons and keeps their pressed state in sync.
  var THEMES = ['aurora', 'abyss', 'classic'];
  var KEY = 'satom.site.theme';
  function currentTheme() {
    var t = document.documentElement.getAttribute('data-theme');
    return THEMES.indexOf(t) >= 0 ? t : 'aurora';
  }
  function applyTheme(name) {
    if (THEMES.indexOf(name) < 0) { name = 'aurora'; }
    document.documentElement.setAttribute('data-theme', name);
    try { localStorage.setItem(KEY, name); } catch (e) { /* private mode */ }
    document.querySelectorAll('[data-theme-set]').forEach(function (b) {
      b.setAttribute('aria-pressed', String(b.getAttribute('data-theme-set') === name));
    });
  }
  var picks = document.querySelectorAll('[data-theme-set]');
  if (picks.length) {
    applyTheme(currentTheme());
    picks.forEach(function (b) {
      b.addEventListener('click', function () { applyTheme(b.getAttribute('data-theme-set')); });
    });
  }

  // --- current year ---
  var y = document.querySelectorAll('.year');
  y.forEach(function (el) { el.textContent = new Date().getFullYear(); });

  // -------------------------------------------------------------------------
  // Search — the manual hub and the release notes
  //
  // Both indexes are inlined as <script type="application/json"> by their
  // generator. Inlined, not fetched: this site is published to a static host
  // we do not configure, and the publication leak scan only sees what the
  // build returns — an index shipped as a side asset would bypass it.
  //
  // Everything below degrades to "no search box behaviour" if the index is
  // missing or malformed. It never hides content it cannot replace: the
  // browsable list is only hidden while a query is actually active.
  // -------------------------------------------------------------------------
  function readIndex(id) {
    var el = document.getElementById(id);
    if (!el) { return null; }
    try { return JSON.parse(el.textContent); } catch (e) { return null; }
  }

  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }

  // Terms are ANDed. "trust store" should find a heading that contains both
  // words, not every page that mentions either one — an OR search over 27
  // documents returns everything and is the same as no search at all.
  function terms(q) {
    return q.toLowerCase().split(/\s+/).filter(function (t) { return t.length > 0; });
  }

  function hits(hay, ts) {
    var low = hay.toLowerCase();
    for (var i = 0; i < ts.length; i++) {
      if (low.indexOf(ts[i]) < 0) { return false; }
    }
    return true;
  }

  function mark(text, ts) {
    var out = esc(text);
    ts.forEach(function (t) {
      var re = new RegExp('(' + t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'ig');
      out = out.replace(re, '<mark>$1</mark>');
    });
    return out;
  }

  function wireClear(input, btn, onChange) {
    if (!btn) { return; }
    btn.addEventListener('click', function () {
      input.value = '';
      btn.hidden = true;
      onChange();
      input.focus();
    });
  }

  // --- manual hub ---
  var docIdx = readIndex('docsearch-index');
  var docIn = document.getElementById('docsearch-input');
  var docOut = document.getElementById('docsearch-results');
  if (docIdx && docIn && docOut) {
    var docHint = document.getElementById('docsearch-hint');
    var docHintText = docHint ? docHint.textContent : '';
    var docBrowse = Array.prototype.slice.call(
      document.querySelectorAll('[data-search-hide]'));
    var docClear = document.getElementById('docsearch-clear');

    var runDocs = function () {
      var q = docIn.value.trim();
      if (docClear) { docClear.hidden = q.length === 0; }
      if (!q) {
        docOut.hidden = true;
        docOut.innerHTML = '';
        // Also force `.in`: these sections are `.reveal`, and a block that was
        // display:none while the intersection observer ran was never observed
        // and would come back at opacity 0 forever. A search must never be
        // able to leave the page it filtered permanently blank.
        docBrowse.forEach(function (el) { el.hidden = false; el.classList.add('in'); });
        if (docHint) { docHint.textContent = docHintText; }
        return;
      }
      var ts = terms(q);
      var html = '';
      var n = 0;
      docIdx.forEach(function (d) {
        var docHit = hits(d.t + ' ' + d.b + ' ' + d.g, ts);
        var heads = d.h.filter(function (h) { return hits(h.t, ts); });
        if (!docHit && !heads.length) { return; }
        html += '<div class="ss-group">' + esc(d.i) + ' ' + esc(d.t) + '</div>';
        if (docHit) {
          n++;
          html += '<a class="ss-hit" href="docs/' + encodeURIComponent(d.s) + '.html">'
                + '<span class="ss-hit-t">' + mark(d.t, ts) + '</span>'
                + '<span class="ss-hit-x">' + mark(d.b, ts) + '</span></a>';
        }
        heads.slice(0, 12).forEach(function (h) {
          n++;
          html += '<a class="ss-hit" href="docs/' + encodeURIComponent(d.s) + '.html#'
                + encodeURIComponent(h.a) + '">'
                + '<span class="ss-hit-t">' + mark(h.t, ts) + '</span>'
                + '<span class="ss-hit-w">in ' + esc(d.t) + '</span></a>';
        });
      });
      docOut.innerHTML = html || '<p class="ss-empty">No section of the manual matches '
        + '<b>' + esc(q) + '</b>. Try a single word — the search ANDs every term.</p>';
      docOut.hidden = false;
      docBrowse.forEach(function (el) { el.hidden = true; });
      if (docHint) {
        docHint.textContent = n + (n === 1 ? ' match' : ' matches') + ' for “' + q + '”';
      }
    };

    docIn.addEventListener('input', runDocs);
    wireClear(docIn, docClear, runDocs);
    docIn.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { docIn.value = ''; runDocs(); }
    });
  }

  // --- release notes ---
  var relIdx = readIndex('relsearch-index');
  var relIn = document.getElementById('relsearch-input');
  var relOut = document.getElementById('relsearch-results');
  if (relIdx && relIn && relOut) {
    var relPanel = document.getElementById('rel-panel');
    var relItems = Array.prototype.slice.call(document.querySelectorAll('.rel-nav-item'));
    var relClear = document.getElementById('relsearch-clear');

    var runRel = function () {
      var q = relIn.value.trim();
      if (relClear) { relClear.hidden = q.length === 0; }
      if (!q) {
        relOut.hidden = true;
        relOut.innerHTML = '';
        if (relPanel) { relPanel.hidden = false; }
        relItems.forEach(function (el) { el.hidden = false; });
        return;
      }
      var ts = terms(q);
      var seen = {};
      var html = '';
      var n = 0;
      relIdx.forEach(function (r) {
        if (!hits(r.t + ' ' + r.x + ' ' + r.k + ' ' + r.v, ts)) { return; }
        n++;
        seen[r.v] = true;
        if (n > 200) { return; }
        var href = 'releases/' + encodeURIComponent(r.s) + '.html'
                 + (r.a ? '#' + encodeURIComponent(r.a) : '');
        html += '<a class="ss-hit" href="' + href + '">'
              + '<span class="ss-hit-t"><span class="ss-tag">v' + esc(r.v) + '</span>'
              + mark(r.t, ts) + '</span>'
              + '<span class="ss-hit-x">' + mark(r.x, ts) + '</span>'
              + '<span class="ss-hit-w">' + esc(r.k || 'Changes')
              + (r.d ? ' · released ' + esc(r.d) : ' · not yet released') + '</span></a>';
      });
      if (n) {
        var head = '<div class="ss-group">' + n + (n === 1 ? ' change' : ' changes')
                 + ' across ' + Object.keys(seen).length + ' release'
                 + (Object.keys(seen).length === 1 ? '' : 's') + '</div>';
        html = head + html + (n > 200 ? '<p class="ss-empty">Showing the first 200.</p>' : '');
      } else {
        html = '<p class="ss-empty">No change matches <b>' + esc(q) + '</b>.</p>';
      }
      relOut.innerHTML = html;
      relOut.hidden = false;
      if (relPanel) { relPanel.hidden = true; }
      // The rail keeps only the versions that actually contain a hit, so the
      // left side answers "which releases is this in?" without reading results.
      relItems.forEach(function (el) {
        el.hidden = !seen[el.getAttribute('data-rel-version')];
      });
    };

    relIn.addEventListener('input', runRel);
    wireClear(relIn, relClear, runRel);
    relIn.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { relIn.value = ''; runRel(); }
    });

    // A version page has no index of its own (it would be the same 200 KB on
    // every one of them); its sidebar form submits here instead. Honour the
    // query it arrives with, so that hop is invisible.
    try {
      var pre = new URLSearchParams(window.location.search).get('q');
      if (pre) { relIn.value = pre; runRel(); }
    } catch (e) { /* no URLSearchParams: the box still works when typed in */ }
  }
})();
