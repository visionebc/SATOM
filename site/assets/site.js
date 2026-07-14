/* OFortMAut site — progressive enhancement (no external deps) */
(function () {
  'use strict';

  // --- scroll reveal ---
  var reveals = document.querySelectorAll('.reveal');
  if ('IntersectionObserver' in window && reveals.length) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); }
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });
    reveals.forEach(function (el) { io.observe(el); });
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

  // --- current year ---
  var y = document.querySelectorAll('.year');
  y.forEach(function (el) { el.textContent = new Date().getFullYear(); });
})();
