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
