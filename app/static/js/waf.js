/* WAF fleet overview — six charts over one payload.
 *
 * Chart.js is already global (base.html vendors it; this product installs into
 * isolated management networks, so a CDN chart is a chart that does not draw
 * where it matters).
 *
 * Three rules this renderer must not break:
 *   1. THE PAGE IS LIGHT. fortiweb.css has no dark mode — grid lines at 7% of
 *      slate are invisible on #FFFFFF, and the pastel status colours that read
 *      on a dark slab drop to ~1.4:1 here (safeguards §9m). Every colour below
 *      comes from the .fw-badge-* set, which is calibrated against white.
 *   2. A FAILED FETCH IS NOT AN EMPTY CHART. On a canvas the two look
 *      identical and mean opposite things, so an error paints a message.
 *   3. Nothing is drawn from a second copy of the numbers. Everything here is
 *      what /waf/api/summary.json served, which is what the server-rendered
 *      tables were built from.
 */
(function () {
  'use strict';

  var root = document.getElementById('waf-root');
  if (!root || typeof Chart === 'undefined') { return; }

  // Calibrated against white — the same values as .fw-badge-*.
  var C = {
    green: '#15692A', amber: '#7A5700', red: '#8B1C2A',
    grey: '#3D4550', purple: '#4C2A85', blue: '#1D4ED8', accent: '#EF5424'
  };
  var POSTURE = {
    'blocking': C.green, 'detection': C.amber,
    'no-profile': C.red, 'disabled': C.grey
  };
  var GRID = 'rgba(15,23,42,0.10)';
  var TICK = '#3D4550';
  var charts = [];

  function axes(extra) {
    var base = {
      x: { grid: { color: GRID }, ticks: { color: TICK, font: { size: 11 } } },
      y: { grid: { color: GRID }, ticks: { color: TICK, font: { size: 11 } },
           beginAtZero: true }
    };
    if (extra && extra.x) { Object.assign(base.x, extra.x); }
    if (extra && extra.y) { Object.assign(base.y, extra.y); }
    return base;
  }

  function legend(position) {
    return { legend: { position: position || 'bottom',
                       labels: { color: TICK, boxWidth: 12, font: { size: 11 } } } };
  }

  function fail(canvasId, message) {
    var cv = document.getElementById(canvasId);
    if (!cv || !cv.parentNode) { return; }
    var box = document.createElement('div');
    box.className = 'waf-chart-error';
    box.textContent = message;
    cv.parentNode.replaceChild(box, cv);
  }

  function draw(canvasId, config) {
    var cv = document.getElementById(canvasId);
    if (!cv) { return; }
    charts.push(new Chart(cv.getContext('2d'), config));
  }

  function render(data) {
    // ---------------------------------------------------------- posture --
    var posture = data.posture || [];
    draw('waf-chart-posture', {
      type: 'doughnut',
      data: {
        labels: posture.map(function (p) { return p.label; }),
        datasets: [{
          data: posture.map(function (p) { return p.value; }),
          backgroundColor: posture.map(function (p) { return POSTURE[p.key] || C.grey; }),
          borderColor: '#FFFFFF', borderWidth: 2
        }]
      },
      options: { responsive: true, maintainAspectRatio: false, plugins: legend() }
    });

    // ------------------------------------------------- policies by scope --
    var scopes = (data.per_scope || []).filter(function (s) { return !s.missing; });
    draw('waf-chart-scopes', {
      type: 'bar',
      data: {
        labels: scopes.map(function (s) { return s.scope; }),
        datasets: posture.map(function (p) {
          return {
            label: p.label,
            data: scopes.map(function (s) { return s[p.key] || 0; }),
            backgroundColor: POSTURE[p.key] || C.grey
          };
        })
      },
      options: {
        responsive: true, maintainAspectRatio: false, plugins: legend(),
        scales: axes({ x: { stacked: true }, y: { stacked: true } })
      }
    });

    // --------------------------------------------------------- coverage --
    // Only protections that ARE applicable somewhere. A slot no profile in
    // this fleet carries would otherwise draw a 0% bar, which reads as a gap
    // rather than as a question nobody asked.
    var cov = (data.coverage || [])
      .filter(function (c) { return c.applicable > 0; })
      .sort(function (a, b) { return a.pct - b.pct; });
    if (!cov.length) {
      fail('waf-chart-coverage',
           'No policy in this ADOM resolves a web protection profile, so there is no coverage to plot.');
    } else {
      draw('waf-chart-coverage', {
        type: 'bar',
        data: {
          labels: cov.map(function (c) { return c.label; }),
          datasets: [{
            label: '% of applicable policies',
            data: cov.map(function (c) { return c.pct; }),
            backgroundColor: cov.map(function (c) {
              return c.pct === 0 ? C.red : (c.pct >= 90 ? C.green : C.amber);
            })
          }]
        },
        options: {
          indexAxis: 'y', responsive: true, maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: { callbacks: { label: function (ctx) {
              var c = cov[ctx.dataIndex];
              return c.on + ' / ' + c.applicable + ' policies (' + c.pct + '%)';
            } } }
          },
          scales: axes({ x: { max: 100 } })
        }
      });
    }

    // ----------------------------------------------------------- crypto --
    var crypto = data.crypto || [];
    draw('waf-chart-crypto', {
      type: 'doughnut',
      data: {
        labels: crypto.map(function (c) { return c.label; }),
        datasets: [{
          data: crypto.map(function (c) { return c.value; }),
          backgroundColor: [C.green, C.amber, C.grey],
          borderColor: '#FFFFFF', borderWidth: 2
        }]
      },
      options: { responsive: true, maintainAspectRatio: false, plugins: legend() }
    });

    // ------------------------------------------------------- signatures --
    var sig = (data.signatures || []).slice(0, 8);
    draw('waf-chart-signatures', {
      type: 'bar',
      data: {
        labels: sig.map(function (s) { return s.name; }),
        datasets: [{ label: 'policies', data: sig.map(function (s) { return s.value; }),
                     backgroundColor: C.purple }]
      },
      options: {
        indexAxis: 'y', responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } }, scales: axes()
      }
    });

    // ---------------------------------------------------------- changes --
    var ch = data.changes || { labels: [], values: [] };
    draw('waf-chart-changes', {
      type: 'line',
      data: {
        labels: ch.labels,
        datasets: [{
          label: 'config versions minted', data: ch.values,
          borderColor: C.accent, backgroundColor: 'rgba(239,84,36,0.12)',
          fill: true, tension: 0.25, pointRadius: 2
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: axes({ y: { ticks: { precision: 0, color: TICK } } })
      }
    });
  }

  fetch(root.dataset.summary, { headers: { 'Accept': 'application/json' } })
    .then(function (r) {
      if (!r.ok) { throw new Error('HTTP ' + r.status); }
      return r.json();
    })
    .then(render)
    .catch(function (err) {
      ['waf-chart-posture', 'waf-chart-scopes', 'waf-chart-coverage',
       'waf-chart-crypto', 'waf-chart-signatures', 'waf-chart-changes']
        .forEach(function (id) {
          fail(id, 'Could not load the fleet summary (' + err.message + ').');
        });
    });

  // Turbo swaps the body without a reload; a chart bound to a detached canvas
  // leaks and keeps its resize listener alive.
  document.addEventListener('turbo:before-render', function () {
    charts.forEach(function (c) { try { c.destroy(); } catch (e) { /* gone */ } });
    charts = [];
  }, { once: true });
})();
