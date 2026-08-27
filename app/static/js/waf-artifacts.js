/* WAF fleet artifacts — six charts over one payload.
 *
 * Separate file from waf.js on purpose: that renderer binds #waf-root and its
 * own six canvas ids, and a single file that guards on both roots would run
 * one page's error handling for the other page's failure.
 *
 * The three rules are the same and are not negotiable here either:
 *   1. THE PAGE IS LIGHT (fortiweb.css has no dark mode). Every colour comes
 *      from the .fw-badge-* set, calibrated against #FFFFFF (safeguards §9m).
 *   2. A FAILED FETCH IS NOT AN EMPTY CHART — on a canvas they look identical
 *      and mean opposite things, so an error paints a message.
 *   3. No second copy of the numbers: everything drawn here is what
 *      /waf/api/artifacts.json served, which is what the server-rendered
 *      tables were built from.
 */
(function () {
  'use strict';

  var root = document.getElementById('waf-art-root');
  if (!root || typeof Chart === 'undefined') { return; }

  var C = {
    green: '#15692A', amber: '#7A5700', red: '#8B1C2A',
    grey: '#3D4550', purple: '#4C2A85', blue: '#1D4ED8', accent: '#EF5424'
  };
  /* Worst -> best, and the SAME colour for the same verdict everywhere on the
     page: a "blocked" that is red in one chart and grey in the next is two
     vocabularies. */
  var VERDICT = {
    'blocked': C.red, 'at-risk': C.amber, 'borrowed': C.purple, 'ok': C.green
  };
  var ORDER = ['blocked', 'at-risk', 'borrowed', 'ok'];
  var LABEL = {
    'blocked': 'Blocked', 'at-risk': 'At risk',
    'borrowed': 'Borrowed', 'ok': 'Held'
  };
  var GRID = 'rgba(15,23,42,0.10)';
  var TICK = '#3D4550';
  var IDS = ['waf-art-chart-readiness', 'waf-art-chart-scopes',
             'waf-art-chart-kinds', 'waf-art-chart-store',
             'waf-art-chart-sweep', 'waf-art-chart-growth'];
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
    // ------------------------------------------------------- readiness --
    var ready = data.readiness || [];
    var total = ready.reduce(function (a, r) { return a + (r.value || 0); }, 0);
    if (!total) {
      // Zero NEEDS is not zero data: it means no walked policy in this fleet
      // references a file-backed object. An empty doughnut would read as a
      // broken chart, which is a different claim.
      fail('waf-art-chart-readiness',
           'No walked policy in this fleet references a file-backed object yet.');
    } else {
      draw('waf-art-chart-readiness', {
        type: 'doughnut',
        data: {
          labels: ready.map(function (r) { return r.label; }),
          datasets: [{
            data: ready.map(function (r) { return r.value; }),
            backgroundColor: ready.map(function (r) { return VERDICT[r.key] || C.grey; }),
            borderColor: '#FFFFFF', borderWidth: 2
          }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: legend() }
      });
    }

    // --------------------------------------------------- objects/scope --
    var scopes = data.per_scope || [];
    draw('waf-art-chart-scopes', {
      type: 'bar',
      data: {
        labels: scopes.map(function (s) { return s.scope; }),
        datasets: ORDER.map(function (k) {
          return { label: LABEL[k], backgroundColor: VERDICT[k],
                   data: scopes.map(function (s) { return s[k] || 0; }) };
        })
      },
      options: {
        responsive: true, maintainAspectRatio: false, plugins: legend(),
        scales: axes({ x: { stacked: true }, y: { stacked: true } })
      }
    });

    // ------------------------------------------------------- by type ----
    var kinds = data.by_kind || [];
    if (!kinds.length) {
      fail('waf-art-chart-kinds',
           'No object type is referenced or stored anywhere in this fleet.');
    } else {
      draw('waf-art-chart-kinds', {
        type: 'bar',
        data: {
          labels: kinds.map(function (k) { return k.label; }),
          datasets: ORDER.map(function (key) {
            return { label: LABEL[key], backgroundColor: VERDICT[key],
                     data: kinds.map(function (k) { return k[key] || 0; }) };
          }).concat([{
            label: 'Orphan copy', backgroundColor: C.grey,
            data: kinds.map(function (k) { return k.orphan || 0; })
          }])
        },
        options: {
          indexAxis: 'y', responsive: true, maintainAspectRatio: false,
          plugins: legend(), scales: axes({ x: { stacked: true }, y: { stacked: true } })
        }
      });
    }

    // --------------------------------------------------------- store ----
    var stored = kinds.filter(function (k) { return k.versions > 0; });
    if (!stored.length) {
      fail('waf-art-chart-store', 'The artifact store holds nothing for these scopes.');
    } else {
      draw('waf-art-chart-store', {
        type: 'doughnut',
        data: {
          labels: stored.map(function (k) { return k.label; }),
          datasets: [{
            data: stored.map(function (k) { return k.versions; }),
            backgroundColor: [C.blue, C.purple, C.green, C.amber, C.accent,
                              C.grey, C.red],
            borderColor: '#FFFFFF', borderWidth: 2
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: {
            legend: legend().legend,
            tooltip: { callbacks: { label: function (ctx) {
              var k = stored[ctx.dataIndex];
              return k.label + ': ' + k.versions + ' versions, ' + k.bytes + ' bytes';
            } } }
          }
        }
      });
    }

    // --------------------------------------------------------- sweep ----
    // Only scopes whose configuration total is KNOWN. A scope with no snapshot
    // has no denominator, and drawing it as "0 unwalked" would report the one
    // thing this page must never claim.
    var known = scopes.filter(function (s) { return s.in_config !== null; });
    if (!known.length) {
      fail('waf-art-chart-sweep',
           'No scope has both a configuration snapshot and a sweep record, so coverage cannot be computed.');
    } else {
      draw('waf-art-chart-sweep', {
        type: 'bar',
        data: {
          labels: known.map(function (s) { return s.scope; }),
          datasets: [
            { label: 'walked', backgroundColor: C.green,
              data: known.map(function (s) { return s.walked || 0; }) },
            { label: 'never walked', backgroundColor: C.red,
              data: known.map(function (s) { return s.unwalked || 0; }) }
          ]
        },
        options: {
          indexAxis: 'y', responsive: true, maintainAspectRatio: false,
          plugins: legend(),
          scales: axes({ x: { stacked: true }, y: { stacked: true } })
        }
      });
    }

    // -------------------------------------------------------- growth ----
    var g = data.growth || { labels: [], values: [] };
    draw('waf-art-chart-growth', {
      type: 'line',
      data: {
        labels: g.labels,
        datasets: [{
          label: 'artifact versions stored', data: g.values,
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
      IDS.forEach(function (id) {
        fail(id, 'Could not load the fleet artifact summary (' + err.message + ').');
      });
    });

  document.addEventListener('turbo:before-render', function () {
    charts.forEach(function (c) { try { c.destroy(); } catch (e) { /* gone */ } });
    charts = [];
  }, { once: true });
})();
