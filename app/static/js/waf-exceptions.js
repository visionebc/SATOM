/* WAF fleet exceptions — five charts over one payload.
 *
 * Its own file rather than a branch inside waf-artifacts.js: that renderer
 * binds #waf-art-root and its own canvas ids, and one file guarding on both
 * roots would run this page's error handling for the other page's failure.
 *
 * The three rules that hold everywhere in this product:
 *   1. THE PAGE IS LIGHT (fortiweb.css has no dark mode). Every colour comes
 *      from the .fw-badge-* set, calibrated against #FFFFFF (safeguards §9m).
 *   2. A FAILED FETCH IS NOT AN EMPTY CHART — on a canvas the two are
 *      indistinguishable and mean opposite things, so an error paints words.
 *   3. No second copy of the numbers: everything drawn is what
 *      /waf/api/exceptions.json served, which is what the server-rendered
 *      tables were built from.
 */
(function () {
  'use strict';

  var root = document.getElementById('waf-exc-root');
  if (!root || typeof Chart === 'undefined') { return; }

  var C = {
    green: '#15692A', amber: '#7A5700', red: '#8B1C2A',
    grey: '#3D4550', purple: '#4C2A85', blue: '#1D4ED8', accent: '#EF5424'
  };
  /* Narrow -> wide. The same bucket keeps the same colour in every chart on
     the page: a "one scope" that is grey here and amber there is two
     vocabularies for one fact. */
  var SPREAD = { 'one scope': C.grey, 'some scopes': C.amber, 'everywhere': C.green };
  var GRID = 'rgba(15,23,42,0.10)';
  var TICK = '#3D4550';
  var IDS = ['waf-exc-chart-spread', 'waf-exc-chart-types',
             'waf-exc-chart-scopes', 'waf-exc-chart-category',
             'waf-exc-chart-recoverable'];

  function fail(msg) {
    IDS.forEach(function (id) {
      var cv = document.getElementById(id);
      if (!cv) { return; }
      var ctx = cv.getContext('2d');
      ctx.clearRect(0, 0, cv.width, cv.height);
      ctx.fillStyle = C.red;
      ctx.font = '13px system-ui, sans-serif';
      ctx.textAlign = 'center';
      /* Words, not a blank canvas. An empty chart and a broken one look the
         same and mean opposite things. */
      ctx.fillText(msg, cv.width / 2, cv.height / 2);
    });
  }

  function labels(series) { return series.map(function (p) { return p.label; }); }
  function values(series) { return series.map(function (p) { return p.value; }); }

  function bar(id, series, colour, horizontal) {
    var cv = document.getElementById(id);
    if (!cv) { return; }
    new Chart(cv, {
      type: 'bar',
      data: {
        labels: labels(series),
        datasets: [{
          data: values(series),
          backgroundColor: series.map(function (p) {
            return typeof colour === 'function' ? colour(p) : colour;
          }),
          borderWidth: 0
        }]
      },
      options: {
        indexAxis: horizontal ? 'y' : 'x',
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: GRID }, ticks: { color: TICK, precision: 0 } },
          y: { grid: { color: GRID }, ticks: { color: TICK, precision: 0 } }
        }
      }
    });
  }

  function doughnut(id, series, colours) {
    var cv = document.getElementById(id);
    if (!cv) { return; }
    new Chart(cv, {
      type: 'doughnut',
      data: {
        labels: labels(series),
        datasets: [{ data: values(series), backgroundColor: colours, borderWidth: 0 }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { color: TICK } } }
      }
    });
  }

  fetch(root.getAttribute('data-feed'), { credentials: 'same-origin' })
    .then(function (r) {
      if (!r.ok) { throw new Error('HTTP ' + r.status); }
      return r.json();
    })
    .then(function (d) {
      doughnut('waf-exc-chart-spread', d.spread,
               d.spread.map(function (p) { return SPREAD[p.label] || C.grey; }));
      /* Horizontal: type labels are sentences ("Signature Exception (per-id)")
         and vertical ticks truncate them to something no operator can match
         against the filter dropdown. */
      bar('waf-exc-chart-types', d.by_type, C.accent, true);
      bar('waf-exc-chart-scopes', d.per_scope, C.blue, true);
      doughnut('waf-exc-chart-category', d.by_category, [C.blue, C.purple]);
      doughnut('waf-exc-chart-recoverable', d.recoverable, [C.green, C.amber]);
    })
    .catch(function (e) { fail('Could not load chart data — ' + e.message); });
}());
