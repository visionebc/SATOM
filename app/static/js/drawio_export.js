/* drawio_export.js — "Export to draw.io" for every diagram in the console.
 *
 * Each diagram script describes what it has on screen (nodes with their box,
 * links between them) and hands that to SatomDrawio.wire(button, collect).
 * The file itself is written by the server (POST /diagram-export/drawio,
 * app/services/drawio_export.py), so the escaping lives in one place that the
 * tests can hold; this script only posts the description and saves the answer.
 *
 * The endpoint comes from this script tag's data-endpoint (url_for in the
 * template), so a console mounted under a prefix still reaches it.
 *
 * CSP-safe: external 'self' script, no eval, no inline handlers.
 */
(function () {
  'use strict';

  var tag = document.currentScript;
  var ENDPOINT = (tag && tag.getAttribute('data-endpoint')) || '/diagram-export/drawio';

  function csrfToken() {
    var m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.getAttribute('content') : '';
  }

  function saveBlob(blob, fname) {
    var href = window.URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = href;
    a.download = fname;
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { window.URL.revokeObjectURL(href); a.remove(); }, 1500);
  }

  /* Post the description; resolve with {skipped} once the file is saved. */
  function exportDrawio(name, model) {
    var body = JSON.stringify({ name: name || 'diagram', nodes: model.nodes || [], edges: model.edges || [] });
    return fetch(ENDPOINT, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken() },
      body: body
    }).then(function (r) {
      if (!r.ok) {
        return r.json().catch(function () { return {}; }).then(function (j) {
          throw new Error(j.error || ('HTTP ' + r.status));
        });
      }
      var skipped = parseInt(r.headers.get('X-Export-Warnings') || '0', 10) || 0;
      var m = /filename="([^"]+)"/.exec(r.headers.get('Content-Disposition') || '');
      return r.blob().then(function (b) {
        saveBlob(b, m ? m[1] : 'diagram.drawio');
        return { skipped: skipped };
      });
    });
  }

  /* collect() returns {name, nodes, edges}; it runs at click time, so the
   * file is what the page shows at that moment (layout, zoom does not matter). */
  function wire(btn, collect) {
    if (!btn || btn.getAttribute('data-drawio-wired')) return;
    btn.setAttribute('data-drawio-wired', '1');
    btn.addEventListener('click', function () {
      var d;
      try { d = collect(); } catch (e) { alert('Export to draw.io failed: ' + e.message); return; }
      if (!d || !d.nodes || !d.nodes.length) { alert('There is nothing drawn to export yet.'); return; }
      btn.disabled = true;
      exportDrawio(d.name, d).then(function (res) {
        btn.disabled = false;
        if (res.skipped) {
          alert('Exported. ' + res.skipped + ' item(s) could not be drawn in draw.io and were left out.');
        }
      }).catch(function (e) {
        btn.disabled = false;
        alert('Export to draw.io failed: ' + e.message);
      });
    });
  }

  window.SatomDrawio = { exportDrawio: exportDrawio, wire: wire };
})();
