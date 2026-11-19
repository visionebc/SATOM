/* satom_to_studio.js — "Open in Diagram Studio" on the live diagrams.
 *
 * Architecture (netarch.js) and the Service Diagram (fleet_map.js) describe
 * what they show in the same neutral shape their "Export to draw.io" posts
 * (drawio_export.js). This script posts that description to
 * POST /diagram-studio/api/from-satom (views/diagram_studio.api_from_satom),
 * which turns it into a new Diagram Studio diagram, and then opens the editor.
 *
 *   SatomStudio.wire(button, source, collect)
 *     source:  'architecture' | 'service-diagram'
 *     collect: () -> {name, title?, sourceId?, nodes, edges}; runs at click
 *              time, so the copy is what the page shows at that moment.
 *
 * The endpoint comes from this script tag's data-endpoint (url_for in the
 * template). CSP-safe: external 'self' script, no eval, no inline handlers.
 */
(function () {
  'use strict';

  var tag = document.currentScript;
  var ENDPOINT = (tag && tag.getAttribute('data-endpoint')) || '/diagram-studio/api/from-satom';

  function csrfToken() {
    var m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.getAttribute('content') : '';
  }

  function copy(source, d) {
    var body = JSON.stringify({
      name: d.title || '', source: source, source_id: d.sourceId || null,
      payload: { name: d.name || '', nodes: d.nodes || [], edges: d.edges || [] }
    });
    return fetch(ENDPOINT, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken() },
      body: body
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok || !j.url) throw new Error(j.error || ('HTTP ' + r.status));
        return j;
      });
    });
  }

  function wire(btn, source, collect) {
    if (!btn || btn.getAttribute('data-studio-wired')) return;
    btn.setAttribute('data-studio-wired', '1');
    btn.addEventListener('click', function () {
      var d;
      try { d = collect(); } catch (e) { alert('Open in Diagram Studio failed: ' + e.message); return; }
      if (!d || !d.nodes || !d.nodes.length) { alert('There is nothing drawn to copy yet.'); return; }
      btn.disabled = true;
      copy(source, d).then(function (j) {
        window.location.assign(j.url);
      }).catch(function (e) {
        btn.disabled = false;
        alert('Open in Diagram Studio failed: ' + e.message);
      });
    });
  }

  window.SatomStudio = { copy: copy, wire: wire };
})();
