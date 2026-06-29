/* Lease-lock guard (Phase 4). Drop a
     <div id="lock-guard" data-appliance-id="N" data-resource-key="kind:name"></div>
   on any edit page and include this script. It acquires a short lease, beats a
   heartbeat every 30s, releases on unload, and — if another user holds the
   lease — shows a banner + a "Take over" button and blocks saves. */
(function () {
  var el = document.getElementById('lock-guard');
  if (!el) return;
  var aid = el.getAttribute('data-appliance-id');
  var key = el.getAttribute('data-resource-key');
  if (!aid || !key) return;

  var blocked = false;
  var hbTimer = null;

  function post(path, cb) {
    fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ appliance_id: parseInt(aid, 10), resource_key: key })
    }).then(function (r) { return r.json(); }).then(cb).catch(function () {});
  }

  function banner(html, danger) {
    var b = document.getElementById('lock-banner');
    if (!b) {
      b = document.createElement('div');
      b.id = 'lock-banner';
      b.className = 'alert ' + (danger ? 'alert-warning' : 'alert-info') +
                    ' d-flex justify-content-between align-items-center';
      el.parentNode.insertBefore(b, el);
    }
    b.className = 'alert ' + (danger ? 'alert-warning' : 'alert-info') +
                  ' d-flex justify-content-between align-items-center';
    b.innerHTML = html;
  }

  function clearBanner() {
    var b = document.getElementById('lock-banner');
    if (b) b.remove();
  }

  function startHeartbeat() {
    if (hbTimer) return;
    hbTimer = setInterval(function () {
      post('/api/locks/heartbeat', function (j) {
        if (!j || !j.ok) { onLost(); }
      });
    }, 30000);
  }

  function onLost() {
    clearInterval(hbTimer); hbTimer = null;
    blocked = true;
    banner('<span>⚠ Your edit lock was lost (expired or taken). Reload before saving.</span>' +
           '<button type="button" class="btn btn-sm btn-outline-dark" onclick="location.reload()">Reload</button>', true);
  }

  function takeOver() {
    post('/api/locks/steal', function (j) {
      if (j && j.ok) { blocked = false; clearBanner(); startHeartbeat(); }
    });
  }
  window.__lockTakeOver = takeOver;

  function onHeld(info) {
    blocked = true;
    var who = (info && info.owner_label) || 'another user';
    banner('<span>🔒 Being edited by <strong>' + who + '</strong>. Saving is blocked to avoid a conflict.</span>' +
           '<button type="button" class="btn btn-sm btn-warning" onclick="window.__lockTakeOver()">Take over</button>', true);
  }

  // Guard the editor's save entry points if present.
  ['saveObject', 'saveRow'].forEach(function (fn) {
    if (typeof window[fn] === 'function') {
      var orig = window[fn];
      window[fn] = function () {
        if (blocked) {
          alert('This object is locked by another user. Take over the lock first.');
          return;
        }
        return orig.apply(this, arguments);
      };
    }
  });

  // Acquire on load.
  post('/api/locks/acquire', function (j) {
    if (j && j.ok) { blocked = false; clearBanner(); startHeartbeat(); }
    else if (j && j.lock) { onHeld(j.lock); }
  });

  // Best-effort release when leaving.
  window.addEventListener('beforeunload', function () {
    try {
      var data = new Blob([JSON.stringify({
        appliance_id: parseInt(aid, 10), resource_key: key
      })], { type: 'application/json' });
      navigator.sendBeacon('/api/locks/release', data);
    } catch (e) {}
  });
})();
