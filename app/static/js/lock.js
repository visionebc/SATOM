/* Lease-lock guard (Phase 4). Drop a
     <div class="fw-lock-guard" data-appliance-id="N" data-resource-key="kind:name"></div>
   inside an editor and include this script. Each guard acquires a short lease,
   beats a heartbeat every 30s, releases on unload (or when its editor panel is
   removed from the page), and — if another user holds the lease — shows a
   banner + a "Take over" button and blocks that editor's saves.

   The script may run more than once on a page: the object editor body is also
   injected inline (?partial=1) and its scripts are re-executed. Guards are
   initialised once each, and the save wrappers are re-applied only when the
   editor script has redefined saveObject / saveRow. The server refuses a save
   over another user's lease regardless (HTTP 409); this is the early warning.

   A lease belongs to the PAGE that took it (one token per page load, shared
   by every guard on it): the same operator with the object open in two tabs
   sees "open in another tab" instead of the two silently overwriting each
   other. Not kept in sessionStorage on purpose -- a duplicated tab copies it
   and would pass for the same editor; a reload gets a new token and the old
   lease goes with the page (beforeunload release). Other editors (policy
   workspace, GUI dialogs) ask fwLockBlocked(el|key) before saving and send
   fwLeaseToken() as lease_token. */
(function () {
  if (!window.__fwLeaseTok) {
    window.__fwLeaseTok = (window.crypto && window.crypto.randomUUID) ? window.crypto.randomUUID()
      : (Date.now().toString(36) + Math.random().toString(36).slice(2));
  }
  function tokenFor() { return window.__fwLeaseTok; }

  function post(aid, key, path, cb, token) {
    fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ appliance_id: parseInt(aid, 10), resource_key: key,
                             token: token || tokenFor(aid, key) })
    }).then(function (r) { return r.json(); }).then(cb || function () {}).catch(function () {});
  }

  function initGuard(el) {
    if (!el || el.getAttribute('data-lock-init')) return;
    el.setAttribute('data-lock-init', '1');
    var aid = el.getAttribute('data-appliance-id');
    var key = el.getAttribute('data-resource-key');
    if (!aid || !key) return;
    var hbTimer = null;
    el.setAttribute('data-lease-token', tokenFor(aid, key));

    function setBlocked(v) { el.setAttribute('data-lock-blocked', v ? '1' : ''); }

    function banner(html, danger) {
      var b = el.querySelector('.lock-banner');
      if (!b) {
        b = document.createElement('div');
        el.appendChild(b);
      }
      b.className = 'lock-banner alert ' + (danger ? 'alert-warning' : 'alert-info') +
                    ' d-flex justify-content-between align-items-center';
      b.innerHTML = html;
      // CSP: script-src-attr 'none' — bind the banner button here, not inline.
      var act = b.querySelector('[data-lock-action]');
      if (act) act.addEventListener('click', function () {
        if (this.getAttribute('data-lock-action') === 'reload') location.reload();
        else takeOver();
      });
    }

    function clearBanner() {
      var b = el.querySelector('.lock-banner');
      if (b) b.remove();
    }

    function stop() { clearInterval(hbTimer); hbTimer = null; }

    function startHeartbeat() {
      if (hbTimer) return;
      hbTimer = setInterval(function () {
        // The inline editor was closed: give the lease back instead of
        // holding it until the whole page is left.
        if (!document.body.contains(el)) { stop(); post(aid, key, '/api/locks/release'); return; }
        post(aid, key, '/api/locks/heartbeat', function (j) {
          if (!j || !j.ok) { onLost(); }
        });
      }, 30000);
    }

    function onLost() {
      stop();
      setBlocked(true);
      banner('<span>⚠ Your edit lock was lost (expired or taken). Reload before saving.</span>' +
             '<button type="button" class="btn btn-sm btn-outline-secondary" data-lock-action="reload">Reload</button>', true);
    }

    function takeOver() {
      post(aid, key, '/api/locks/steal', function (j) {
        if (j && j.ok) { setBlocked(false); clearBanner(); startHeartbeat(); }
      });
    }

    function onHeld(info) {
      setBlocked(true);
      el.setAttribute('data-lock-same', info && info.same_user ? '1' : '');
      var msg;
      if (info && info.same_user) {
        msg = '🔒 You have this open in another tab or window. Saving here is blocked so the two do not overwrite each other.';
      } else {
        var who = document.createElement('strong');
        who.textContent = (info && info.owner_label) || 'another user';
        msg = '🔒 Being edited by ' + who.outerHTML + '. Saving is blocked to avoid a conflict.';
      }
      banner('<span>' + msg + '</span>' +
             '<button type="button" class="btn btn-sm btn-outline-warning" data-lock-action="takeover">Take over</button>', true);
    }

    post(aid, key, '/api/locks/acquire', function (j) {
      if (j && j.ok) { setBlocked(false); clearBanner(); startHeartbeat(); }
      else if (j && j.lock) { onHeld(j.lock); }
    });
  }

  // The guard of the editor an element belongs to (several editors can be
  // alive at once: the page plus an inline panel or a slide-over, or one
  // guard per section of the policy workspace): the nearest ancestor that
  // holds a guard, else the page's first one.
  function guardFor(node) {
    // a lease key (or an element that names one: data-lease-key) -> its guard
    var key = typeof node === 'string' ? node
      : (node && node.closest && node.closest('[data-lease-key]')
         ? node.closest('[data-lease-key]').getAttribute('data-lease-key') : '');
    if (key) {
      var all = document.querySelectorAll('.fw-lock-guard');
      for (var i = 0; i < all.length; i++) {
        if (all[i].getAttribute('data-resource-key') === key) return all[i];
      }
      if (typeof node === 'string') return null;
    }
    for (var n = node; n && n !== document; n = n.parentElement) {
      if (n.classList && n.classList.contains('fw-lock-guard')) return n;
      var g = n.querySelector ? n.querySelector('.fw-lock-guard') : null;
      if (g) return g;
    }
    return document.querySelector('.fw-lock-guard');
  }
  function blockedFor(btn) {
    var g = guardFor(btn);
    return !!(g && g.getAttribute('data-lock-blocked') === '1');
  }
  // "" when saving is allowed, else the sentence to show
  window.fwLockBlocked = function (node) {
    var g = guardFor(node);
    if (!g || g.getAttribute('data-lock-blocked') !== '1') return '';
    return g.getAttribute('data-lock-same') === '1'
      ? 'You have this object open in another tab or window. Take over the lock here first.'
      : 'This object is locked by another user. Take over the lock first.';
  };
  window.fwLeaseToken = function () { return tokenFor(); };

  ['saveObject', 'saveRow'].forEach(function (fn) {
    var orig = window[fn];
    if (typeof orig !== 'function' || orig.__lockWrapped) return;
    var wrapped = function (btn) {
      if (blockedFor(btn)) {
        alert(window.fwLockBlocked(btn));
        return;
      }
      return orig.apply(this, arguments);
    };
    wrapped.__lockWrapped = true;
    window[fn] = wrapped;
  });

  window.fwLockGuardInit = function (root) {
    (root || document).querySelectorAll('.fw-lock-guard').forEach(initGuard);
  };
  window.fwLockGuardInit(document);

  // Best-effort release of every guard still on the page when leaving.
  if (!window.__fwLockUnloadBound) {
    window.__fwLockUnloadBound = true;
    window.addEventListener('beforeunload', function () {
      document.querySelectorAll('.fw-lock-guard[data-lock-init]').forEach(function (el) {
        try {
          var data = new Blob([JSON.stringify({
            appliance_id: parseInt(el.getAttribute('data-appliance-id'), 10),
            resource_key: el.getAttribute('data-resource-key'),
            token: el.getAttribute('data-lease-token') || ''
          })], { type: 'application/json' });
          navigator.sendBeacon('/api/locks/release', data);
        } catch (e) {}
      });
    });
  }
})();
