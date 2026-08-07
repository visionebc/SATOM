/* Attack-log detail panel + AI investigation (2026-08-08).
 *
 * Clicking a row on WAF → Search Attack ID slides a panel in from the right,
 * the same way the FortiWeb GUI opens a referenced object — the operator keeps
 * the result table in view instead of navigating away from their search.
 *
 * Why this is NOT objedit_drawer.js: that module's panels are always an
 * /objedit/<aid>/edit fragment for a config object, keyed on window.OBJEDIT_AID,
 * which does not exist on this page. It is loaded globally though, so this file
 * deliberately avoids its delegated hooks — the `.fw-drawer-close` and
 * `.fw-drawer-reload` class names are ITS handles, and reusing them would let
 * its `pop()` tear down a panel that is not on its stack, leaving this one's
 * backdrop behind. Only the purely visual `.fw-drawer*` styles are shared.
 *
 * The panel renders from the JSON the page already carries: the detail view is
 * the same data the table was built from, so it cannot disagree with it. The AI
 * path is the exception and does the opposite on purpose — it sends only the
 * appliance id and the MSG ID, and the server re-reads the entry off the
 * device. A browser must never be able to hand the model an "attack" it made up
 * and have a rule carve-out drafted from it.
 */
(function () {
  'use strict';

  var ROWS = [];
  var PAGE = {};
  var panel = null;
  var backdrop = null;
  var current = -1;

  function readJson(id) {
    var el = document.getElementById(id);
    if (!el) return null;
    try { return JSON.parse(el.textContent); } catch (e) { return null; }
  }

  function esc(v) {
    var d = document.createElement('div');
    d.textContent = (v == null ? '' : String(v));
    return d.innerHTML;
  }

  function csrf() {
    var m = document.querySelector('meta[name="csrf-token"]');
    return (m && m.content) || '';
  }

  function post(url, body) {
    return fetch(url, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrf()},
      body: JSON.stringify(body || {})
    }).then(function (r) {
      return r.json().catch(function () { return {ok: false, error: 'HTTP ' + r.status}; })
        .then(function (j) { j._status = r.status; return j; });
    });
  }

  // ── panel chrome ──────────────────────────────────────────────────────────
  function ensureChrome() {
    if (backdrop) return;
    backdrop = document.createElement('div');
    // Own class as well as the shared one: objedit_drawer's singleton lookup
    // grabs the FIRST .fw-drawer-backdrop in the document, so this element must
    // still be findable as ours.
    backdrop.className = 'fw-drawer-backdrop atk-backdrop';
    backdrop.addEventListener('click', close);
    document.body.appendChild(backdrop);

    panel = document.createElement('aside');
    panel.className = 'fw-drawer atk-drawer';
    panel.style.width = 'min(880px, 94vw)';
    panel.style.zIndex = '1051';
    panel.innerHTML =
      '<div class="fw-drawer-head">' +
        '<div class="fw-drawer-titles">' +
          '<i class="bi bi-shield-exclamation me-2"></i>' +
          '<span class="fw-drawer-title atk-title">Attack entry</span>' +
          '<code class="fw-drawer-coll atk-sub"></code>' +
        '</div>' +
        '<div class="fw-drawer-actions">' +
          '<button type="button" class="btn btn-sm btn-fw-outline atk-x" title="Close (Esc)">' +
            '<i class="bi bi-x-lg"></i></button>' +
        '</div>' +
      '</div>' +
      '<div class="fw-drawer-body atk-body"></div>';
    document.body.appendChild(panel);
    panel.querySelector('.atk-x').addEventListener('click', close);
  }

  function open(index) {
    var row = ROWS[index];
    if (!row) return;
    ensureChrome();
    current = index;
    panel.querySelector('.atk-title').textContent =
      (row.main_type || 'Attack') +
      (row.sub_type && row.sub_type !== 'N/A' ? ' — ' + row.sub_type : '');
    panel.querySelector('.atk-sub').textContent = 'MSG ID ' + (row.msg_id || '');
    panel.querySelector('.atk-body').innerHTML = detailHtml(row);
    wireBody(row);
    requestAnimationFrame(function () {
      backdrop.classList.add('show');
      panel.classList.add('show');
    });
  }

  function close() {
    if (!panel) return;
    panel.classList.remove('show');
    backdrop.classList.remove('show');
    current = -1;
  }

  // ── detail body ───────────────────────────────────────────────────────────
  function kvRows(row, fields) {
    var out = '';
    fields.forEach(function (pair) {
      var v = row[pair[0]];
      if (v === undefined || v === null || v === '' || v === 'N/A') return;
      out += '<tr><th style="width:210px;font-weight:600;">' + esc(pair[1]) + '</th>' +
             '<td style="word-break:break-all;">' + esc(v) + '</td></tr>';
    });
    return out;
  }

  function allRows(row) {
    var out = '';
    Object.keys(row).sort().forEach(function (k) {
      var v = row[k];
      if (v === undefined || v === null || v === '') return;
      out += '<tr><th style="width:210px;font-weight:600;">' + esc(k) + '</th>' +
             '<td style="word-break:break-all;">' + esc(v) + '</td></tr>';
    });
    return out;
  }

  function detailHtml(row) {
    var ai;
    if (PAGE.ai_enabled) {
      ai =
        '<button type="button" class="btn btn-sm btn-primary atk-ai">' +
          '<i class="bi bi-stars me-1"></i>Analyze with AI</button> ' +
        '<span class="text-muted" style="font-size:12px;">' +
          'Re-reads this entry from ' + esc(PAGE.appliance_name) + ' and judges it.' +
        '</span>';
    } else {
      // Say WHY the button is absent. A missing control reads as a missing
      // feature; a disabled subsystem is a setting someone can change.
      ai = '<span class="text-muted" style="font-size:13px;">' +
           '<i class="bi bi-info-circle me-1"></i>' +
           'The AI Advisor is switched off (Settings → AI), so this entry ' +
           'cannot be analysed.</span>';
    }
    return '' +
      '<div class="fw-card mb-3"><div class="fw-card-header">' +
        '<i class="bi bi-stars me-1"></i>AI investigation</div>' +
        '<div class="fw-card-body"><div class="atk-ai-bar">' + ai + '</div>' +
        '<div class="atk-ai-out mt-3"></div></div></div>' +
      '<div class="fw-card mb-3"><div class="fw-card-header">' +
        '<i class="bi bi-list-ul me-1"></i>Entry</div>' +
        '<table class="table table-sm mb-0"><tbody>' +
          kvRows(row, PAGE.primary_fields || []) +
        '</tbody></table></div>' +
      '<details class="mb-2"><summary style="cursor:pointer;font-size:13px;">' +
        'All ' + Object.keys(row).length + ' fields</summary>' +
        '<table class="table table-sm mt-2 mb-0"><tbody>' + allRows(row) +
        '</tbody></table></details>';
  }

  // ── AI investigation ──────────────────────────────────────────────────────
  var VERDICT_BADGE = {
    'false-positive': 'fw-badge-ok',
    'true-attack': 'fw-badge-crit',
    'uncertain': 'fw-badge-warn'
  };
  var RISK_BADGE = {
    'low': 'fw-badge-ok', 'medium': 'fw-badge-warn',
    'high': 'fw-badge-crit', 'unacceptable': 'fw-badge-crit'
  };

  function judgementHtml(d) {
    var h = '';
    if (d.verdict) {
      h += '<span class="fw-badge ' + (VERDICT_BADGE[d.verdict] || 'fw-badge-neutral') +
           '">verdict: ' + esc(d.verdict) + '</span> ';
    } else {
      h += '<span class="fw-badge fw-badge-neutral">no verdict returned</span> ';
    }
    if (d.risk) {
      h += '<span class="fw-badge ' + (RISK_BADGE[d.risk] || 'fw-badge-neutral') +
           '">exception risk: ' + esc(d.risk) + '</span> ';
    }
    if (d.wpp) {
      h += '<span class="fw-badge fw-badge-info">profile: ' + esc(d.wpp) + '</span> ';
    }
    if (d.wpp_locked) {
      h += '<span class="fw-badge fw-badge-warn">template-managed</span> ';
    }
    var cost = [];
    if (d.duration_ms != null) cost.push((d.duration_ms / 1000).toFixed(1) + ' s');
    cost.push((d.prompt_tokens == null && d.completion_tokens == null)
      ? 'tokens not reported'
      : ((d.prompt_tokens || 0) + (d.completion_tokens || 0)) + ' tokens');
    h += '<span class="text-muted" style="font-size:12px;">' + esc(cost.join(' · ')) + '</span>';
    return h;
  }

  function proposalHtml(d) {
    var p = d.proposal;
    if (!p) {
      // Two different facts, never shown as one: the Advisor declining to
      // draft a carve-out, and SATOM refusing the one it drafted.
      if (d.proposal_error) {
        return '<div class="alert alert-warning mb-0" style="font-size:13px;">' +
          '<i class="bi bi-exclamation-triangle me-1"></i>' +
          'The Advisor drafted a carve-out, but SATOM would not accept it: ' +
          esc(d.proposal_error) + '. Author it by hand under Exceptions.</div>';
      }
      return '<div class="alert alert-secondary mb-0" style="font-size:13px;">' +
        '<i class="bi bi-slash-circle me-1"></i>No carve-out was drafted. ' +
        'The Advisor only drafts one when it judges the block a false positive ' +
        'at low or medium risk — read its reasoning above.</div>';
    }
    // The model was told not to draft under these conditions. If it did anyway,
    // the operator is warned in the loudest place rather than handed a normal
    // Accept button: an exception approved on a true attack is the worst
    // outcome this page can produce.
    var contra = (d.verdict === 'true-attack' || d.risk === 'high' ||
                  d.risk === 'unacceptable');
    var h = '';
    if (contra) {
      h += '<div class="alert alert-danger" style="font-size:13px;">' +
        '<i class="bi bi-exclamation-octagon me-1"></i><strong>The Advisor drafted ' +
        'a carve-out that contradicts its own judgement</strong> (' +
        esc(d.verdict || 'no verdict') + ' / risk ' + esc(d.risk || 'unstated') +
        '). Treat it as unsafe until you have justified it yourself.</div>';
    }
    h += '<div class="fw-card"><div class="fw-card-header">' +
      '<i class="bi bi-pencil-square me-1"></i>Drafted carve-out — ' + esc(p.title || '') +
      '</div><div class="fw-card-body">';
    if (p.rationale) {
      h += '<p style="font-size:13px;">' + esc(p.rationale) + '</p>';
    }
    if (p.wpp_locked) {
      h += '<div class="alert alert-warning" style="font-size:13px;">' +
        '<i class="bi bi-lock me-1"></i>' + esc(p.lock_reason) +
        '<br>SATOM will clone it as <code>' + esc(p.clone_name) + '</code>, re-bind ' +
        '<code>' + esc(p.server_policy) + '</code> to the clone, and author the ' +
        'carve-out there. <strong>That clone is a real write to the appliance.</strong>' +
        '<div class="form-check mt-2">' +
          '<input class="form-check-input atk-clone-ok" type="checkbox" id="atk-clone-ok">' +
          '<label class="form-check-label" for="atk-clone-ok">' +
            'Clone the profile and re-bind the policy</label>' +
        '</div></div>';
    }
    h += '<label class="form-label" style="font-size:13px;">Payload — edit to adapt ' +
      'it before accepting</label>' +
      '<textarea class="form-control atk-payload" rows="12" spellcheck="false" ' +
      'style="font-family:var(--bs-font-monospace,monospace);font-size:12px;">' +
      esc(JSON.stringify(p.payload, null, 2)) + '</textarea>' +
      '<div class="form-text">Accepting stores a DRAFT carve-out under Exceptions. ' +
      'Nothing is pushed to the appliance from here.</div>' +
      '<div class="mt-2 d-flex gap-2">' +
        '<button type="button" class="btn btn-sm btn-primary atk-accept" ' +
          'data-pid="' + esc(p.id) + '">' +
          '<i class="bi bi-check2 me-1"></i>Accept</button>' +
        '<button type="button" class="btn btn-sm btn-outline-danger atk-reject" ' +
          'data-pid="' + esc(p.id) + '">' +
          '<i class="bi bi-x me-1"></i>Reject</button>' +
      '</div><div class="atk-decision mt-2"></div></div></div>';
    return h;
  }

  function renderAnalysis(out, d) {
    out.innerHTML =
      '<div class="mb-2">' + judgementHtml(d) + '</div>' +
      '<pre class="atk-analysis" style="white-space:pre-wrap;word-break:break-word;' +
        'font-size:13px;background:#F4F5F7;border:1px solid #DDE3EA;border-radius:4px;' +
        'padding:.65rem;">' + esc(d.analysis || '') + '</pre>' +
      proposalHtml(d);
    wireDecision(out, d);
  }

  function wireDecision(out, d) {
    var accept = out.querySelector('.atk-accept');
    var reject = out.querySelector('.atk-reject');
    var box = out.querySelector('.atk-decision');
    if (!accept) return;

    accept.addEventListener('click', function () {
      var ta = out.querySelector('.atk-payload');
      var payload;
      try {
        payload = JSON.parse(ta.value);
      } catch (e) {
        box.innerHTML = '<div class="alert alert-danger mb-0" style="font-size:13px;">' +
          'The payload is not valid JSON: ' + esc(e.message) + '</div>';
        return;
      }
      var cloneOk = out.querySelector('.atk-clone-ok');
      accept.disabled = reject.disabled = true;
      box.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Applying…';
      post('/waf/attack-search/proposal/' + accept.dataset.pid + '/apply',
           {payload: payload, clone_wpp: !!(cloneOk && cloneOk.checked)})
        .then(function (r) {
          accept.disabled = reject.disabled = false;
          if (r.ok) {
            accept.disabled = reject.disabled = true;
            box.innerHTML = '<div class="alert alert-success mb-0" style="font-size:13px;">' +
              '<i class="bi bi-check2-circle me-1"></i>' + esc(r.message || 'Applied.') +
              ' <code>' + esc(r.applied_ref || '') + '</code>' +
              (r.adapted ? ' <span class="fw-badge fw-badge-info">adapted</span>' : '') +
              '</div>';
            return;
          }
          if (r.template_locked) {
            box.innerHTML = '<div class="alert alert-warning mb-0" style="font-size:13px;">' +
              '<i class="bi bi-lock me-1"></i>' + esc(r.error) +
              '<br>Tick “Clone the profile and re-bind the policy”, then accept again.' +
              '</div>';
            return;
          }
          box.innerHTML = '<div class="alert alert-danger mb-0" style="font-size:13px;">' +
            esc(r.error || 'Apply failed.') + '</div>';
        });
    });

    reject.addEventListener('click', function () {
      accept.disabled = reject.disabled = true;
      post('/waf/attack-search/proposal/' + reject.dataset.pid + '/dismiss', {})
        .then(function (r) {
          if (r.ok) {
            box.innerHTML = '<div class="alert alert-secondary mb-0" style="font-size:13px;">' +
              'Rejected. The draft and this decision stay in the audit trail.</div>';
          } else {
            accept.disabled = reject.disabled = false;
            box.innerHTML = '<div class="alert alert-danger mb-0" style="font-size:13px;">' +
              esc(r.error || 'Reject failed.') + '</div>';
          }
        });
    });
  }

  function wireBody(row) {
    var btn = panel.querySelector('.atk-ai');
    if (!btn) return;
    var out = panel.querySelector('.atk-ai-out');
    btn.addEventListener('click', function () {
      btn.disabled = true;
      var t0 = Date.now();
      out.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>' +
        '<span class="atk-clock">Asking the Advisor…</span>';
      var clock = setInterval(function () {
        var e = out.querySelector('.atk-clock');
        if (e) e.textContent = 'Asking the Advisor… ' +
          ((Date.now() - t0) / 1000).toFixed(0) + ' s';
      }, 1000);
      post(PAGE.analyze_url, {appliance_id: PAGE.appliance_id, msg_id: row.msg_id})
        .then(function (d) {
          clearInterval(clock);
          btn.disabled = false;
          if (!d.ok) {
            out.innerHTML = '<div class="alert alert-danger mb-0" style="font-size:13px;">' +
              esc(d.error || 'Analysis failed.') + '</div>';
            return;
          }
          renderAnalysis(out, d);
        })
        .catch(function (e) {
          clearInterval(clock);
          btn.disabled = false;
          out.innerHTML = '<div class="alert alert-danger mb-0" style="font-size:13px;">' +
            esc(e.message) + '</div>';
        });
    });
  }

  // ── boot ──────────────────────────────────────────────────────────────────
  function boot() {
    ROWS = readJson('atk-rows-data') || [];
    PAGE = readJson('atk-page-data') || {};
    if (!ROWS.length) return;
    var table = document.getElementById('atk-results');
    if (!table) return;
    table.addEventListener('click', function (ev) {
      var tr = ev.target.closest('[data-atk-index]');
      if (!tr) return;
      ev.preventDefault();
      open(parseInt(tr.dataset.atkIndex, 10));
    });
    // Bound on `document`, which survives Turbo's body swap — so it is bound
    // ONCE, not once per boot(). Re-binding per page would stack a new closer
    // on every navigation and each Escape would fire all of them.
    if (!window.__atkEscBound) {
      window.__atkEscBound = true;
      document.addEventListener('keydown', function (ev) {
        if (ev.key === 'Escape' && current >= 0) { ev.stopPropagation(); close(); }
      }, true);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
  // Turbo Drive swaps the <body>: the panel and backdrop NODES die with it, so
  // drop the stale handles or the next open() writes into a detached element.
  document.addEventListener('turbo:load', function () {
    panel = null; backdrop = null; current = -1;
    boot();
  });
})();
