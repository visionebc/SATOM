/* Attack-log detail panel — investigation, carve-out authoring and insertion.
 *
 * Clicking a row on WAF → Search Attack ID slides a panel in from the right,
 * the same way the FortiWeb GUI opens a referenced object: the operator keeps
 * their result table in view instead of navigating away from their search.
 *
 * Why this is NOT objedit_drawer.js: that module's panels are always an
 * /objedit/<aid>/edit fragment for a config object, keyed on window.OBJEDIT_AID,
 * which does not exist on this page. It is loaded globally though, so this file
 * deliberately avoids its delegated hooks — `.fw-drawer-close` and
 * `.fw-drawer-reload` are ITS handles, and reusing them would let its pop()
 * tear down a panel that is not on its stack, leaving this one's backdrop
 * behind with nothing left to close it. Only the visual `.fw-drawer*` styles
 * are shared.
 *
 * The entry table renders from JSON the page already carries, so the detail
 * view cannot disagree with the table it came from. Everything that ACTS on the
 * entry does the opposite on purpose — analysis, field intelligence, payload
 * assembly and insertion send only the appliance id and the MSG ID, and the
 * server re-reads the row off the device. A browser must never be able to hand
 * SATOM an "attack" it made up and have a rule carved out from it.
 *
 * Three things here are load-bearing and easy to lose:
 *
 * 1. **Every DOM handle is resolved once, at the top of the function that uses
 *    it, and passed down by argument.** The advisor chat shipped a bug where a
 *    handle declared in a sibling function's scope threw a ReferenceError that
 *    killed the callback silently — the reply was saved and never drawn. The
 *    class of bug is designed out here rather than patched.
 * 2. **The carve-out builder does not depend on the AI verdict.** It is drawn
 *    whether the Advisor was asked, agreed, disagreed or is switched off. The
 *    operator's judgement is the one that authorises the change.
 * 3. **Insertion is two calls.** The first previews the exact request and
 *    writes nothing; the second writes. Approving a rule and approving a
 *    specific POST against a production WAF are different acts.
 */
(function () {
  'use strict';

  var ROWS = [];
  var PAGE = {};
  var panel = null;
  var backdrop = null;
  var current = -1;

  // Per-open state. Reset in open() so a second entry never inherits the first
  // one's ticked fields or saved draft id.
  var sel = {};
  var built = null;
  var draftId = null;
  var judged = {verdict: '', risk: ''};
  var intelCache = {};

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

  function getJson(url) {
    return fetch(url, {headers: {'Accept': 'application/json'}}).then(function (r) {
      return r.json().catch(function () { return {ok: false, error: 'HTTP ' + r.status}; });
    });
  }

  function alertBox(kind, html) {
    return '<div class="alert alert-' + kind + ' mb-0" style="font-size:13px;">' +
      html + '</div>';
  }

  function spinner(label) {
    return '<span class="spinner-border spinner-border-sm me-2"></span>' + esc(label);
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
    panel.style.width = 'min(980px, 96vw)';
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
    sel = {};
    built = null;
    draftId = null;
    judged = {verdict: '', risk: ''};
    intelCache = {};
    panel.querySelector('.atk-title').textContent =
      (row.main_type || 'Attack') +
      (row.sub_type && row.sub_type !== 'N/A' ? ' — ' + row.sub_type : '');
    panel.querySelector('.atk-sub').textContent = 'MSG ID ' + (row.msg_id || '');
    panel.querySelector('.atk-body').innerHTML = detailHtml(row);
    wireBody(panel.querySelector('.atk-body'), row);
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

  // ── entry table ───────────────────────────────────────────────────────────
  // Each field is three things at once: a value, something to investigate, and
  // something an exception can be scoped by. A flat key/value dump was only the
  // first of the three.
  function entryRows(row, fields) {
    var out = '';
    fields.forEach(function (pair) {
      var key = pair[0], label = pair[1], v = row[key];
      if (v === undefined || v === null || v === '' || v === 'N/A') return;
      out +=
        '<tr class="atk-frow" data-atk-field="' + esc(key) + '">' +
          '<td style="width:34px;" class="text-center">' +
            '<input class="form-check-input atk-pick" type="checkbox" ' +
              'data-atk-field="' + esc(key) + '" title="Use this field to scope an exception">' +
          '</td>' +
          '<th style="width:190px;font-weight:600;">' + esc(label) + '</th>' +
          '<td style="word-break:break-all;">' + esc(v) + '</td>' +
          '<td style="width:38px;" class="text-end">' +
            '<button type="button" class="btn btn-sm btn-fw-outline atk-i" ' +
              'data-atk-field="' + esc(key) + '" title="Explain this field">' +
              '<i class="bi bi-info-circle"></i></button>' +
          '</td>' +
        '</tr>' +
        '<tr class="atk-irow" data-atk-intel="' + esc(key) + '" style="display:none;">' +
          '<td colspan="4" class="atk-icell" style="background:#F4F5F7;"></td>' +
        '</tr>';
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
          'Re-reads this entry from ' + esc(PAGE.appliance_name) + ' and judges it. ' +
          'Its verdict is advice — you can still author an exception it argues against.' +
        '</span>';
    } else {
      // Say WHY the button is absent. A missing control reads as a missing
      // feature; a disabled subsystem is a setting someone can change.
      ai = '<span class="text-muted" style="font-size:13px;">' +
           '<i class="bi bi-info-circle me-1"></i>' +
           'The AI Advisor is switched off (Settings → AI). You can still build ' +
           'an exception by hand below.</span>';
    }
    return '' +
      '<div class="fw-card mb-3"><div class="fw-card-header">' +
        '<i class="bi bi-stars me-1"></i>AI investigation</div>' +
        '<div class="fw-card-body"><div class="atk-ai-bar">' + ai + '</div>' +
        '<div class="atk-ai-out mt-3"></div></div></div>' +

      '<div class="fw-card mb-3"><div class="fw-card-header d-flex ' +
        'justify-content-between align-items-center">' +
        '<span><i class="bi bi-list-ul me-1"></i>Entry</span>' +
        '<span class="text-muted" style="font-size:12px;">' +
        'Tick a field to scope an exception by it · ' +
        '<i class="bi bi-info-circle"></i> explains it</span></div>' +
        '<table class="table table-sm mb-0 atk-entry"><tbody>' +
          entryRows(row, PAGE.primary_fields || []) +
        '</tbody></table></div>' +

      '<div class="fw-card mb-3"><div class="fw-card-header">' +
        '<i class="bi bi-wrench-adjustable me-1"></i>Build an exception</div>' +
        '<div class="fw-card-body atk-builder">' + spinner('Reading the policy…') +
        '</div></div>' +

      '<details class="mb-2"><summary style="cursor:pointer;font-size:13px;">' +
        'All ' + Object.keys(row).length + ' fields</summary>' +
        '<table class="table table-sm mt-2 mb-0"><tbody>' + allRows(row) +
        '</tbody></table></details>';
  }

  // ── field intelligence ────────────────────────────────────────────────────
  function intelHtml(d) {
    var i = d.intel || {};
    var h = '';
    if (i.help) {
      h += '<p class="mb-2" style="font-size:13px;">' + esc(i.help) + '</p>';
    }
    if (i.flags && i.flags.length) {
      h += '<div class="mb-2">';
      i.flags.forEach(function (f) {
        h += '<div class="alert alert-warning py-1 px-2 mb-1" style="font-size:12.5px;">' +
          '<strong>' + esc(f.label) + '</strong> — ' + esc(f.note) + '</div>';
      });
      h += '</div>';
    }
    if (i.facts && i.facts.length) {
      h += '<table class="table table-sm mb-2"><tbody>';
      i.facts.forEach(function (f) {
        h += '<tr><th style="width:170px;font-weight:600;">' + esc(f.label) + '</th>' +
          '<td style="word-break:break-all;">' + esc(f.value) +
          (f.note ? '<div class="text-muted" style="font-size:12px;">' +
                    esc(f.note) + '</div>' : '') + '</td></tr>';
      });
      h += '</tbody></table>';
    }
    (i.notes || []).forEach(function (n) {
      h += '<div class="alert alert-info py-1 px-2 mb-1" style="font-size:12.5px;">' +
        esc(n) + '</div>';
    });
    if (i.params && i.params.length) {
      h += '<div style="font-size:12.5px;"><strong>Query parameters</strong>' +
        '<table class="table table-sm mt-1 mb-2"><tbody>';
      i.params.forEach(function (p) {
        h += '<tr><th style="width:170px;font-weight:600;">' + esc(p.name) + '</th>' +
          '<td style="word-break:break-all;">' + esc(p.value) + '</td></tr>';
      });
      h += '</tbody></table></div>';
    }
    var c = d.correlation;
    if (c && c.total) {
      h += '<div class="alert alert-secondary py-2 px-2 mb-0" style="font-size:12.5px;">' +
        '<strong>Seen ' + esc(c.matches) + ' time' + (c.matches === 1 ? '' : 's') +
        '</strong> in the last ' + esc(c.total) + ' entries on this appliance' +
        (c.types && c.types.length
          ? ', across: ' + c.types.map(esc).join(', ') : '') + '.' +
        (c.matches > 1
          ? ' Repetition is the difference between one odd request and a campaign.'
          : ' A single occurrence.') +
        '</div>';
    }
    h += '<div class="text-muted mt-2" style="font-size:11.5px;">' +
      '<i class="bi bi-shield-lock me-1"></i>Analysed locally on this appliance ' +
      'manager. Nothing about this entry is sent to a WHOIS, geolocation or ' +
      'threat-intelligence service.</div>';
    return h || '<span class="text-muted">Nothing further to say about this field.</span>';
  }

  function toggleIntel(body, row, key) {
    var irow = body.querySelector('[data-atk-intel="' + key + '"]');
    if (!irow) return;
    if (irow.style.display !== 'none') { irow.style.display = 'none'; return; }
    irow.style.display = '';
    var cell = irow.querySelector('.atk-icell');
    if (intelCache[key]) { cell.innerHTML = intelCache[key]; return; }
    cell.innerHTML = spinner('Analysing…');
    post(PAGE.field_intel_url,
         {appliance_id: PAGE.appliance_id, msg_id: row.msg_id, field: key})
      .then(function (d) {
        var html = d.ok ? intelHtml(d) : alertBox('danger', esc(d.error || 'Failed.'));
        intelCache[key] = html;
        cell.innerHTML = html;
      });
  }

  // ── the review card: where a carve-out lands and how wide it reaches ──────
  var BREADTH_BADGE = {
    'narrow': 'fw-badge-ok', 'moderate': 'fw-badge-warn', 'wide': 'fw-badge-crit'
  };

  function explainHtml(e) {
    if (!e) return '';
    var h = '<div class="atk-explain">';
    h += '<div class="mb-2">' +
      '<span class="fw-badge ' + (BREADTH_BADGE[e.breadth] || 'fw-badge-neutral') +
      '">' + esc(e.breadth_label) + '</span></div>';
    if (e.breadth_why) {
      h += '<p class="text-muted" style="font-size:12.5px;">' + esc(e.breadth_why) +
        '</p>';
    }
    h += '<table class="table table-sm mb-2"><tbody>' +
      '<tr><th style="width:150px;font-weight:600;">Kind</th><td>' +
        esc(e.category_label) + '</td></tr>' +
      '<tr><th style="font-weight:600;">Goes into</th><td>' +
        (e.gui_path && e.gui_path.length
          ? e.gui_path.map(esc).join(' <span class="text-muted">→</span> ') : '—') +
        (e.container
          ? '<div class="text-muted" style="font-size:12px;">Written into ' +
            esc(e.container) + '. ' + esc(e.container_note) + '</div>' : '') +
        '</td></tr>' +
      '<tr><th style="font-weight:600;">Stops checking</th><td>' + esc(e.stops) +
        '</td></tr>' +
      '<tr><th style="font-weight:600;">Still enforced</th><td>' + esc(e.keeps) +
        '</td></tr>' +
      '</tbody></table>';

    if (e.fields && e.fields.length) {
      h += '<div style="font-size:12.5px;font-weight:600;" class="mb-1">Exact scope</div>' +
        '<table class="table table-sm mb-2"><tbody>';
      e.fields.forEach(function (f) {
        h += '<tr><th style="width:190px;font-weight:600;">' + esc(f.label) +
          (f.required ? ' <span class="text-danger">*</span>' : '') +
          (f.known ? '' : ' <span class="fw-badge fw-badge-warn">not in catalog</span>') +
          '</th><td style="word-break:break-all;"><code>' + esc(f.value) +
          '</code></td></tr>';
      });
      h += '</tbody></table>';
    }
    if (e.missing_required && e.missing_required.length) {
      h += alertBox('warning', 'Required field(s) still empty: <code>' +
        e.missing_required.map(esc).join('</code>, <code>') + '</code>.');
    }
    h += '</div>';
    return h;
  }

  function scopeHtml(s) {
    if (!s) return '';
    if (!s.needs_clone) {
      return '<div class="text-muted mb-2" style="font-size:12.5px;">' +
        '<i class="bi bi-check2-circle me-1 text-success"></i>' + esc(s.summary) +
        '</div>';
    }
    var h = '<div class="alert alert-warning" style="font-size:13px;">' +
      '<i class="bi bi-diagram-3 me-1"></i><strong>This profile cannot take the ' +
      'exception as it stands.</strong>';
    (s.reasons || []).forEach(function (r) {
      h += '<div class="mt-1">' + esc(r) + '</div>';
    });
    if (s.clone_name) {
      h += '<div class="mt-2">SATOM can clone it as <code>' + esc(s.clone_name) +
        '</code>, re-bind <code>' + esc(s.policy) + '</code> to the clone, and ' +
        'author the exception there — so it applies to this policy and no other. ' +
        '<strong>That clone is a real write to the appliance.</strong></div>' +
        '<div class="form-check mt-2">' +
          '<input class="form-check-input atk-clone-ok" type="checkbox" ' +
            'id="atk-clone-ok-' + esc(s.state) + '">' +
          '<label class="form-check-label" for="atk-clone-ok-' + esc(s.state) + '">' +
            'Clone the profile and re-bind the policy</label></div>';
    }
    h += '</div>';
    return h;
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
      // Three different facts, never shown as one: the Advisor declining to
      // draft, SATOM refusing the draft it made, and the operator still being
      // free to author one themselves.
      var why = d.proposal_error
        ? alertBox('warning', '<i class="bi bi-exclamation-triangle me-1"></i>' +
            'The Advisor drafted an exception, but SATOM would not accept it: ' +
            esc(d.proposal_error) + '.')
        : alertBox('secondary', '<i class="bi bi-slash-circle me-1"></i>' +
            'The Advisor drafted no exception. It only drafts one when it judges ' +
            'the block a false positive at low or medium risk — read its ' +
            'reasoning above.');
      return why + '<div class="text-muted mt-2" style="font-size:12.5px;">' +
        'You can still build one yourself in <strong>Build an exception</strong> ' +
        'below — tick the fields it must be scoped to.</div>';
    }
    var contra = (d.verdict === 'true-attack' || d.risk === 'high' ||
                  d.risk === 'unacceptable');
    var h = '';
    if (contra) {
      h += alertBox('danger', '<i class="bi bi-exclamation-octagon me-1"></i>' +
        '<strong>The Advisor drafted an exception that contradicts its own ' +
        'judgement</strong> (' + esc(d.verdict || 'no verdict') + ' / risk ' +
        esc(d.risk || 'unstated') + '). Treat it as unsafe until you have ' +
        'justified it yourself.');
    }
    h += '<div class="fw-card mt-2"><div class="fw-card-header">' +
      '<i class="bi bi-pencil-square me-1"></i>Drafted exception — ' +
      esc(p.title || '') + '</div><div class="fw-card-body">';
    if (p.rationale) {
      h += '<p style="font-size:13px;">' + esc(p.rationale) + '</p>';
    }
    h += explainHtml(p.explain);
    h += scopeHtml(p.scope);
    h += '<details class="mb-2"><summary style="cursor:pointer;font-size:12.5px;">' +
      'Raw payload — edit to adapt it before accepting</summary>' +
      '<textarea class="form-control atk-payload mt-2" rows="10" spellcheck="false" ' +
      'style="font-family:var(--bs-font-monospace,monospace);font-size:12px;">' +
      esc(JSON.stringify(p.payload, null, 2)) + '</textarea></details>' +
      '<div class="mt-2 d-flex gap-2">' +
        '<button type="button" class="btn btn-sm btn-primary atk-accept" ' +
          'data-atk-pid="' + esc(p.id) + '">' +
          '<i class="bi bi-check2 me-1"></i>Accept</button>' +
        '<button type="button" class="btn btn-sm btn-outline-danger atk-reject" ' +
          'data-atk-pid="' + esc(p.id) + '">' +
          '<i class="bi bi-x me-1"></i>Reject</button>' +
      '</div><div class="atk-decision mt-2"></div></div></div>';
    return h;
  }

  function renderAnalysis(out, d, row) {
    judged = {verdict: d.verdict || '', risk: d.risk || ''};
    out.innerHTML =
      '<div class="mb-2">' + judgementHtml(d) + '</div>' +
      '<pre class="atk-analysis" style="white-space:pre-wrap;word-break:break-word;' +
        'font-size:13px;background:#F4F5F7;border:1px solid #DDE3EA;border-radius:4px;' +
        'padding:.65rem;">' + esc(d.analysis || '') + '</pre>' +
      proposalHtml(d);
    wireDecision(out, d, row);
  }

  function wireDecision(out, d, row) {
    var accept = out.querySelector('.atk-accept');
    var reject = out.querySelector('.atk-reject');
    var box = out.querySelector('.atk-decision');
    if (!accept || !reject || !box) return;

    accept.addEventListener('click', function () {
      var ta = out.querySelector('.atk-payload');
      var payload;
      try {
        payload = JSON.parse(ta.value);
      } catch (e) {
        box.innerHTML = alertBox('danger',
          'The payload is not valid JSON: ' + esc(e.message));
        return;
      }
      var cloneOk = out.querySelector('.atk-clone-ok');
      accept.disabled = reject.disabled = true;
      box.innerHTML = spinner('Applying…');
      post(PAGE.proposal_apply_url.replace('__PID__', accept.dataset.atkPid),
           {payload: payload, clone_wpp: !!(cloneOk && cloneOk.checked)})
        .then(function (r) {
          if (r.ok) {
            draftId = r.exc_id || null;
            box.innerHTML = alertBox('success',
              '<i class="bi bi-check2-circle me-1"></i>' + esc(r.message || 'Applied.') +
              ' <code>' + esc(r.applied_ref || '') + '</code>' +
              (r.adapted ? ' <span class="fw-badge fw-badge-info">adapted</span>' : '') +
              (r.cloned_wpp ? ' <span class="fw-badge fw-badge-info">cloned to ' +
                esc(r.cloned_wpp) + '</span>' : '')) +
              '<div class="atk-insert mt-2"></div>';
            if (draftId) startInsert(box.querySelector('.atk-insert'), draftId);
            return;
          }
          accept.disabled = reject.disabled = false;
          if (r.scope && r.scope.needs_clone) {
            box.innerHTML = scopeHtml(r.scope) +
              '<div class="text-muted" style="font-size:12.5px;">Tick the box ' +
              'above, then Accept again.</div>';
            return;
          }
          box.innerHTML = alertBox('danger', esc(r.error || 'Apply failed.'));
        });
    });

    reject.addEventListener('click', function () {
      accept.disabled = reject.disabled = true;
      post(PAGE.proposal_dismiss_url.replace('__PID__', reject.dataset.atkPid), {})
        .then(function (r) {
          if (r.ok) {
            box.innerHTML = alertBox('secondary',
              'Rejected. The draft and this decision stay in the audit trail.');
          } else {
            accept.disabled = reject.disabled = false;
            box.innerHTML = alertBox('danger', esc(r.error || 'Reject failed.'));
          }
        });
    });
  }

  // ── the builder ───────────────────────────────────────────────────────────
  function typeListHtml(types) {
    var h = '<div class="mb-2" style="font-size:12.5px;font-weight:600;">' +
      'What kind of exception?</div>';
    types.forEach(function (t, i) {
      h += '<div class="form-check mb-2">' +
        '<input class="form-check-input atk-type" type="radio" name="atk-type" ' +
          'id="atk-type-' + i + '" value="' + esc(t.exc_type) + '"' +
          (i === 0 ? ' checked' : '') + '>' +
        '<label class="form-check-label" for="atk-type-' + i + '" style="font-size:13px;">' +
          '<strong>' + esc(t.label) + '</strong> ' +
          '<span class="text-muted">· ' + esc(t.group) + '</span>' +
          '<div class="text-muted" style="font-size:12px;">' + esc(t.why) + '</div>' +
        '</label></div>';
    });
    return h;
  }

  function scoperHintHtml(types, chosen) {
    var t = null;
    types.forEach(function (x) { if (x.exc_type === chosen) t = x; });
    if (!t) return '';
    if (!t.scopers || !t.scopers.length) {
      return '<div class="text-muted" style="font-size:12.5px;">' +
        'This kind of exception takes no element scope — it applies to the whole ' +
        'profile. Ticking fields above will not narrow it.</div>';
    }
    var h = '<div class="text-muted" style="font-size:12.5px;">' +
      'Tick any of these in the <strong>Entry</strong> table above to narrow it:';
    h += '<ul class="mb-0 mt-1" style="padding-left:1.1rem;">';
    t.scopers.forEach(function (s) {
      h += '<li><strong>' + esc(s.label) + '</strong>' +
        (s.value ? ' — <code>' + esc(s.value) + '</code>' : '') +
        '<div>' + esc(s.note) + '</div></li>';
    });
    return h + '</ul></div>';
  }

  function builderHtml(opts) {
    if (!opts.types || !opts.types.length) {
      return alertBox('secondary', 'SATOM could not work out which kind of ' +
        'exception fits this entry.');
    }
    return '' +
      scopeHtml(opts.scope) +
      typeListHtml(opts.types) +
      '<div class="atk-scoper mb-2"></div>' +
      '<div class="d-flex gap-2 mb-2">' +
        '<button type="button" class="btn btn-sm btn-fw-outline atk-preview">' +
          '<i class="bi bi-eye me-1"></i>Preview the exception</button>' +
      '</div>' +
      '<div class="atk-build-out"></div>';
  }

  function renderBuild(out, d, row) {
    built = d;
    var h = '';
    (d.warnings || []).forEach(function (w) {
      h += alertBox('warning', '<i class="bi bi-exclamation-triangle me-1"></i>' +
        esc(w)) + '<div class="mb-1"></div>';
    });
    (d.ignored || []).forEach(function (ig) {
      h += '<div class="text-muted" style="font-size:12.5px;">' +
        '<i class="bi bi-dash-circle me-1"></i><code>' + esc(ig.row_key) +
        '</code> was not used — ' + esc(ig.why) + '</div>';
    });
    if (d.errors && d.errors.length) {
      h += alertBox('danger', 'This exception is not valid yet: ' +
        d.errors.map(esc).join('; ') + '.');
    }
    h += explainHtml(d.explain);
    h += '<details class="mb-2"><summary style="cursor:pointer;font-size:12.5px;">' +
      'Raw payload — edit to adapt it</summary>' +
      '<textarea class="form-control atk-bpayload mt-2" rows="9" spellcheck="false" ' +
      'style="font-family:var(--bs-font-monospace,monospace);font-size:12px;">' +
      esc(JSON.stringify(d.payload, null, 2)) + '</textarea></details>';

    var contra = (judged.verdict === 'true-attack' || judged.risk === 'high' ||
                  judged.risk === 'unacceptable');
    if (contra) {
      h += alertBox('warning',
        '<i class="bi bi-pencil me-1"></i>The Advisor judged this <strong>' +
        esc(judged.verdict || 'unresolved') + '</strong> at <strong>' +
        esc(judged.risk || 'unstated') + '</strong> risk. Authoring an exception ' +
        'anyway may well be right — write down why. It is stored with the rule ' +
        'and in the audit trail.') +
        '<textarea class="form-control atk-just mt-2" rows="3" ' +
        'placeholder="Why this exception is correct despite the verdict…"></textarea>';
    }
    h += '<div class="mt-2"><button type="button" class="btn btn-sm btn-primary ' +
      'atk-save"' + (d.errors && d.errors.length ? ' disabled' : '') + '>' +
      '<i class="bi bi-save me-1"></i>Save as draft</button></div>' +
      '<div class="atk-save-out mt-2"></div>';
    out.innerHTML = h;

    var save = out.querySelector('.atk-save');
    if (save) wireSave(out, save, row);
  }

  function wireSave(out, save, row) {
    var sout = out.querySelector('.atk-save-out');
    save.addEventListener('click', function () {
      var ta = out.querySelector('.atk-bpayload');
      var payload = null;
      if (ta) {
        try {
          payload = JSON.parse(ta.value);
        } catch (e) {
          sout.innerHTML = alertBox('danger',
            'The payload is not valid JSON: ' + esc(e.message));
          return;
        }
      }
      var just = out.querySelector('.atk-just');
      var cloneOk = panel.querySelector('.atk-builder .atk-clone-ok');
      save.disabled = true;
      sout.innerHTML = spinner('Saving…');
      post(PAGE.carveout_url, {
        appliance_id: PAGE.appliance_id, msg_id: row.msg_id,
        exc_type: built.explain ? built.explain.type_key : '',
        fields: Object.keys(sel).filter(function (k) { return sel[k]; }),
        payload: payload,
        verdict: judged.verdict, risk: judged.risk,
        justification: just ? just.value : '',
        clone_wpp: !!(cloneOk && cloneOk.checked)
      }).then(function (r) {
        save.disabled = false;
        if (!r.ok) {
          if (r.scope && r.scope.needs_clone) {
            sout.innerHTML = scopeHtml(r.scope) +
              '<div class="text-muted" style="font-size:12.5px;">Tick the box, ' +
              'then Save again.</div>';
            return;
          }
          sout.innerHTML = alertBox('danger', esc(r.error || 'Save failed.'));
          return;
        }
        draftId = r.exc_id;
        save.disabled = true;
        sout.innerHTML = alertBox('success',
          '<i class="bi bi-check2-circle me-1"></i>' + esc(r.message) +
          ' <code>' + esc(r.ref || '') + '</code>' +
          (r.cloned_wpp ? ' <span class="fw-badge fw-badge-info">cloned to ' +
            esc(r.cloned_wpp) + '</span>' : '')) +
          '<div class="atk-insert mt-2"></div>';
        startInsert(sout.querySelector('.atk-insert'), draftId);
      });
    });
  }

  // ── insertion ─────────────────────────────────────────────────────────────
  function startInsert(host, excId) {
    if (!host) return;
    host.innerHTML = spinner('Reading the appliance for a place to put it…');
    getJson(PAGE.targets_url.replace('__ID__', excId) +
            '?appliance_id=' + encodeURIComponent(PAGE.appliance_id))
      .then(function (d) {
        if (!d.ok) {
          host.innerHTML = alertBox('warning',
            '<i class="bi bi-exclamation-triangle me-1"></i>' +
            esc(d.error || 'Could not list targets.') +
            ' The draft is saved — insert it from the Exceptions page.');
          return;
        }
        renderInsert(host, d, excId);
      });
  }

  function renderInsert(host, d, excId) {
    var opts = (d.targets || []).map(function (t) {
      return '<option value="' + esc(t) + '">' + esc(t) + '</option>';
    }).join('');
    host.innerHTML =
      '<div class="fw-card"><div class="fw-card-header">' +
        '<i class="bi bi-box-arrow-in-down me-1"></i>Insert into the appliance' +
      '</div><div class="fw-card-body">' +
        (d.targets && d.targets.length
          ? '<label class="form-label" style="font-size:12.5px;">Which object on ' +
            'the device it goes into</label>' +
            '<select class="form-select form-select-sm atk-target">' + opts +
            '</select>'
          : alertBox('warning', 'The appliance offers no object of the right kind ' +
              'to hold this exception.' +
              (d.can_create ? ' You can create one below.' : ''))) +
        (d.can_create
          ? '<div class="form-check mt-2">' +
            '<input class="form-check-input atk-mkcontainer" type="checkbox" ' +
              'id="atk-mkcontainer">' +
            '<label class="form-check-label" for="atk-mkcontainer" ' +
              'style="font-size:12.5px;">Create the container if it does not exist' +
            '</label></div>'
          : '') +
        '<div class="mt-2 d-flex gap-2">' +
          '<button type="button" class="btn btn-sm btn-fw-outline atk-plan">' +
            '<i class="bi bi-eye me-1"></i>Preview the exact request</button>' +
        '</div>' +
        '<div class="atk-plan-out mt-2"></div>' +
      '</div></div>';

    var planBtn = host.querySelector('.atk-plan');
    var planOut = host.querySelector('.atk-plan-out');
    planBtn.addEventListener('click', function () {
      doInsert(host, planOut, excId, false);
    });
  }

  function doInsert(host, out, excId, apply) {
    var target = host.querySelector('.atk-target');
    var mk = host.querySelector('.atk-mkcontainer');
    out.innerHTML = spinner(apply ? 'Writing to the appliance…' : 'Planning…');
    post(PAGE.insert_url.replace('__ID__', excId), {
      appliance_id: PAGE.appliance_id,
      target: target ? target.value : '',
      create_container: !!(mk && mk.checked),
      apply: !!apply
    }).then(function (r) {
      var h = '';
      if (r.scope && r.scope.needs_clone) {
        out.innerHTML = scopeHtml(r.scope);
        return;
      }
      if (r.plan) {
        h += '<div style="font-size:12.5px;font-weight:600;">' +
          (apply ? 'What was sent' : 'What would be sent') + '</div>' +
          '<pre style="font-size:12px;background:#F4F5F7;border:1px solid #DDE3EA;' +
          'border-radius:4px;padding:.5rem;white-space:pre-wrap;word-break:break-all;">' +
          esc((r.plan.method || '') + ' ' + (r.plan.endpoint || '')) +
          (r.body ? '\n' + esc(JSON.stringify(r.body, null, 2)) : '') + '</pre>';
        if (r.plan.error) {
          h += alertBox('danger', esc(r.plan.error));
        }
      }
      if (!apply) {
        h += (r.plan && r.plan.status === 'ready')
          ? '<button type="button" class="btn btn-sm btn-danger atk-go">' +
            '<i class="bi bi-box-arrow-in-down me-1"></i>Insert it into the ' +
            'appliance now</button>' +
            '<div class="text-muted mt-1" style="font-size:12px;">' +
            'This writes to a live WAF. It takes effect immediately.</div>'
          : alertBox('warning', esc(r.plan && r.plan.error
              ? r.plan.error : 'The request could not be planned.'));
      } else {
        h += r.ok
          ? alertBox('success', '<i class="bi bi-check2-circle me-1"></i>' +
              esc(r.message))
          : alertBox('danger', '<i class="bi bi-x-octagon me-1"></i>' +
              esc(r.message || 'The appliance rejected the write.') +
              ((r.steps || []).filter(function (s) { return s.error; })
                .map(function (s) { return '<div>' + esc(s.error) + '</div>'; })
                .join('')));
      }
      out.innerHTML = h;
      var go = out.querySelector('.atk-go');
      if (go) {
        go.addEventListener('click', function () {
          go.disabled = true;
          doInsert(host, out, excId, true);
        });
      }
    });
  }

  // ── wiring ────────────────────────────────────────────────────────────────
  function loadBuilder(body, row) {
    var host = body.querySelector('.atk-builder');
    post(PAGE.options_url, {appliance_id: PAGE.appliance_id, msg_id: row.msg_id})
      .then(function (d) {
        if (!d.ok) {
          host.innerHTML = alertBox('danger', esc(d.error || 'Failed.'));
          return;
        }
        host.innerHTML = builderHtml(d);
        wireBuilder(host, d, row);
      });
  }

  function wireBuilder(host, opts, row) {
    var hint = host.querySelector('.atk-scoper');
    var out = host.querySelector('.atk-build-out');
    var preview = host.querySelector('.atk-preview');
    if (!hint || !out || !preview) return;

    function chosen() {
      var r = host.querySelector('.atk-type:checked');
      return r ? r.value : '';
    }
    function refresh() { hint.innerHTML = scoperHintHtml(opts.types, chosen()); }
    refresh();
    Array.prototype.forEach.call(host.querySelectorAll('.atk-type'), function (r) {
      r.addEventListener('change', function () { refresh(); out.innerHTML = ''; });
    });

    preview.addEventListener('click', function () {
      out.innerHTML = spinner('Assembling…');
      post(PAGE.build_url, {
        appliance_id: PAGE.appliance_id, msg_id: row.msg_id,
        exc_type: chosen(),
        fields: Object.keys(sel).filter(function (k) { return sel[k]; })
      }).then(function (d) {
        if (!d.ok) {
          out.innerHTML = alertBox('danger', esc(d.error || 'Failed.'));
          return;
        }
        renderBuild(out, d, row);
      });
    });
  }

  function wireBody(body, row) {
    var ai = body.querySelector('.atk-ai');
    var aiOut = body.querySelector('.atk-ai-out');

    body.addEventListener('click', function (ev) {
      var info = ev.target.closest('.atk-i');
      if (info) {
        ev.preventDefault();
        toggleIntel(body, row, info.dataset.atkField);
      }
    });
    body.addEventListener('change', function (ev) {
      var pick = ev.target.closest('.atk-pick');
      if (pick) sel[pick.dataset.atkField] = pick.checked;
    });

    if (ai && aiOut) {
      ai.addEventListener('click', function () {
        ai.disabled = true;
        var t0 = Date.now();
        aiOut.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>' +
          '<span class="atk-clock">Asking the Advisor…</span>';
        var clock = setInterval(function () {
          var e = aiOut.querySelector('.atk-clock');
          if (e) e.textContent = 'Asking the Advisor… ' +
            ((Date.now() - t0) / 1000).toFixed(0) + ' s';
        }, 1000);
        post(PAGE.analyze_url, {appliance_id: PAGE.appliance_id, msg_id: row.msg_id})
          .then(function (d) {
            clearInterval(clock);
            ai.disabled = false;
            if (!d.ok) {
              aiOut.innerHTML = alertBox('danger', esc(d.error || 'Analysis failed.'));
              return;
            }
            renderAnalysis(aiOut, d, row);
          })
          .catch(function (e) {
            clearInterval(clock);
            ai.disabled = false;
            aiOut.innerHTML = alertBox('danger', esc(e.message));
          });
      });
    }
    loadBuilder(body, row);
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
