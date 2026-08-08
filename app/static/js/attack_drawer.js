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
  // What to redraw once `sel` has been written. The body's change handler owns
  // that write and calls this AFTER it, so the hint can never report the
  // selection as it stood one click ago. The alternative — a second `change`
  // listener registered by the builder — would run BEFORE the writer (it would
  // sit on a descendant) and would stack one more handler per open() on a node
  // open() never replaces, which is the fault the note in ensureChrome()
  // records.
  var onPick = null;
  var built = null;
  var draftId = null;
  var judged = {verdict: '', risk: ''};
  var intelCache = {};
  // Per-field AI thread, keyed by field name:
  //   {open:bool, conv:int|null, items:[{q, answer|error, cost}], busy:bool}
  // It lives beside intelCache because the intelligence cell is rebuilt from
  // BOTH on every render — that is what makes an answer survive the row being
  // collapsed and reopened, instead of being appended into DOM that gets
  // thrown away.
  var askState = {};

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

  // Every analysis this panel shows — local or AI — is stamped with the same
  // three things: which engine produced it, how long it took and what it cost.
  // ONE implementation, because two of them agree on the day they are written
  // and disagree on the first change to either.
  //
  // A null token count is NOT zero. Some OpenAI-compatible gateways omit the
  // usage block entirely, and a confident "0 tokens" would be a measurement the
  // product never made. The local path is the one case where "no tokens" is a
  // fact rather than an absence, and it says so in those words.
  function costChip(d, opts) {
    opts = opts || {};
    var bits = [];
    bits.push(d && d.duration_ms != null
      ? (d.duration_ms / 1000).toFixed(1) + ' s'
      : 'time not reported');
    if (opts.local) {
      bits.push('no tokens');
    } else if (d && (d.prompt_tokens != null || d.completion_tokens != null)) {
      bits.push(((d.prompt_tokens || 0) + (d.completion_tokens || 0)) + ' tokens');
    } else {
      bits.push('tokens not reported');
    }
    return '<span class="text-muted" style="font-size:12px;">' +
      '<i class="bi ' + esc(opts.icon || 'bi-stars') + ' me-1"></i>' +
      esc(opts.who || 'AI Advisor') + ' · ' + esc(bits.join(' · ')) + '</span>';
  }

  // A wait with no clock is indistinguishable from a hang, and a local model
  // loading cold can take a minute. `host` is the element that OUTLIVES the
  // re-render (the cell, not its contents), so the ticker keeps finding its
  // label after the block around it is redrawn.
  //
  // Returns the timer id and is stopped by name rather than by returning a
  // closure: a callable held in a `var` is invisible to the guard that checks
  // every call in this file resolves to a function defined in it, and that
  // guard is the one standing between this page and the class of bug that
  // shipped the advisor chat broken.
  function startClock(host, sel, label, t0) {
    return setInterval(function () {
      var e = host && host.querySelector(sel);
      if (e) e.textContent = label + ' ' + ((Date.now() - t0) / 1000).toFixed(0) + ' s';
    }, 1000);
  }

  function stopClock(id) {
    if (id) clearInterval(id);
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

    // Delegated ONCE, here, on the element that outlives every open(). open()
    // replaces the body's innerHTML but never the body itself, so binding these
    // per-open stacked one more handler on the same node each time: two
    // handlers toggled the intelligence row open and shut within a single
    // click, which is why "Explain this field" appeared to do nothing at all
    // from the second entry opened onwards. The current row is read from
    // module state at event time rather than captured, so there is no reason
    // left to rebind them.
    var body = panel.querySelector('.atk-body');
    body.addEventListener('click', function (ev) {
      var row = ROWS[current];
      var send = ev.target.closest('.atk-ask-send');
      if (send) {
        ev.preventDefault();
        if (row) sendAsk(body, row, send.dataset.atkField);
        return;
      }
      var ask = ev.target.closest('.atk-q');
      if (ask) {
        ev.preventDefault();
        if (row) openAsk(body, row, ask.dataset.atkField);
        return;
      }
      var info = ev.target.closest('.atk-i');
      if (!info) return;
      ev.preventDefault();
      if (row) toggleIntel(body, row, info.dataset.atkField);
    });
    // Ctrl/Cmd+Enter sends. The box is a textarea on purpose — a question
    // about a URL or a payload routinely needs more than one line — so plain
    // Enter has to stay a newline.
    body.addEventListener('keydown', function (ev) {
      if (ev.key !== 'Enter' || !(ev.ctrlKey || ev.metaKey)) return;
      var input = ev.target.closest('.atk-ask-input');
      if (!input) return;
      var host = input.closest('.atk-ask');
      var row = ROWS[current];
      if (!host || !row) return;
      ev.preventDefault();
      sendAsk(body, row, host.dataset.atkAsk);
    });
    body.addEventListener('change', function (ev) {
      var pick = ev.target.closest('.atk-pick');
      if (!pick) return;
      sel[pick.dataset.atkField] = pick.checked;
      if (onPick) onPick();
    });
  }

  function open(index) {
    var row = ROWS[index];
    if (!row) return;
    ensureChrome();
    current = index;
    sel = {};
    onPick = null;
    built = null;
    draftId = null;
    judged = {verdict: '', risk: ''};
    intelCache = {};
    askState = {};
    panel.querySelector('.atk-title').textContent =
      (row.main_type || 'Attack') +
      (row.sub_type && row.sub_type !== 'N/A' ? ' — ' + row.sub_type : '');
    panel.querySelector('.atk-sub').textContent = 'MSG ID ' + (row.msg_id || '');
    panel.querySelector('.atk-body').innerHTML =
      detailHtml(row, (PAGE.row_times || [])[index] || '');
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
  //
  // `localTime` is the timestamp the SERVER already localized for the result
  // table. It is passed in rather than computed here so the panel and the row
  // it was opened from cannot show two different times for one entry, and so
  // the timezone stays a single server-side setting instead of becoming a
  // second, browser-side notion of "now". The raw epoch is still visible in the
  // "All N fields" dump below, which is the device's answer verbatim.
  function entryRows(row, fields, localTime) {
    var out = '';
    fields.forEach(function (pair) {
      var key = pair[0], label = pair[1], v = row[key];
      if (key === PAGE.time_field && localTime) v = localTime;
      if (v === undefined || v === null || v === '' || v === 'N/A') return;
      out +=
        '<tr class="atk-frow" data-atk-field="' + esc(key) + '">' +
          '<td style="width:34px;" class="text-center">' +
            '<input class="form-check-input atk-pick" type="checkbox" ' +
              'data-atk-field="' + esc(key) + '" title="Use this field to scope an exception">' +
          '</td>' +
          '<th style="width:190px;font-weight:600;">' + esc(label) + '</th>' +
          '<td style="word-break:break-all;">' + esc(v) + '</td>' +
          '<td style="width:82px;" class="text-end text-nowrap">' +
            '<button type="button" class="btn btn-sm btn-fw-outline atk-i" ' +
              'data-atk-field="' + esc(key) + '" title="Explain this field">' +
              '<i class="bi bi-info-circle"></i></button>' +
            // The second icon is only drawn when the Advisor is on. A button
            // that always 409s teaches the operator to distrust the buttons.
            (PAGE.ai_enabled
              ? ' <button type="button" class="btn btn-sm btn-fw-outline atk-q" ' +
                  'data-atk-field="' + esc(key) + '" ' +
                  'title="Ask the AI about this field — answers on click">' +
                  '<i class="bi bi-chat-dots"></i></button>'
              : '') +
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

  function detailHtml(row, localTime) {
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
        '<i class="bi bi-info-circle"></i> explains it' +
        (PAGE.ai_enabled
          ? ' · <i class="bi bi-chat-dots"></i> asks the AI about it (it answers straight away)'
          : '') + '</span></div>' +
        '<table class="table table-sm mb-0 atk-entry"><tbody>' +
          entryRows(row, PAGE.primary_fields || [], localTime) +
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
    h += '<div class="mt-2">' +
      costChip({duration_ms: d.elapsed_ms},
               {icon: 'bi-cpu', who: 'Local analysis', local: true}) + '</div>';
    h += '<div class="text-muted mt-2" style="font-size:11.5px;">' +
      '<i class="bi bi-shield-lock me-1"></i>Analysed locally on this appliance ' +
      'manager. Nothing about this entry is sent to a WHOIS, geolocation or ' +
      'threat-intelligence service.</div>';
    return h || '<span class="text-muted">Nothing further to say about this field.</span>';
  }

  // The cell under a field row holds two stacked blocks and is rebuilt from
  // state on every render: the LOCAL explanation on top, the AI thread UNDER
  // it. Rendering from state instead of appending into live DOM is what lets
  // an answer, a pending question and a half-typed follow-up all survive the
  // row being toggled shut.
  function renderCell(cell, key) {
    if (!cell) return;
    cell.innerHTML =
      '<div class="atk-icontent">' +
        (intelCache[key] || spinner('Analysing…')) +
      '</div>' + askHtml(key);
  }

  function cellFor(body, key) {
    var irow = body.querySelector('[data-atk-intel="' + key + '"]');
    return irow ? irow.querySelector('.atk-icell') : null;
  }

  function loadIntel(body, row, key) {
    if (intelCache[key]) return;
    post(PAGE.field_intel_url,
         {appliance_id: PAGE.appliance_id, msg_id: row.msg_id, field: key})
      .then(function (d) {
        intelCache[key] = d.ok ? intelHtml(d)
                               : alertBox('danger', esc(d.error || 'Failed.'));
        renderCell(cellFor(body, key), key);
      });
  }

  function toggleIntel(body, row, key) {
    var irow = body.querySelector('[data-atk-intel="' + key + '"]');
    if (!irow) return;
    if (irow.style.display !== 'none') { irow.style.display = 'none'; return; }
    irow.style.display = '';
    renderCell(irow.querySelector('.atk-icell'), key);
    loadIntel(body, row, key);
  }

  // ── ask the AI about this one field ──────────────────────────────────────
  function askFor(key) {
    if (!askState[key]) {
      // `asked` is NOT `items.length`: an exchange that errored pushes an item
      // too, and the difference between "this field has been asked once" and
      // "this field has an answer" is exactly what decides whether the click
      // may fire the provider again.
      askState[key] = {open: false, conv: null, items: [], busy: false,
                       asked: false};
    }
    return askState[key];
  }

  function askHtml(key) {
    var st = askFor(key);
    if (!st.open) return '';
    var h = '<div class="atk-ask mt-3" data-atk-ask="' + esc(key) + '" ' +
      'style="border-top:1px solid #DDE3EA;padding-top:.6rem;">' +
      '<div class="mb-2" style="font-size:12.5px;font-weight:600;">' +
      '<i class="bi bi-chat-dots me-1"></i>Ask the AI about this field</div>';
    var replying = st.items.length > 0;
    st.items.forEach(function (it) {
      h += '<div class="mb-3 atk-ask-item">' +
        '<div style="font-size:12.5px;">' +
          '<i class="bi bi-person-circle me-1"></i><strong>' + esc(it.q) +
        '</strong></div>';
      h += it.error
        ? alertBox('danger', '<i class="bi bi-x-octagon me-1"></i>' + esc(it.error))
        : '<pre style="white-space:pre-wrap;word-break:break-word;font-size:13px;' +
          'background:#FFFFFF;border:1px solid #DDE3EA;border-radius:4px;' +
          'padding:.55rem;margin:.35rem 0 .25rem;">' + esc(it.answer || '') + '</pre>';
      // Cost is printed for a FAILED exchange too. A provider that burned 40
      // seconds and then errored spent those 40 seconds.
      h += '<div>' + costChip(it.cost || {}, {icon: 'bi-stars', who: 'AI Advisor'}) +
        '</div></div>';
    });
    if (st.busy) {
      h += '<div class="mb-2"><span class="spinner-border spinner-border-sm me-2">' +
        '</span><span class="atk-ask-clock">Asking the Advisor…</span></div>';
    }
    h += '<textarea class="form-control atk-ask-input" rows="2" ' +
      'placeholder="' + (replying
        ? 'Reply to the Advisor about this field — Ctrl+Enter sends.'
        : 'Ask anything about this field — Ctrl+Enter sends.') + '"' +
      (st.busy ? ' disabled' : '') + '></textarea>' +
      '<div class="d-flex gap-2 align-items-center mt-2">' +
        '<button type="button" class="btn btn-sm btn-primary atk-ask-send" ' +
          'data-atk-field="' + esc(key) + '"' + (st.busy ? ' disabled' : '') + '>' +
          '<i class="bi bi-send me-1"></i>' + (replying ? 'Reply' : 'Ask') +
          '</button>' +
        '<span class="text-muted" style="font-size:11.5px;">' +
          '<i class="bi bi-shield-lock me-1"></i>SATOM re-reads this entry from ' +
          esc(PAGE.appliance_name) + ' and sends it to the Advisor. It answers — ' +
          'it cannot author an exception from here.</span>' +
      '</div></div>';
    return h;
  }

  // The thread is drawn UNDER the local explanation, so opening it opens that
  // too rather than replacing it: the operator asked for the AI answer to
  // appear below where the element is explained, and the two are read together.
  function openAsk(body, row, key) {
    var irow = body.querySelector('[data-atk-intel="' + key + '"]');
    if (!irow) return;
    var st = askFor(key);
    st.open = true;
    irow.style.display = '';
    renderCell(irow.querySelector('.atk-icell'), key);
    loadIntel(body, row, key);
    // Clicking the icon IS the question. The answer arrives on the click and
    // the box below is kept for the operator's REPLY. The question itself is
    // left empty on purpose so the SERVER supplies its default text — that is
    // the string the audit row records, and a browser-side default would put a
    // question in the log that the provider was never actually sent.
    //
    // Fired at most once per field per opened entry, and never again after an
    // answer OR an error: an automatic retry against a provider that just
    // failed spends tokens to reproduce a failure already on screen.
    if (!st.asked) {
      st.asked = true;
      sendAsk(body, row, key);
      return;
    }
    var ta = irow.querySelector('.atk-ask-input');
    if (ta) ta.focus();
  }

  function sendAsk(body, row, key) {
    var st = askFor(key);
    if (st.busy) return;
    var cell = cellFor(body, key);
    if (!cell) return;
    var ta = cell.querySelector('.atk-ask-input');
    var q = ta ? ta.value.trim() : '';
    var t0 = Date.now();
    st.busy = true;
    renderCell(cell, key);
    var clockId = startClock(cell, '.atk-ask-clock', 'Asking the Advisor…', t0);

    function settle(item) {
      stopClock(clockId);
      st.busy = false;
      st.items.push(item);
      renderCell(cellFor(body, key), key);
    }

    // Only which entry and which field go up. The value is re-read from the
    // appliance server-side — see the module header.
    post(PAGE.ask_field_url, {
      appliance_id: PAGE.appliance_id, msg_id: row.msg_id, field: key,
      question: q, conversation_id: st.conv
    }).then(function (d) {
      if (!d.ok) {
        settle({q: q || '(general explanation)', cost: {duration_ms: Date.now() - t0},
                error: d.error || 'The Advisor could not answer.'});
        return;
      }
      // Follow-ups continue the same thread, so the operator does not have to
      // restate the entry to ask a second question about it.
      st.conv = d.conversation_id || st.conv;
      settle({q: d.question || q, answer: d.answer, cost: d});
    }).catch(function (e) {
      settle({q: q || '(general explanation)', cost: {duration_ms: Date.now() - t0},
              error: e.message});
    });
  }

  // ── the review card: where a carve-out lands and how wide it reaches ──────
  var BREADTH_BADGE = {
    'narrow': 'fw-badge-success', 'moderate': 'fw-badge-warning', 'wide': 'fw-badge-danger'
  };

  function explainHtml(e) {
    if (!e) return '';
    var h = '<div class="atk-explain">';
    h += '<div class="mb-2">' +
      '<span class="fw-badge ' + (BREADTH_BADGE[e.breadth] || 'fw-badge-secondary') +
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
          (f.known ? '' : ' <span class="fw-badge fw-badge-warning">not in catalog</span>') +
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
    'false-positive': 'fw-badge-success',
    'true-attack': 'fw-badge-danger',
    'uncertain': 'fw-badge-warning'
  };
  var RISK_BADGE = {
    'low': 'fw-badge-success', 'medium': 'fw-badge-warning',
    'high': 'fw-badge-danger', 'unacceptable': 'fw-badge-danger'
  };

  function judgementHtml(d) {
    var h = '';
    if (d.verdict) {
      h += '<span class="fw-badge ' + (VERDICT_BADGE[d.verdict] || 'fw-badge-secondary') +
           '">verdict: ' + esc(d.verdict) + '</span> ';
    } else {
      h += '<span class="fw-badge fw-badge-secondary">no verdict returned</span> ';
    }
    if (d.risk) {
      h += '<span class="fw-badge ' + (RISK_BADGE[d.risk] || 'fw-badge-secondary') +
           '">exception risk: ' + esc(d.risk) + '</span> ';
    }
    if (d.wpp) {
      h += '<span class="fw-badge fw-badge-info">profile: ' + esc(d.wpp) + '</span> ';
    }
    // Through the shared chip, not a second hand-rolled copy: this line and
    // the per-field thread must never end up disagreeing about what a missing
    // token count means.
    h += costChip(d, {icon: 'bi-stars', who: 'AI Advisor'});
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

  // A required scoper is not a narrowing option, and calling it one is how an
  // operator reaches "'request-file' is required for this carve-out type"
  // having read a list headed "tick any of these to narrow it". Requiredness
  // comes from the server, off the same table the validator reads.
  // A required scoper is not a narrowing option, and calling it one is how an
  // operator reaches "'request-file' is required for this carve-out type"
  // having read a list headed "tick any of these to narrow it". Requiredness
  // comes from the server, off the same table the validator reads.
  //
  // The list also reports what is TICKED, and reads that from `sel` at render
  // time rather than from what the builder meant to tick. The two agree while
  // nothing has gone wrong, and the case worth putting on screen is the one
  // where they do not.
  function scoperHintHtml(types, chosen) {
    var t = null;
    types.forEach(function (x) { if (x.exc_type === chosen) t = x; });
    if (!t) return '';
    var h = '';
    if (t.subject) {
      h += '<div class="mb-2" style="font-size:12.5px;">' +
        '<span class="fw-badge fw-badge-info">taken from the entry</span> ' +
        '<strong>' + esc(t.subject.label) + '</strong>' +
        (t.subject.value ? ' — <code>' + esc(t.subject.value) + '</code>' : '') +
        '<div class="text-muted">' + esc(t.subject.note) + '</div></div>';
    }
    if (!t.scopers || !t.scopers.length) {
      return h + '<div class="text-muted" style="font-size:12.5px;">' +
        'This kind of exception takes no element scope — it applies to the whole ' +
        'profile. Ticking fields above will not narrow it.</div>';
    }
    var req = t.scopers.filter(function (s) { return s.required; });
    // A required field the ENTRY does not carry cannot be ticked at all — the
    // table above draws a row only for a field that has a value. Telling the
    // operator to tick it sends them hunting for a checkbox that was never
    // drawn, which is the dead end this hint exists to prevent.
    var absent = req.filter(function (s) { return !s.value; });
    var miss = req.filter(function (s) { return s.value && !sel[s.row_key]; });
    var names = function (list) {
      return list.map(function (s) { return '<strong>' + esc(s.label) + '</strong>'; })
                 .join(' and ');
    };
    h += '<div class="text-muted" style="font-size:12.5px;">';
    if (req.length) {
      h += 'FortiWeb keys this kind of exception on ' + names(req) + ', so ' +
        (req.length > 1 ? 'those are' : 'that one is') + ' not optional — ';
      if (miss.length) {
        h += 'tick ' + names(miss) + ' in the <strong>Entry</strong> table above.';
      } else if (req.length > absent.length) {
        h += 'SATOM has ticked ' + (req.length > 1 ? 'them' : 'it') +
          ' for you in the <strong>Entry</strong> table above — untick only to ' +
          'widen the exception.';
      }
      if (absent.length) {
        h += ' This entry records no ' + names(absent) + ', so there is nothing ' +
          'here to scope it with — author this one from the Exceptions page.';
      }
      h += ' The rest narrow it further:';
    } else {
      h += 'Tick any of these in the <strong>Entry</strong> table above to narrow it:';
    }
    h += '<ul class="mb-0 mt-1" style="padding-left:1.1rem;">';
    // Why each box is in the state it is in. The reasons come from the same
    // call that decided the ticks, so the panel cannot explain a selection it
    // did not make. A field held back on purpose says so: a recommendation that
    // silently declines to use evidence the entry carries reads as SATOM having
    // missed it, and the operator re-ticks it without learning anything.
    var rec = t.recommended || {};
    var why = rec.reasons || {};
    var held = {};
    (rec.skipped || []).forEach(function (k) { held[k.row_key] = k.why; });
    t.scopers.forEach(function (s) {
      var state = '';
      if (s.required && !s.value) {
        state = ' <span class="fw-badge fw-badge-danger">not in this entry</span>';
      } else if (sel[s.row_key]) {
        state = ' <span class="fw-badge fw-badge-success">ticked</span>';
      } else if (s.required) {
        state = ' <span class="fw-badge fw-badge-danger">not ticked</span>';
      }
      h += '<li><strong>' + esc(s.label) + '</strong>' +
        (s.required
          ? ' <span class="fw-badge fw-badge-warning">required</span>'
          : '') + state +
        (s.value ? ' — <code>' + esc(s.value) + '</code>' : '') +
        '<div>' + esc(s.note) + '</div>';
      if (why[s.row_key]) {
        h += '<div class="atk-rec-why" style="font-size:12px;">' +
          '<i class="bi bi-check2-circle me-1"></i>' +
          esc(why[s.row_key]) + '</div>';
      } else if (held[s.row_key]) {
        h += '<div class="atk-rec-held text-muted" style="font-size:12px;">' +
          '<i class="bi bi-dash-circle me-1"></i>' +
          esc(held[s.row_key]) + '</div>';
      }
      h += '</li>';
    });
    h += '</ul>';
    if (rec.summary) {
      h += '<div class="atk-rec-summary mt-2" style="font-size:12.5px;">' +
        '<i class="bi bi-magic me-1"></i>' + esc(rec.summary) + '</div>';
    }
    // A default selection that does not assemble has to say so on arrival.
    // Finding out at Preview teaches the operator that the pre-selection is
    // not to be trusted, which costs more than the error it hid.
    if (rec.preview && rec.preview.errors && rec.preview.errors.length) {
      h += '<div class="mt-2">' + alertBox('warning',
        'The pre-selection is not enough on its own: ' +
        rec.preview.errors.map(esc).join('; ') + '.') + '</div>';
    }
    return h + '</div>';
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
    var body = host.closest('.atk-body');

    function chosen() {
      var r = host.querySelector('.atk-type:checked');
      return r ? r.value : '';
    }

    // A required scoper is not an option the operator may decline. Left
    // unticked the type produces no carve-out at all — only the validation
    // error naming a device schema key the operator never typed, under a
    // heading that invited them to tick "any of these to narrow it". The
    // server already knows which field it is and what the entry holds, so the
    // panel ticks it.
    //
    // Safe by direction, not by policy: every scoper NARROWS. Ticking one can
    // only make the exception match LESS, never more, so doing it unasked
    // decides nothing about reach that the operator would want back. The
    // opposite default — pre-ticking something that widened the rule — would
    // not be defensible on the same argument.
    //
    // The tick is made in the visible table as well as in `sel`, because those
    // two disagreeing is a page that sends a field it shows as unticked.
    // WHICH fields to tick is decided in ``attack_carveout.recommend`` and read
    // from here. The browser used to re-derive it ("every required scoper with
    // a value"), which is a second implementation of the rule: the day the
    // server started preferring one element for a signature exception, or
    // holding back the caller address, this copy would still have been ticking
    // by the old rule and the panel would have disagreed with its own reasons
    // panel about what it had selected.
    function autoTick() {
      var t = null;
      opts.types.forEach(function (x) { if (x.exc_type === chosen()) t = x; });
      var picked = (t && t.recommended && t.recommended.picked) || [];
      // Two rules, one pass over the fields the panel actually drew.
      //
      // WHICH fields to prefer is decided by ``attack_carveout.recommend`` and
      // read from here. The browser used to derive it ("every required scoper
      // with a value"), which is a second implementation of the rule: the day
      // the server started preferring one element for a signature exception,
      // or holding the caller address back, this copy would still tick by the
      // old rule while the reasons panel beside it described the new one.
      //
      // The required check stays as a FLOOR, not as duplication. A required
      // scoper with a value is what makes the exception valid at all, so a
      // regressed recommendation must leave the panel slightly wide rather
      // than invalid. And no value in the entry means no row in the table
      // above — there is no checkbox to tick, and claiming otherwise sends the
      // operator hunting for one that was never drawn.
      (t && t.scopers ? t.scopers : []).forEach(function (s) {
        if (picked.indexOf(s.row_key) < 0 && (!s.required || !s.value)) return;
        if (sel[s.row_key]) return;   // never re-tick what is already chosen
        sel[s.row_key] = true;
        var box = body && body.querySelector(
          '.atk-pick[data-atk-field="' + s.row_key + '"]');
        if (box) box.checked = true;
      });
    }
    function refresh() { hint.innerHTML = scoperHintHtml(opts.types, chosen()); }
    onPick = refresh;
    autoTick();
    refresh();
    Array.prototype.forEach.call(host.querySelectorAll('.atk-type'), function (r) {
      r.addEventListener('change', function () {
        // Each type has its OWN required fields, so the tick is re-evaluated
        // rather than done once at load. Nothing is unticked: a field the
        // operator chose stays chosen even when the new type does not require
        // it, and the build path reports any it cannot use.
        autoTick();
        refresh();
        out.innerHTML = '';
      });
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

  // Only elements that open() has just created are wired here. The two
  // delegated handlers on the body live in ensureChrome() because the body is
  // NOT recreated — see the note there.
  function wireBody(body, row) {
    var ai = body.querySelector('.atk-ai');
    var aiOut = body.querySelector('.atk-ai-out');

    if (ai && aiOut) {
      ai.addEventListener('click', function () {
        ai.disabled = true;
        var t0 = Date.now();
        aiOut.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>' +
          '<span class="atk-clock">Asking the Advisor…</span>';
        var clockId = startClock(aiOut, '.atk-clock', 'Asking the Advisor…', t0);
        post(PAGE.analyze_url, {appliance_id: PAGE.appliance_id, msg_id: row.msg_id})
          .then(function (d) {
            stopClock(clockId);
            ai.disabled = false;
            if (!d.ok) {
              aiOut.innerHTML = alertBox('danger', esc(d.error || 'Analysis failed.'));
              return;
            }
            renderAnalysis(aiOut, d, row);
          })
          .catch(function (e) {
            stopClock(clockId);
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
    // boot() runs TWICE on a first load, and did from the day Turbo arrived:
    // this file registers on DOMContentLoaded, turbo-boot.js remaps every such
    // registration to `turbo:load`, and the file ALSO registers turbo:load
    // directly for the body swap — so both run on the initial visit. Two click
    // handlers on one table opened every entry twice: two reads of the entry
    // off the appliance per click, two builder renders, and — once anything
    // kept a handle to a rendered node — a hook pointing at whichever render
    // lost the race and is no longer on screen.
    //
    // The flag lives on the TABLE, not on `window`: Turbo replaces the body on
    // every visit, so a real navigation gets a fresh table and binds again,
    // while a second boot() within one load finds the flag and stops. A window
    // flag would bind once per browser session and leave every Turbo visit
    // after the first with a dead page.
    if (table.dataset.atkBound === '1') return;
    table.dataset.atkBound = '1';
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
