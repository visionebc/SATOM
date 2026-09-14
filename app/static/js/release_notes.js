/* ============================================================
   SATOM — release_notes.js
   Top-banner Release Notes modal. Same logic as the desktop page:
   Scan from Fortinet / Reload corpus + Issues / Upgrade advisor / Notes.
   Backend: app/views/release_notes.py
   ============================================================ */
'use strict';

(function () {
  const modalEl = document.getElementById('releaseNotesModal');
  if (!modalEl) return;

  const BASE = '/release-notes';
  const PRODUCT = (document.querySelector('meta[name="current-product"]') || {}).content || 'fortiweb';
  const PLABEL = { fortiweb: 'FortiWeb', fortiadc: 'FortiADC' }[PRODUCT] || 'Fortinet';
  let loaded = false;
  let scanPoll = null;
  // Rendered by the server into the modal element; the Scout panel needs it
  // BEFORE /data comes back, because the 503 path renders first.
  const IS_ADMIN = modalEl.dataset.rnAdmin === 'true';

  // ---- tiny helpers ----
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const get = (url) => apiFetch(url);                       // GET → JSON (api.js)
  const post = (url, body) => apiFetch(url, {
    method: 'POST', body: body ? JSON.stringify(body) : undefined,
  });
  function debounce(fn, ms) {
    let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
  }
  function fillSelect(sel, items, { firstLabel, firstValue = '' } = {}) {
    if (!sel) return;
    const keep = sel.value;
    sel.innerHTML = '';
    if (firstLabel != null) {
      const o = document.createElement('option');
      o.value = firstValue; o.textContent = firstLabel; sel.appendChild(o);
    }
    items.forEach((it) => {
      const o = document.createElement('option');
      if (typeof it === 'object') { o.value = it.value; o.textContent = it.label; }
      else { o.value = it; o.textContent = it; }
      sel.appendChild(o);
    });
    if (keep && [...sel.options].some((o) => o.value === keep)) sel.value = keep;
  }

  const STATUS_LABEL = { known: 'Known', resolved: 'Resolved' };
  const STATUS_BADGE = { known: 'text-warning', resolved: 'text-success' };

  // ---- data load (first paint + after scan/reload) ----
  async function loadData() {
    let d;
    try { d = await get(`${BASE}/data`); }
    catch (e) { $('rnStatus').innerHTML = `<span class="text-danger">Failed to load: ${esc(e.message)}</span>`; return; }

    const sw = $('rnScoutOn');
    if (sw) sw.checked = !!d.scout_enabled;
    const c = d.counts;
    if (c.issues) {
      const gen = c.generated_at ? ` · last scan ${esc(c.generated_at)}` : '';
      $('rnStatus').innerHTML =
        `<i class="bi bi-check-circle text-success"></i> ${c.issues} issues ` +
        `(${c.known} known / ${c.resolved} resolved) · ${c.sections} sections · ` +
        `${c.versions} versions${gen}.`;
    } else {
      $('rnStatus').innerHTML = d.is_admin
        ? 'No release-notes data yet — click <b>Scan from Fortinet</b> to harvest it.'
        : 'No release-notes data yet — ask an admin to run a scan on this node.';
    }

    fillSelect($('rnIssueVersion'), d.versions, { firstLabel: '(all versions)' });
    fillSelect($('rnNoteVersion'), d.versions, { firstLabel: '(all versions)' });
    fillSelect($('rnIssueTopic'), d.topics, { firstLabel: '(all topics)' });
    fillSelect($('rnNoteSection'), d.sections, { firstLabel: '(all sections)' });
    // advisor: newest-first, no "(all)" entry
    fillSelect($('rnAdvCurrent'), d.versions);
    fillSelect($('rnAdvTarget'), d.versions);
    if (d.versions.length > 1) {
      $('rnAdvTarget').selectedIndex = 0;          // newest
      $('rnAdvCurrent').selectedIndex = 1;         // one older
    }

    // default firecrawl endpoint
    const fcEp = $('rnFcEndpoint');
    if (fcEp && !fcEp.value) fcEp.value = d.firecrawl_default || '';

    // a scan may be running (started by another admin / worker)
    if (d.scan_running && !scanPoll) startScanPolling();

    await searchIssues();
  }

  // ---- Issues tab ----
  async function searchIssues() {
    const p = new URLSearchParams({
      version: $('rnIssueVersion').value || '',
      status: $('rnIssueStatus').value || '',
      topic: $('rnIssueTopic').value || '',
      q: $('rnIssueQuery').value.trim(),
    });
    let d;
    try { d = await get(`${BASE}/issues?${p}`); } catch (e) { return; }
    const tb = $('rnIssueRows');
    tb.innerHTML = '';
    d.issues.forEach((r) => {
      const tr = document.createElement('tr');
      tr.style.cursor = 'pointer';
      tr.innerHTML =
        `<td>${esc(r.version)}</td>` +
        `<td class="${STATUS_BADGE[r.status] || ''}">${esc(STATUS_LABEL[r.status] || r.status)}</td>` +
        `<td>${esc(r.bug_id)}</td>` +
        `<td>${esc(r.topic)}</td>` +
        `<td>${esc(r.description)}</td>`;
      tr.addEventListener('click', () => showIssueDetail(r));
      tb.appendChild(tr);
    });
    $('rnIssueCount').textContent = `${d.count} issue(s).`;
  }

  function showIssueDetail(r) {
    const box = $('rnIssueDetail');
    let html =
      `<h6 class="mb-1">Bug ${esc(r.bug_id)} ` +
      `<span class="${STATUS_BADGE[r.status] || ''}">${esc(STATUS_LABEL[r.status] || r.status)}</span></h6>` +
      `<div class="small text-muted mb-2">${PLABEL} ${esc(r.version)} · ${esc(r.topic)}</div>` +
      `<div>${esc(r.description)}</div>`;
    if (r.workaround) html += `<div class="mt-2"><b>Workaround:</b> ${esc(r.workaround)}</div>`;
    if (r.source_url) html += `<div class="mt-2"><a href="${esc(r.source_url)}" target="_blank" rel="noopener">Open release note ↗</a></div>`;
    box.innerHTML = html;
    box.classList.remove('d-none');
  }

  // ---- Upgrade advisor tab ----
  function issueListHtml(rows, empty) {
    if (!rows.length) return `<p class="text-muted"><i>${esc(empty)}</i></p>`;
    return '<ul>' + rows.map((r) => {
      const link = r.source_url ? ` <a href="${esc(r.source_url)}" target="_blank" rel="noopener">↗</a>` : '';
      return `<li><b>${esc(r.bug_id)}</b> <span class="text-muted">[${esc(r.version)} · ${esc(r.topic)}]</span> ${esc(r.description)}${link}</li>`;
    }).join('') + '</ul>';
  }

  // ---- Scout advisory (the verdicts, above the bug diff) ----
  const SEV_BADGE = { blocker: 'fw-badge-danger', caution: 'fw-badge-warning',
                      note: 'fw-badge-secondary' };
  const VERDICT = {
    blocker: ['fw-badge-danger', 'Blocked — act before the window'],
    caution: ['fw-badge-warning', 'Proceed with care'],
    clear: ['fw-badge-success', 'Nothing blocking found'],
    unknown: ['fw-badge-info', 'Unknown — the corpus is incomplete'],
  };
  const SECTION_LABEL = {
    upgrade_notes: 'Upgrade notes', upgrading_from: 'Supported upgrade paths',
    repartitioning: 'Repartitioning the hard disk', ha_upgrade: 'Upgrading an HA cluster',
    downgrading: 'Downgrading to a previous release', vm_license: 'VM license validation',
  };

  function scoutOffHtml(msg, canFix) {
    return `<div class="fw-card p-3">`
      + `<div class="fw-badge fw-badge-secondary mb-2">Scout advisory off</div>`
      + `<p class="small mb-${canFix ? '2' : '0'}">${esc(msg)}</p>`
      + (canFix
        ? `<button type="button" class="btn btn-sm btn-primary" id="rnScoutEnable">`
          + `Turn Scout on</button>` : '')
      + `</div>`;
  }

  function findingHtml(f) {
    const link = f.source_url
      ? ` <a href="${esc(f.source_url)}" target="_blank" rel="noopener">↗</a>` : '';
    return `<div class="border rounded p-2 mb-2">`
      + `<div class="d-flex align-items-start gap-2">`
      + `<span class="fw-badge ${SEV_BADGE[f.severity] || 'fw-badge-secondary'}">`
      + `${esc(f.severity)}</span>`
      + `<div class="flex-grow-1">`
      + `<div><b>${esc(f.title)}</b></div>`
      + `<div class="small">${esc(f.detail)}</div>`
      + `<details class="small mt-1"><summary class="text-muted">`
      + `Fortinet's words — ${esc(f.version)} · `
      + `${esc(SECTION_LABEL[f.section] || f.section)}${link}</summary>`
      + `<div class="mt-1" style="white-space:pre-wrap">${esc(f.evidence)}</div>`
      + `</details></div></div></div>`;
  }

  function renderScout(a) {
    const [cls, label] = VERDICT[a.verdict] || VERDICT.unknown;
    const blockers = a.findings.filter((f) => f.severity === 'blocker');
    const rest = a.findings.filter((f) => f.severity !== 'blocker');
    let h = `<div class="fw-card p-3">`
      + `<div class="d-flex align-items-center gap-2 mb-2">`
      + `<i class="bi bi-binoculars"></i><b>Scout advisory</b>`
      + `<span class="fw-badge ${cls}">${esc(label)}</span></div>`;
    if (a.path && a.path.length) {
      const hops = a.path.length - 1;
      h += `<p class="mb-2"><b>Required route:</b> `
        + a.path.map((v) => `<code>${esc(v)}</code>`).join(' → ')
        + ` — <span class="text-muted">that is ${hops} maintenance `
        + `window${hops === 1 ? '' : 's'}, not one.</span></p>`;
    }
    h += blockers.map(findingHtml).join('');
    if (a.gaps && a.gaps.length) {
      // Absence is not innocence. Say what was NOT read, and how to fix it.
      const vs = [...new Set(a.gaps.map((g) => g.version))];
      h += `<div class="border rounded p-2 mb-2">`
        + `<span class="fw-badge fw-badge-info">coverage</span> `
        + `<b>${a.gaps.length} section(s) were not read</b> for ${esc(vs.join(', '))}. `
        + `<span class="small text-muted">This advisory cannot be called clean — `
        + `scan those versions and ask again.</span></div>`;
    }
    if (rest.length) {
      h += `<details${blockers.length ? '' : ' open'}><summary class="small text-muted mb-2">`
        + `${rest.length} further finding(s)</summary>`
        + rest.map(findingHtml).join('') + `</details>`;
    }
    if (!a.findings.length && !(a.gaps || []).length) {
      h += `<p class="small mb-0 text-muted">No rule matched the prose for this `
        + `move. That is not a guarantee — it means SATOM found nothing it `
        + `recognises, over sections it did read.</p>`;
    }
    h += `<div class="small text-muted mt-2">`
      + `Rule set <code>${esc(a.rules_digest)}</code> · `
      + `${a.read.length} section(s) read · ${esc(a.generated_at)}</div></div>`;
    return h;
  }

  async function loadScoutAdvisory(cur, tgt) {
    const view = $('rnScoutView');
    if (!view) return;
    view.innerHTML = '<span class="small text-muted">Scout is reading the upgrade notes…</span>';
    try {
      const a = await get(`${BASE}/advisory?${new URLSearchParams({ current: cur, target: tgt })}`);
      view.innerHTML = renderScout(a);
    } catch (e) {
      let body = {}; try { body = JSON.parse(e.message); } catch (_) {}
      if (body.disabled) {
        view.innerHTML = scoutOffHtml(body.error || 'Scout is switched off.', IS_ADMIN);
        const b = $('rnScoutEnable');
        if (b) b.addEventListener('click', () => setScout(true));
      } else {
        view.innerHTML = `<p class="small text-warning">Scout advisory: `
          + `${esc(body.error || e.message)}</p>`;
      }
    }
  }

  async function setScout(on) {
    try {
      const r = await post(`${BASE}/scout-switch`, { enabled: on });
      const sw = $('rnScoutOn');
      if (sw) sw.checked = !!r.enabled;
      const cur = $('rnAdvCurrent').value, tgt = $('rnAdvTarget').value;
      if (cur && tgt && cur !== tgt) loadScoutAdvisory(cur, tgt);
      else $('rnScoutView').innerHTML = r.enabled ? '' : scoutOffHtml('Scout is switched off.', IS_ADMIN);
      window.FW?.toast?.(r.enabled ? 'Scout advisory on.' : 'Scout advisory off.', 'info');
    } catch (e) {
      window.FW?.toast?.('Could not change the Scout switch: ' + e.message, 'warning');
    }
  }

  async function showAdvisory() {
    const cur = $('rnAdvCurrent').value, tgt = $('rnAdvTarget').value;
    const view = $('rnAdvView');
    if (cur && tgt && cur !== tgt) loadScoutAdvisory(cur, tgt);
    const p = new URLSearchParams({ current: cur, target: tgt });
    let d;
    try { d = await get(`${BASE}/advise?${p}`); }
    catch (e) {
      let msg = e.message; try { msg = JSON.parse(e.message).error || msg; } catch (_) {}
      view.innerHTML = `<p class="text-warning">${esc(msg)}</p>`; return;
    }
    const verb = d.is_upgrade ? 'Upgrading' : 'Downgrading';
    let html =
      `<h5>${verb} ${PLABEL} ${esc(d.current)} → ${esc(d.target)}</h5>` +
      `<p><b>${d.resolved.length}</b> issue(s) resolved in this range · ` +
      `<b>${d.known_in_target.length}</b> known in target · ` +
      `<b>${d.notes.length}</b> upgrade note(s).</p>`;
    if (!d.is_upgrade) html += `<p class="text-warning">⚠ This is a downgrade — Fortinet generally does not support downgrades; review carefully.</p>`;
    html += `<h6 class="text-success">✔ Resolved by upgrading (${d.resolved.length})</h6>`;
    html += issueListHtml(d.resolved, 'No resolved issues recorded in this range (have you scanned these versions?).');
    html += `<h6 class="text-warning">⚠ Known issues you'd inherit in ${esc(d.target)} (${d.known_in_target.length})</h6>`;
    html += issueListHtml(d.known_in_target, 'No known issues recorded for the target.');
    html += '<h6>📋 Upgrade notes</h6>';
    if (d.notes.length) {
      d.notes.forEach((n) => {
        const link = n.source_url ? ` <a href="${esc(n.source_url)}" target="_blank" rel="noopener">↗</a>` : '';
        html += `<p class="mb-1"><b>${esc(n.version)} — ${esc(n.title)}</b>${link}</p>`;
        html += `<p class="text-muted" style="white-space:pre-wrap">${esc((n.content || '').slice(0, 1500))}</p>`;
      });
    } else {
      html += '<p class="text-muted"><i>No upgrade notes recorded in this range.</i></p>';
    }
    view.innerHTML = html;
  }

  // ---- Notes tab ----
  async function searchNotes() {
    const p = new URLSearchParams({
      version: $('rnNoteVersion').value || '',
      section: $('rnNoteSection').value || '',
      q: $('rnNoteQuery').value.trim(),
    });
    let d;
    try { d = await get(`${BASE}/notes?${p}`); } catch (e) { return; }
    const view = $('rnNoteView');
    if (!d.sections.length) { view.innerHTML = '<span class="text-muted">No matching sections.</span>'; return; }
    view.innerHTML = d.sections.map((s) => {
      const link = s.source_url ? ` <a href="${esc(s.source_url)}" target="_blank" rel="noopener">↗</a>` : '';
      return `<h6>${esc(s.version)} — ${esc(s.title)}${link}</h6>` +
        `<p style="white-space:pre-wrap">${esc((s.content || '').slice(0, 4000))}</p><hr>`;
    }).join('');
  }

  // ---- Reload corpus (was 'Sync from git' — see views/release_notes.py) ----
  async function reloadCorpus() {
    const btn = $('rnReloadBtn');
    btn.disabled = true;
    const old = btn.innerHTML;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Reloading…';
    try {
      const d = await post(`${BASE}/reload`);
      window.FW?.toast?.(d.message, d.counts && d.counts.issues ? 'info' : 'warning');
      await loadData();
    } catch (e) {
      window.FW?.toast?.('Reload failed: ' + e.message, 'danger');
    } finally {
      btn.disabled = false; btn.innerHTML = old;
    }
  }

  // ---- Scan from Fortinet ----
  function startScanPolling() {
    if (scanPoll) return;
    const out = $('rnScanOut');
    if (out) out.classList.remove('d-none');
    const startBtn = $('rnScanStart');
    if (startBtn) startBtn.disabled = true;
    const bgBtn = $('rnScanBg');
    if (bgBtn) bgBtn.classList.remove('d-none');
    scanPoll = setInterval(async () => {
      let st;
      try { st = await get(`${BASE}/scan/status`); } catch (e) { return; }
      if (!st || typeof st !== 'object') {
        clearInterval(scanPoll); scanPoll = null;
        if (startBtn) startBtn.disabled = false;
        if (bgBtn) bgBtn.classList.add('d-none');
        const m = 'Lost the scan status (session or ADOM permission changed?). '
          + 'Reload the page and try again.';
        if (out) out.textContent = m;
        window.FW?.toast?.(m, 'danger');
        return;
      }
      if (out) { out.textContent = (st.lines || []).join('\n'); out.scrollTop = out.scrollHeight; }
      if (!st.running) {
        clearInterval(scanPoll); scanPoll = null;
        if (startBtn) startBtn.disabled = false;
        if (bgBtn) bgBtn.classList.add('d-none');
        window.FW?.refreshBell?.();
        if (st.error) window.FW?.toast?.('Scan failed: ' + st.error, 'danger');
        else if (st.result && (st.result.unreadable || []).length) {
          // Harvested something AND failed to read a published section: the corpus
          // is incomplete for those versions. Calling that 'done' is how the 8.0.7
          // docset went missing for two releases.
          const u = st.result.unreadable;
          const vs = [...new Set(u.map((x) => x.version))].join(', ');
          window.FW?.toast?.(
            `Scan INCOMPLETE — ${st.result.scanned} version(s) harvested, but `
            + `${u.length} published section(s) could not be read (${vs}). See the log.`,
            'warning');
        } else if (st.result) window.FW?.toast?.(
          `Scan done — ${st.result.scanned} version(s), ${st.result.new_issues} issue(s).`, 'success');
        await loadData();
      }
    }, 1500);
  }

  // ---- version discovery (the scan's input, not a guess) ----
  let discovered = [];          // [{version, major, in_corpus, checked}]
  let discovering = false;

  function transports() {
    return {
      use_direct: $('rnDirect').checked,
      use_firecrawl: $('rnFc').checked,
      firecrawl_endpoint: $('rnFcEndpoint').value,
      firecrawl_key: $('rnFcKey').value,
    };
  }

  function pickedVersions() {
    return discovered.filter((r) => r.checked).map((r) => r.version);
  }

  function updatePickCount() {
    const n = pickedVersions().length;
    const el = $('rnPickCount');
    if (el) el.textContent = n ? `${n} version(s) selected` : 'nothing selected';
    const btn = $('rnScanStart');
    if (btn) btn.disabled = !n;
  }

  function renderVersions() {
    const box = $('rnVersionPick'); const bar = $('rnVersionBar');
    if (!box || !bar) return;
    if (!discovered.length) { box.classList.add('d-none'); bar.classList.add('d-none'); return; }
    const byMajor = new Map();
    discovered.forEach((r) => {
      if (!byMajor.has(r.major)) byMajor.set(r.major, []);
      byMajor.get(r.major).push(r);
    });
    const parts = [];
    byMajor.forEach((rows, maj) => {
      const cells = rows.map((r) => (
        `<label class="form-check-label small me-3 text-nowrap">`
        + `<input class="form-check-input rn-ver me-1" type="checkbox" value="${esc(r.version)}"`
        + `${r.checked ? ' checked' : ''}> ${esc(r.version)}`
        + (r.in_corpus ? '' : ' <span class="badge text-bg-warning">new</span>')
        + `</label>`)).join(' ');
      parts.push(`<div class="mb-1"><strong class="small me-2">${esc(maj)}</strong>${cells}</div>`);
    });
    box.innerHTML = parts.join('');
    box.classList.remove('d-none'); bar.classList.remove('d-none');
    box.querySelectorAll('.rn-ver').forEach((cb) => cb.addEventListener('change', () => {
      const row = discovered.find((r) => r.version === cb.value);
      if (row) row.checked = cb.checked;
      updatePickCount();
    }));
    updatePickCount();
  }

  async function discoverVersions() {
    if (discovering) return;
    discovering = true;
    const hint = $('rnDiscoverHint'); const btn = $('rnDiscover');
    if (btn) btn.disabled = true;
    if (hint) hint.textContent = 'Reading docs.fortinet.com…';
    try {
      const d = await post(`${BASE}/discover`, transports());
      // Pre-tick exactly what the corpus is MISSING. Re-scanning what we already
      // hold is the slow, pointless default the old form had; leaving everything
      // unticked would be a dead end.
      discovered = (d.versions || []).map((r) => ({ ...r, checked: !r.in_corpus }));
      renderVersions();
      if (hint) {
        hint.textContent = `${d.count} version(s) published · ${d.new} not in the corpus`
          + (d.new ? ' (pre-ticked)' : ' — the corpus is up to date');
      }
    } catch (e) {
      let msg = e.message; try { msg = JSON.parse(e.message).error || msg; } catch (_) {}
      if (hint) hint.innerHTML = `<span class="text-danger">${esc(msg)}</span>`;
      window.FW?.toast?.('Discover: ' + msg, 'warning');
    } finally {
      discovering = false;
      if (btn) btn.disabled = false;
    }
  }

  async function startScan() {
    const picked = pickedVersions();
    if (!picked.length) {
      window.FW?.toast?.('Tick at least one version (use Discover versions).', 'warning');
      return;
    }
    const body = {
      versions: picked,
      ...transports(),
    };
    const out = $('rnScanOut');
    if (out) { out.classList.remove('d-none'); out.textContent = 'Starting…'; }
    try {
      const r = await post(`${BASE}/scan`, body);
      if (!r || typeof r !== 'object' || !r.started) {
        throw new Error('Could not start the scan — your session or ADOM '
          + 'permission may have changed. Reload the page and try again.');
      }
      startScanPolling();
    } catch (e) {
      let msg = e.message; try { msg = JSON.parse(e.message).error || msg; } catch (_) {}
      window.FW?.toast?.('Scan: ' + msg, 'warning');
      if (out) out.textContent = msg;
    }
  }

  // ---- wire-up ----
  modalEl.addEventListener('shown.bs.modal', () => {
    if (!loaded) { loaded = true; loadData(); }
  });

  $('rnIssueVersion').addEventListener('change', searchIssues);
  $('rnIssueStatus').addEventListener('change', searchIssues);
  $('rnIssueTopic').addEventListener('change', searchIssues);
  $('rnIssueQuery').addEventListener('input', debounce(searchIssues, 300));
  $('rnAdvShow').addEventListener('click', showAdvisory);
  $('rnScoutOn')?.addEventListener('change', (e) => setScout(e.target.checked));
  $('rnNoteVersion').addEventListener('change', searchNotes);
  $('rnNoteSection').addEventListener('change', searchNotes);
  $('rnNoteQuery').addEventListener('input', debounce(searchNotes, 300));
  $('rnReloadBtn').addEventListener('click', reloadCorpus);

  const scanToggle = $('rnScanToggle');
  if (scanToggle) scanToggle.addEventListener('click', () => {
    const panel = $('rnScanPanel');
    panel.classList.toggle('d-none');
    // Opening the panel with an empty list would make Start scan permanently
    // disabled with no explanation, so the first open discovers.
    if (!panel.classList.contains('d-none') && !discovered.length) discoverVersions();
  });
  const discoverBtn = $('rnDiscover');
  if (discoverBtn) discoverBtn.addEventListener('click', discoverVersions);
  const setAll = (fn) => () => {
    discovered.forEach((r) => { r.checked = fn(r); });
    renderVersions();
  };
  $('rnPickNew')?.addEventListener('click', setAll((r) => !r.in_corpus));
  $('rnPickAll')?.addEventListener('click', setAll(() => true));
  $('rnPickNone')?.addEventListener('click', setAll(() => false));
  const scanStart = $('rnScanStart');
  if (scanStart) scanStart.addEventListener('click', startScan);
  const scanBg = $('rnScanBg');
  if (scanBg) scanBg.addEventListener('click', () => {
    const inst = (window.bootstrap && bootstrap.Modal.getInstance(modalEl))
      || (window.bootstrap && bootstrap.Modal.getOrCreateInstance(modalEl));
    if (inst) inst.hide();
    window.FW?.toast?.('Scan running in background — a bell notification will appear when it finishes.', 'info');
  });
})();
