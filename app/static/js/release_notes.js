/* ============================================================
   OFortMAuT — release_notes.js
   Top-banner Release Notes modal. Same logic as the desktop page:
   Scan from Fortinet / Sync from git + Issues / Upgrade advisor / Notes.
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

  // ---- data load (first paint + after scan/sync) ----
  async function loadData() {
    let d;
    try { d = await get(`${BASE}/data`); }
    catch (e) { $('rnStatus').innerHTML = `<span class="text-danger">Failed to load: ${esc(e.message)}</span>`; return; }

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
        : 'No release-notes data yet — ask an admin to run a scan, or click <b>Sync from git</b>.';
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

  async function showAdvisory() {
    const cur = $('rnAdvCurrent').value, tgt = $('rnAdvTarget').value;
    const view = $('rnAdvView');
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

  // ---- Sync from git ----
  async function syncFromGit() {
    const btn = $('rnSyncBtn');
    btn.disabled = true;
    const old = btn.innerHTML;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Syncing…';
    try {
      const d = await post(`${BASE}/sync`);
      window.FW?.toast?.(d.message, 'info');
      await loadData();
    } catch (e) {
      window.FW?.toast?.('Sync failed: ' + e.message, 'danger');
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
        else if (st.result) window.FW?.toast?.(
          `Scan done — ${st.result.scanned} version(s), ${st.result.new_issues} issue(s).`, 'success');
        await loadData();
      }
    }, 1500);
  }

  async function startScan() {
    const body = {
      majors: $('rnMajors').value,
      all: $('rnAll').checked,
      use_direct: $('rnDirect').checked,
      use_firecrawl: $('rnFc').checked,
      firecrawl_endpoint: $('rnFcEndpoint').value,
      firecrawl_key: $('rnFcKey').value,
      publish: $('rnPublish').checked,
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
  $('rnNoteVersion').addEventListener('change', searchNotes);
  $('rnNoteSection').addEventListener('change', searchNotes);
  $('rnNoteQuery').addEventListener('input', debounce(searchNotes, 300));
  $('rnSyncBtn').addEventListener('click', syncFromGit);

  const scanToggle = $('rnScanToggle');
  if (scanToggle) scanToggle.addEventListener('click', () => $('rnScanPanel').classList.toggle('d-none'));
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
