/* ============================================================
   SATOM — release_notes.js
   Top-banner Release Notes modal. Same logic as the desktop page:
   Reload corpus + Issues / Upgrade advisor / Notes, over the corpus that
   signed knowledge packs bring (no vendor-site scan since SATOM 3.0).
   Backend: app/views/release_notes.py
   ============================================================ */
'use strict';

(function () {
  const modalEl = document.getElementById('releaseNotesModal');
  if (!modalEl) return;

  const BASE = '/release-notes';
  const PRODUCT = (document.querySelector('meta[name="current-product"]') || {}).content || 'fortiweb';
  const PLABEL = {
    fortiweb: 'FortiWeb', fortiadc: 'FortiADC',
    fortiauthenticator: 'FortiAuthenticator', fortianalyzer: 'FortiAnalyzer',
  }[PRODUCT] || 'Fortinet';
  let loaded = false;
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

  // "Knowledge from <pack> (<date>)" + a warning when older than 30 days.
  function knowledgeHtml(k) {
    if (!k || !k.pack) {
      return '<span class="fw-badge fw-badge-warning">no knowledge pack</span> '
        + '<span class="text-muted">imported on this node yet.</span>';
    }
    const age = (k.age_days == null) ? '' : ` · ${k.age_days} day(s) old`;
    const badge = k.stale
      ? ` <span class="fw-badge fw-badge-warning" title="Older than ${esc(k.stale_days)} days — import a newer knowledge pack">stale</span>`
      : '';
    return `<i class="bi bi-book text-muted me-1"></i>Knowledge from <code>${esc(k.pack)}</code> `
      + `(${esc(k.date || '?')})${age}${badge}`;
  }

  // ---- data load (first paint + after reload) ----
  async function loadData() {
    let d;
    try { d = await get(`${BASE}/data`); }
    catch (e) { $('rnStatus').innerHTML = `<span class="text-danger">Failed to load: ${esc(e.message)}</span>`; return; }

    const sw = $('rnScoutOn');
    if (sw) sw.checked = !!d.scout_enabled;
    const c = d.counts;
    if (c.issues) {
      const gen = c.generated_at ? ` · corpus written ${esc(c.generated_at)}` : '';
      $('rnStatus').innerHTML =
        `<i class="bi bi-check-circle text-success"></i> ${c.issues} issues ` +
        `(${c.known} known / ${c.resolved} resolved) · ${c.sections} sections · ` +
        `${c.versions} versions${gen}.`;
    } else {
      // Nothing imported: an empty list here would read as "no issues". Say
      // what is missing and where it comes from instead.
      $('rnStatus').innerHTML =
        `<i class="bi bi-cloud-slash text-warning"></i> ${esc(d.empty_reason)}`
        + (d.is_admin ? '' : ' Ask an administrator.');
    }
    const kn = $('rnKnowledge');
    if (kn) kn.innerHTML = knowledgeHtml(d.knowledge);

    // The builds the fleet runs but the corpus lacks are offered too, marked:
    // picking one shows WHY it is empty instead of an empty table.
    const picks = d.versions.concat((d.fleet_missing || []).map(
      (v) => ({ value: v, label: `${v} (in your fleet — no notes here)` })));
    fillSelect($('rnIssueVersion'), picks, { firstLabel: '(all versions)' });
    fillSelect($('rnNoteVersion'), picks, { firstLabel: '(all versions)' });
    fillSelect($('rnIssueTopic'), d.topics, { firstLabel: '(all topics)' });
    fillSelect($('rnNoteSection'), d.sections, { firstLabel: '(all sections)' });
    // advisor: newest-first, no "(all)" entry
    fillSelect($('rnAdvCurrent'), d.versions);
    fillSelect($('rnAdvTarget'), d.versions);
    if (d.versions.length > 1) {
      $('rnAdvTarget').selectedIndex = 0;          // newest
      $('rnAdvCurrent').selectedIndex = 1;         // one older
    }

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
    if (!d.issues.length && d.empty_reason) {
      // Nothing harvested for this build: say so (and, offline, where the
      // notes come from) rather than leave an empty table that reads as
      // "this build has no issues".
      tb.innerHTML = `<tr><td colspan="5" class="text-muted fst-italic">`
        + `<i class="bi bi-cloud-slash me-1"></i>${esc(d.empty_reason)}</td></tr>`;
      $('rnIssueCount').textContent = '';
      return;
    }
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
      // A destination-scoped finding is true from EVERY origin. Saying so is
      // not decoration: the rest of this panel is floors ("you are below
      // 7.6.1"), so an operator who reads a blocker here and assumes it is
      // about how old their appliance is will try to clear it by hopping —
      // and there is no hop that clears "do not install this version".
      + (f.data && f.data.scope === 'target'
        ? `<div class="small text-muted mt-1">Applies to the DESTINATION`
          + `${f.data.named ? ` (${esc(f.data.named)})` : ''} — this holds no `
          + `matter which version you upgrade from.`
          + `${f.data.condition
            ? ` It is conditional: ${esc(f.data.condition)}.` : ''}</div>`
        : '')
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
    if (a.knowledge) h += `<div class="small mb-2">${knowledgeHtml(a.knowledge)}</div>`;
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
        + `import a newer knowledge pack and ask again.</span></div>`;
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
    html += issueListHtml(d.resolved, 'No resolved issues recorded in this range (is a knowledge pack for these versions imported?).');
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
    if (!d.sections.length) {
      view.innerHTML = d.empty_reason
        ? `<span class="text-muted fst-italic"><i class="bi bi-cloud-slash me-1"></i>${esc(d.empty_reason)}</span>`
        : '<span class="text-muted">No matching sections.</span>';
      return;
    }
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
})();
