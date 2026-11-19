/* diagram_studio_import.js — Import wizard, steps 1 (Import) and 2 (Recognition).
 *
 * Files come by drag & drop or the file browser; each gets a type badge from
 * its extension (a hint: the server detects the real format), a preview for
 * images and a page picker for PDF / TIFF / multi-page draw.io and Visio
 * (POST /api/imports/pages; PDF pages show thumbnails). The upload is one
 * multipart POST with upload progress; then every job is polled with
 * back-off (0.5 s, then 1 s, then 2 s) until it is ok, failed or refused.
 */
(function () {
  'use strict';
  var DS = window.DS, h = DS.h;
  var root = document.getElementById('dsImport');
  if (!root || root.dataset.dsBooted) return;
  root.dataset.dsBooted = '1';
  var cfg = DS.config(), api = DS.Api(cfg), lim = cfg.limits || {};
  var MAX_FILES = lim.files || 20, MAX_MB = lim.file_mb || 50, MAX_PAGES = lim.pdf_pages || 50;
  var TYPES = {
    drawio: 'draw.io', xml: 'draw.io', svg: 'SVG', vsdx: 'Visio', vdx: 'Visio', vsdm: 'Visio', vsd: 'Visio (legacy)', pdf: 'PDF',
    png: 'Image', jpg: 'Image', jpeg: 'Image', gif: 'Image', webp: 'Image', bmp: 'Image', tif: 'TIFF image', tiff: 'TIFF image',
    mmd: 'Mermaid', mermaid: 'Mermaid', dot: 'Graphviz', gv: 'Graphviz'
  };
  var MULTI = { pdf: 1, tif: 1, tiff: 1, drawio: 1, xml: 1, vsdx: 1, vdx: 1, vsdm: 1 };
  var IMG = { png: 1, jpg: 1, jpeg: 1, gif: 1, webp: 1, bmp: 1 };
  var supported = Array.isArray(cfg.extensions) && cfg.extensions.length ? new Set(cfg.extensions.map(function (x) { return String(x).replace(/^\./, '').toLowerCase(); })) : null;
  var files = [];   // {file, ext, ok, why, pages: null|[{id,name}], pick: Set|null, staged}
  var drop = document.getElementById('dsDrop'), input = document.getElementById('dsFiles'), listEl = document.getElementById('dsFileList');
  var startBtn = document.getElementById('dsStart');

  function ext(name) { var m = /\.([A-Za-z0-9]+)$/.exec(name || ''); return m ? m[1].toLowerCase() : ''; }
  function step(n) {
    DS.$$('.ds-step', root).forEach(function (li) {
      var k = Number(li.dataset.step);
      li.classList.toggle('done', k < n);
      if (k === n) li.setAttribute('aria-current', 'step'); else li.removeAttribute('aria-current');
    });
    document.getElementById('dsStep1').hidden = n !== 1;
    document.getElementById('dsStep2').hidden = n !== 2;
  }

  // -------------------------------------------------------------- step 1
  function add(list) {
    Array.prototype.forEach.call(list, function (f) {
      if (files.some(function (x) { return x.file.name === f.name && x.file.size === f.size; })) return;
      var e = ext(f.name);
      var it = { file: f, ext: e, ok: true, why: '', pages: null, pick: null, staged: null };
      if (e === 'vsd') { it.ok = false; it.why = 'Legacy binary Visio is not read. Save it as .vsdx in Visio first.'; }
      else if (!TYPES[e] || (supported && !supported.has(e))) { it.ok = false; it.why = 'Unsupported file type' + (e ? ' (.' + e + ')' : '') + '.'; }
      else if (f.size > MAX_MB * 1048576) { it.ok = false; it.why = 'Larger than ' + MAX_MB + ' MiB.'; }
      else if (f.size === 0) { it.ok = false; it.why = 'The file is empty.'; }
      files.push(it);
    });
    if (files.length > MAX_FILES) DS.toast('At most ' + MAX_FILES + ' files per import: only the first ' + MAX_FILES + ' are kept.', 'warning');
    files = files.slice(0, MAX_FILES);
    renderFiles();
  }
  function renderFiles() {
    DS.clear(listEl);
    files.forEach(function (it, i) {
      var thumb = h('div', { class: 'ds-file-thumb', 'aria-hidden': 'true' }, DS.icon(IMG[it.ext] ? 'image' : it.ext === 'pdf' ? 'file-earmark-pdf' : it.ext === 'svg' ? 'filetype-svg' : 'file-earmark'));
      if (IMG[it.ext] && it.ok && it.file.size < 8 * 1048576) {
        var fr = new FileReader();
        fr.onload = function () { if (/^data:image\/(png|jpeg|gif|webp|bmp);base64,/.test(fr.result)) { DS.clear(thumb).appendChild(h('img', { src: fr.result, alt: '' })); } };
        fr.readAsDataURL(it.file);
      }
      var badge = it.ok ? DS.badge('info', TYPES[it.ext] || it.ext, 'file-earmark-check') : DS.badge('danger', 'Will be refused', 'x-octagon');
      var meta = h('div', { class: 'ds-file-meta' }, [badge, h('span', { text: DS.fmtBytes(it.file.size) }), it.ok ? null : h('span', { text: it.why })]);
      var body = h('div', null, [h('div', { class: 'ds-file-name', text: it.file.name }), meta]);
      if (it.ok && MULTI[it.ext]) body.appendChild(pagePicker(it));
      var rm = h('button', { type: 'button', class: 'btn btn-sm ds-icon-btn', 'aria-label': 'Remove ' + it.file.name, title: 'Remove' }, DS.icon('x-lg'));
      rm.addEventListener('click', function () { dropProbe(it); files.splice(i, 1); renderFiles(); });
      listEl.appendChild(h('li', { class: 'ds-file' }, [thumb, body, rm]));
    });
    startBtn.disabled = !files.some(function (f) { return f.ok; });
  }
  function pagePicker(it) {
    var box = h('div', { class: 'ds-pages-pick' });
    var summary = h('span', { class: 'small', text: it.pick ? it.pick.size + ' page(s) selected' : 'All pages' });
    var btn = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary' }, [DS.icon('files'), ' ', it.pages ? 'Change pages' : 'Choose pages…']);
    btn.addEventListener('click', function () { choosePages(it, btn); });
    box.appendChild(h('div', { class: 'ds-btnrow' }, [btn, summary]));
    if (it.pages) {
      var grid = h('div', { class: 'ds-thumbs', role: 'group', 'aria-label': 'Pages of ' + it.file.name });
      var all = h('input', { type: 'checkbox', class: 'form-check-input', checked: !it.pick, id: 'dsAll' + it.staged });
      all.addEventListener('change', function () { it.pick = all.checked ? null : new Set(it.pages.map(function (p, j) { return j + 1; })); renderFiles(); });
      box.appendChild(h('div', { class: 'form-check mt-2' }, [all, h('label', { class: 'form-check-label small', for: all.id, text: 'All ' + it.pages.length + ' pages' })]));
      it.pages.forEach(function (p, j) {
        var n = j + 1;
        var on = !it.pick || it.pick.has(n);
        var cb = h('input', { type: 'checkbox', checked: on, 'aria-label': 'Page ' + n + (p.name ? ': ' + p.name : '') });
        cb.addEventListener('change', function () {
          if (!it.pick) it.pick = new Set(it.pages.map(function (q, k) { return k + 1; }));
          if (cb.checked) it.pick.add(n); else it.pick.delete(n);
          if (it.pick.size === it.pages.length) it.pick = null;
          renderFiles();
        });
        var kids = [cb];
        if (it.thumbs) kids.push(h('img', { src: api.jobThumb(it.staged, n), alt: '', loading: 'lazy' }));
        kids.push(h('span', { text: p.name || 'Page ' + n }));
        grid.appendChild(h('label', { class: 'ds-thumb' + (on ? ' ds-on' : '') }, kids));
      });
      box.appendChild(grid);
      if (it.ext === 'pdf' && it.pages.length > MAX_PAGES) box.appendChild(h('div', { class: 'small fw-alert-warning p-1 mt-1', text: 'Only ' + MAX_PAGES + ' PDF pages are read per import: choose the ones you need.' }));
    }
    return box;
  }
  function choosePages(it, btn) {
    btn.disabled = true;
    var fd = new FormData();
    fd.append('file', it.file, it.file.name);
    DS.http('POST', api.importPages(), fd).then(function (res) {
      btn.disabled = false;
      if (!res.ok) { DS.toast(DS.errorText(res, it.file.name), res.status === 503 ? 'warning' : 'danger'); return; }
      it.pages = (res.data.pages || []).slice(0, 500);
      dropProbe(it);   // a second "Change pages" replaces the earlier probe
      it.staged = res.data.id || res.data.job || null;
      it.thumbs = !!res.data.thumbnails && !!it.staged;
      if (!it.pages.length) DS.toast(it.file.name + ': no pages found.', 'warning');
      renderFiles();
    }, function (e) { btn.disabled = false; DS.toast(e.message, 'danger'); });
  }
  /* The page-picker probe (a "staged" import record) is only needed while the
   * picker is on screen: removed file, replaced probe, upload done or page
   * left -> DELETE it, best effort (the server also purges them after 1 h). */
  function deleteJob(id, keepalive) {
    return fetch(api.job(id), { method: 'DELETE', credentials: 'same-origin', keepalive: !!keepalive,
      headers: { 'X-CSRFToken': DS.csrf(), 'Accept': 'application/json' } });
  }
  function dropProbe(it, keepalive) {
    if (!it || !it.staged) return;
    var id = it.staged;
    it.staged = null;
    deleteJob(id, keepalive).catch(function () { /* best effort */ });
  }
  function dropAllProbes(keepalive) { files.forEach(function (it) { dropProbe(it, keepalive); }); }
  DS.on(window, 'pagehide', function () { dropAllProbes(true); });
  DS.on(document, 'turbo:before-visit', function () { if (document.body.contains(root)) dropAllProbes(true); });

  function spec(it) {
    if (!it.pick) return 'all';
    var ns = Array.from(it.pick).sort(function (a, b) { return a - b; }), out = [], i = 0;
    while (i < ns.length) { var j = i; while (j + 1 < ns.length && ns[j + 1] === ns[j] + 1) j++; out.push(i === j ? String(ns[i]) : ns[i] + '-' + ns[j]); i = j + 1; }
    return out.join(',') || 'all';
  }

  drop.addEventListener('dragover', function (ev) { ev.preventDefault(); drop.classList.add('ds-over'); });
  drop.addEventListener('dragleave', function () { drop.classList.remove('ds-over'); });
  drop.addEventListener('drop', function (ev) { ev.preventDefault(); drop.classList.remove('ds-over'); add(ev.dataTransfer.files); });
  drop.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); input.click(); } });
  input.addEventListener('change', function () { add(input.files); input.value = ''; });

  // ------------------------------------------------------------- upload
  startBtn.addEventListener('click', function () {
    var ok = files.filter(function (f) { return f.ok; });
    if (!ok.length) return;
    var pick = ok.filter(function (f) { return f.ext === 'pdf' && f.pick && f.pick.size > MAX_PAGES; });
    if (pick.length) { DS.toast('Choose at most ' + MAX_PAGES + ' PDF pages.', 'warning'); return; }
    var fd = new FormData(), pages = {};
    ok.forEach(function (it) { fd.append('files[]', it.file, it.file.name); pages[it.file.name] = spec(it); });
    var name = document.getElementById('dsOptName').value.trim();
    fd.append('options', JSON.stringify({ pages: pages, ocr: document.getElementById('dsOptOcr').checked, classify: document.getElementById('dsOptClassify').checked,
      vision: document.getElementById('dsOptVision').checked, name: name || undefined }));
    startBtn.disabled = true;
    step(2);
    var jobsEl = document.getElementById('dsJobs');
    DS.clear(jobsEl);
    var up = h('div', { class: 'fw-card ds-job' }, [h('div', { class: 'ds-job-head' }, [DS.icon('cloud-arrow-up'), h('strong', { text: 'Uploading ' + ok.length + ' file(s)…' })]), h('div', { class: 'ds-progress', role: 'progressbar', 'aria-label': 'Upload', 'aria-valuemin': 0, 'aria-valuemax': 100 }, h('div'))]);
    jobsEl.appendChild(up);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', api.imports());
    xhr.setRequestHeader('X-CSRFToken', DS.csrf());
    xhr.setRequestHeader('Accept', 'application/json');
    xhr.upload.addEventListener('progress', function (ev) {
      if (!ev.lengthComputable) return;
      var pc = Math.round(ev.loaded / ev.total * 100);
      var bar = up.querySelector('.ds-progress');
      bar.firstChild.style.width = pc + '%'; bar.setAttribute('aria-valuenow', pc);
    });
    xhr.addEventListener('load', function () {
      var data = null;
      try { data = JSON.parse(xhr.responseText); } catch (e) { data = null; }
      up.remove();
      if (xhr.status < 200 || xhr.status >= 300 || !data || !Array.isArray(data.jobs)) {
        jobsEl.appendChild(h('div', { class: 'fw-alert-danger p-2', role: 'alert' }, [DS.icon('x-octagon'), ' ', DS.errorText({ status: xhr.status, data: data }, 'Upload failed')]));
        startBtn.disabled = false;
        return;
      }
      dropAllProbes(false);   // the upload carries the files; the probes are done
      files = [];
      renderFiles();
      data.jobs.forEach(function (j) { track(j); });
    });
    xhr.addEventListener('error', function () { up.remove(); jobsEl.appendChild(h('div', { class: 'fw-alert-danger p-2', role: 'alert', text: 'The server could not be reached. Check the connection and try again.' })); startBtn.disabled = false; });
    xhr.send(fd);
  });
  document.getElementById('dsMore').addEventListener('click', function () { step(1); });

  // ---------------------------------------------------------- recognition
  var STATUS = {
    queued: ['secondary', 'Queued', 'hourglass-split'], running: ['info', 'Recognising', 'arrow-repeat'], ok: ['success', 'Done', 'check-circle'],
    failed: ['danger', 'Failed', 'x-octagon'], refused: ['warning', 'Refused', 'slash-circle'], staged: ['secondary', 'Staged', 'pause-circle']
  };
  var jobs = new Map();
  function summary() {
    var c = { total: 0, done: 0, bad: 0 };
    jobs.forEach(function (j) { c.total++; if (j.status === 'ok') c.done++; if (j.status === 'failed') c.bad++; if (j.status === 'refused') c.ref = (c.ref || 0) + 1; });
    document.getElementById('dsJobsSummary').textContent = c.done + ' of ' + c.total + ' done' + (c.ref ? ', ' + c.ref + ' refused' : '') + (c.bad ? ', ' + c.bad + ' failed' : '');
  }
  function track(j) {
    var card = h('article', { class: 'fw-card ds-job', 'aria-label': j.filename });
    document.getElementById('dsJobs').appendChild(card);
    var st = { id: j.id, card: card, polls: 0, status: j.status, data: j };
    jobs.set(j.id, st);
    draw(st);
    if (j.status === 'queued' || j.status === 'running') schedule(st);
  }
  function delay(n) { return n < 4 ? 500 : n < 14 ? 1000 : 2000; }
  function schedule(st) { st.timer = setTimeout(function () { poll(st); }, delay(st.polls)); }
  function poll(st) {
    if (!document.body.contains(root) || st.gone) return;
    st.polls++;
    DS.http('GET', api.job(st.id)).then(function (res) {
      if (!res.ok) { st.err = DS.errorText(res, 'Status'); draw(st); if (res.status >= 500 || res.status === 0) schedule(st); return; }
      st.err = null;
      st.data = res.data; st.status = res.data.status;
      draw(st);
      if (st.status === 'queued' || st.status === 'running') schedule(st);
    }, function (e) { st.err = e.message; draw(st); schedule(st); });
  }
  function stat(n, label) { return h('div', { class: 'ds-stat' }, [h('b', { text: n === undefined || n === null ? '—' : String(n) }), h('span', { text: label })]); }
  function draw(st) {
    var j = st.data || {}, s = STATUS[st.status] || STATUS.queued;
    var card = st.card;
    DS.clear(card);
    card.appendChild(h('div', { class: 'ds-job-head' }, [DS.icon('file-earmark'), h('strong', { text: j.filename || st.id }), DS.badge(s[0], s[1], s[2])]));
    var running = st.status === 'queued' || st.status === 'running';
    var pct = st.status === 'queued' ? 8 : st.status === 'running' ? null : 100;
    var bar = h('div', { class: 'ds-progress' + (pct === null ? ' ds-indet' : ''), role: 'progressbar', 'aria-label': 'Progress of ' + (j.filename || ''), 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-valuenow': pct === null ? null : pct, 'aria-valuetext': s[1] }, h('div'));
    if (pct !== null) bar.firstChild.style.width = pct + '%';
    card.appendChild(bar);
    if (j.format) card.appendChild(h('div', { class: 'small ds-muted', text: 'Format: ' + j.format + (j.duration_ms ? ' · ' + (j.duration_ms / 1000).toFixed(1) + ' s' : '') }));
    if (st.err) card.appendChild(h('div', { class: 'small fw-alert-warning p-1 mt-1', role: 'status', text: st.err + ' — retrying.' }));
    if (st.status === 'refused') {
      // a deliberate refusal: the file is not something the reader accepts
      card.appendChild(h('div', { class: 'fw-alert-warning small p-2 mt-2', role: 'alert', 'data-outcome': 'refused' }, [DS.icon('slash-circle'), ' ',
        h('strong', { text: 'Not imported: ' }), j.error || 'the file was refused.']));
      card.appendChild(h('p', { class: 'small ds-muted mt-1 mb-0', text: 'Nothing broke: fix or convert the file and import it again.' }));
      card.appendChild(h('div', { class: 'ds-btnrow mt-2' }, [discardBtn(st)]));
      summary();
      return;
    }
    if (st.status === 'failed') {
      // a crash, a timeout or a memory limit while reading
      card.appendChild(h('div', { class: 'fw-alert-danger small p-2 mt-2', role: 'alert', 'data-outcome': 'failed' }, [DS.icon('x-octagon'), ' ',
        h('strong', { text: 'Recognition failed: ' }), j.error || 'the reader stopped.']));
      card.appendChild(h('p', { class: 'small ds-muted mt-1 mb-0', text: 'The reader crashed, ran out of time or of memory. Try again, or try fewer pages.' }));
      card.appendChild(h('div', { class: 'ds-btnrow mt-2' }, [discardBtn(st)]));
      summary();
      return;
    }
    if (running) {
      card.appendChild(h('p', { class: 'small ds-muted mt-1 mb-0', text: st.status === 'queued' ? 'Waiting for a free worker…' : 'Reading the file, detecting shapes, connectors and text…' }));
      card.appendChild(h('div', { class: 'ds-btnrow mt-2' }, [discardBtn(st)]));
      summary(); return;
    }
    var x = j.stats || {};
    card.appendChild(h('div', { class: 'ds-stat-grid' }, [stat(x.elements, 'elements'), stat(x.connectors, 'connectors'), stat(x.connected, 'connected'),
      stat(x.dangling, 'dangling'), stat(x.low_confidence, 'low confidence'), stat(x.unclassified, 'unclassified')]));
    var fams = (j.classification && j.classification.families) || x.families || {};
    var fk = Object.keys(fams);
    if (fk.length) card.appendChild(h('div', { class: 'ds-families', 'aria-label': 'Families' }, fk.map(function (f) { return DS.badge('primary', f + ' ' + fams[f]); })));
    var w = j.warnings || [];
    if (w.length) card.appendChild(h('details', { class: 'mt-2' }, [h('summary', { class: 'small', text: w.length + ' warning(s)' }), h('ul', { class: 'ds-warnings' }, w.slice(0, 100).map(function (t) { return h('li', { text: String(t) }); }))]));
    var review = h('a', { class: 'btn btn-sm btn-fw-primary', href: api.reviewPage(st.id) }, [DS.icon('clipboard-check'), ' Review']);
    var direct = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', title: 'Create the diagram without reviewing and open the editor' }, [DS.icon('box-arrow-up-right'), ' Accept as is']);
    direct.addEventListener('click', function () { acceptDirect(st, direct); });
    var acts = [review];
    if (cfg.mayEdit) acts.push(direct);
    if (j.diagram_id) acts = [h('a', { class: 'btn btn-sm btn-fw-secondary', href: api.editorPage(j.diagram_id) }, [DS.icon('pencil-square'), ' Open the diagram'])];
    acts.push(discardBtn(st));
    card.appendChild(h('div', { class: 'ds-btnrow mt-2' }, acts));
    summary();
  }
  /* What a discard removes, per status: a refused or failed import has no
   * result to lose; a finished one does, unless a diagram was made from it. */
  function discardText(status, made) {
    if (status === 'queued' || status === 'running') return 'Recognition stops and nothing is kept.';
    if (status === 'refused') return 'It was refused, so there is no result: only the record and the uploaded file are removed.';
    if (status === 'failed') return 'It failed, so there is no result: only the record and the uploaded file are removed.';
    if (made) return 'The diagram already created from it stays; the import record and its files are removed.';
    return 'Its recognised result is deleted; the file has to be imported again to review it.';
  }
  DS.discardText = discardText;
  /* Discard: DELETE the import (record, queued request, result, stored file). */
  function discardBtn(st) {
    var b = h('button', { type: 'button', class: 'btn btn-sm btn-fw-secondary', 'data-ds-discard': st.id, title: 'Remove this import and its files' }, [DS.icon('trash'), ' Discard']);
    b.addEventListener('click', function () {
      var name = (st.data && st.data.filename) || st.id;
      var made = st.data && st.data.diagram_id;
      DS.confirm('Discard import', 'Discard the import of "' + name + '"? ' + discardText(st.status, made), 'Discard', true).then(function (ok) {
        if (!ok) return;
        b.disabled = true;
        deleteJob(st.id).then(function (r) {
          if (!r.ok && r.status !== 404) {
            return r.json().catch(function () { return {}; }).then(function (d) { b.disabled = false; DS.toast(DS.errorText({ status: r.status, data: d }, 'Discarding failed'), 'danger'); });
          }
          clearTimeout(st.timer);
          st.gone = true;
          jobs.delete(st.id);
          st.card.remove();
          summary();
          DS.toast('Discarded "' + name + '".', 'success', 2500);
        }, function () { b.disabled = false; DS.toast('The server could not be reached.', 'danger'); });
      });
    });
    return b;
  }
  function acceptDirect(st, btn) {
    btn.disabled = true;
    var name = document.getElementById('dsOptName').value.trim() || (st.data.filename || 'Imported diagram').replace(/\.[^.]+$/, '');
    DS.http('POST', api.jobAccept(st.id), { name: name }).then(function (res) {
      if (res.ok || (res.status === 409 && res.data && res.data.url)) {
        var url = res.data.url || api.editorPage(res.data.id);
        if (window.Turbo) window.Turbo.visit(url); else window.location.assign(url);
        return;
      }
      btn.disabled = false;
      DS.toast(DS.errorText(res, 'Creating the diagram failed'), 'danger');
    }, function (e) { btn.disabled = false; DS.toast(e.message, 'danger'); });
  }
  step(1);
})();
