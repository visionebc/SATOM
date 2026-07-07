// Regex Lab — the professional pattern calculator for FortiWeb & FortiADC.
// Opened two ways:
//   • from a field's ".*" button  → FWRegexLab.open(inputEl, context, product)
//   • standalone from the header    → FWRegexLab.open(null, '', product, tab)
// Self-contained: builds its modal DOM once (works on full pages AND
// AJAX-injected editor fragments), tests patterns SERVER-SIDE (Python re ≈
// FortiWeb/FortiADC PCRE), previews the rewritten URL from $0 $1 … captures,
// ships a section example library + a token cheat sheet, and writes a proven
// pattern back into the field that opened it.
(function () {
  if (window.FWRegexLab) return;

  let targetInput = null;
  let product = 'fortiweb';
  let ctx = '';
  let cheatData = [];

  function el(tag, cls, html) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html !== undefined) e.innerHTML = html;
    return e;
  }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, c =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function $(id) { return document.getElementById(id); }

  function buildModal() {
    if ($('fw-rxlab')) return;
    const wrap = el('div');
    wrap.innerHTML = `
<div class="modal fade" id="fw-rxlab" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-xl modal-dialog-scrollable">
    <div class="modal-content">
      <div class="modal-header py-2">
        <h6 class="modal-title mb-0">
          <i class="bi bi-braces-asterisk me-1"></i>Regex Calculator
          <span class="text-muted small" id="fw-rxlab-ctx"></span>
        </h6>
        <div class="btn-group btn-group-sm ms-3" role="group" id="fw-rxlab-prod">
          <input type="radio" class="btn-check" name="fw-rxlab-prod" id="fw-rxlab-fw" value="fortiweb" autocomplete="off" checked>
          <label class="btn btn-outline-primary btn-sm" for="fw-rxlab-fw">FortiWeb</label>
          <input type="radio" class="btn-check" name="fw-rxlab-prod" id="fw-rxlab-fadc" value="fortiadc" autocomplete="off">
          <label class="btn btn-outline-primary btn-sm" for="fw-rxlab-fadc">FortiADC</label>
        </div>
        <button type="button" class="btn-close ms-auto" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body pt-2">
        <ul class="nav nav-tabs nav-fill small mb-3" id="fw-rxlab-tabs" role="tablist">
          <li class="nav-item"><button class="nav-link active" data-tab="test" type="button"><i class="bi bi-check2-circle me-1"></i>Match tester</button></li>
          <li class="nav-item"><button class="nav-link" data-tab="rewrite" type="button"><i class="bi bi-signpost-split me-1"></i>Rewrite / $captures</button></li>
          <li class="nav-item"><button class="nav-link" data-tab="library" type="button"><i class="bi bi-collection me-1"></i>Library</button></li>
          <li class="nav-item"><button class="nav-link" data-tab="cheat" type="button"><i class="bi bi-card-list me-1"></i>Cheat sheet</button></li>
        </ul>

        <!-- Shared pattern + samples -->
        <div class="row g-3" id="fw-rxlab-pane-io">
          <div class="col-lg-7">
            <label class="form-label small fw-bold mb-1">Pattern</label>
            <input type="text" class="form-control form-control-sm font-monospace" id="fw-rxlab-pattern"
                   placeholder="e.g. ^/admin(/.*)?$" autocomplete="off" spellcheck="false">
            <div id="fw-rxlab-rewrite-row" class="mt-2 d-none">
              <label class="form-label small fw-bold mb-1">Replacement <span class="text-muted fw-normal">(use $0 $1 … for captures)</span></label>
              <input type="text" class="form-control form-control-sm font-monospace" id="fw-rxlab-replacement"
                     placeholder="e.g. /new-shop/$1" autocomplete="off" spellcheck="false">
            </div>
            <div class="form-check form-check-inline mt-2">
              <input class="form-check-input" type="checkbox" id="fw-rxlab-ci">
              <label class="form-check-label small" for="fw-rxlab-ci">Case-insensitive</label>
            </div>
            <label class="form-label small fw-bold mb-1 mt-2">Test samples
              <span class="text-muted fw-normal">(one per line — paste real URLs / hosts / values)</span></label>
            <textarea class="form-control form-control-sm font-monospace" id="fw-rxlab-samples" rows="6"
                      placeholder="/admin/login.php&#10;/shop/cart&#10;/api/v2/users"></textarea>
            <div class="mt-2 small" id="fw-rxlab-verdict"></div>
            <div id="fw-rxlab-results" class="mt-1"></div>
          </div>
          <div class="col-lg-5">
            <div id="fw-rxlab-side-library">
              <label class="form-label small fw-bold mb-1">Examples <span class="text-muted fw-normal" id="fw-rxlab-lib-scope"></span></label>
              <div id="fw-rxlab-examples" class="list-group small mb-2" style="max-height:300px;overflow:auto"></div>
            </div>
            <div id="fw-rxlab-side-notes">
              <label class="form-label small fw-bold mb-1"><i class="bi bi-info-circle me-1"></i>Flavor notes</label>
              <ul class="small text-muted mb-0 ps-3" id="fw-rxlab-notes" style="max-height:260px;overflow:auto"></ul>
            </div>
          </div>
        </div>

        <!-- Cheat sheet pane -->
        <div id="fw-rxlab-pane-cheat" class="d-none">
          <div class="row g-3" id="fw-rxlab-cheat"></div>
        </div>
      </div>
      <div class="modal-footer py-2">
        <span class="me-auto small text-muted"><i class="bi bi-shield-check me-1"></i>Tested server-side against a PCRE-compatible engine — matches FortiWeb & FortiADC.</span>
        <button type="button" class="btn btn-sm btn-outline-secondary" data-bs-dismiss="modal">Close</button>
        <button type="button" class="btn btn-sm btn-fw-primary d-none" id="fw-rxlab-use"><i class="bi bi-box-arrow-in-down me-1"></i>Use this pattern</button>
      </div>
    </div>
  </div>
</div>`;
    document.body.appendChild(wrap.firstElementChild);

    const pat = $('fw-rxlab-pattern');
    const repl = $('fw-rxlab-replacement');
    const samples = $('fw-rxlab-samples');
    const ci = $('fw-rxlab-ci');
    let t = null;
    const kick = () => { clearTimeout(t); t = setTimeout(run, 300); };
    pat.addEventListener('input', kick);
    repl.addEventListener('input', kick);
    samples.addEventListener('input', kick);
    ci.addEventListener('change', run);

    // Tabs
    $('fw-rxlab-tabs').querySelectorAll('button[data-tab]').forEach(function (b) {
      b.addEventListener('click', function () { selectTab(b.dataset.tab); });
    });
    // Product switch
    $('fw-rxlab-prod').querySelectorAll('input').forEach(function (r) {
      r.addEventListener('change', function () {
        if (r.checked) { product = r.value; loadLibrary(); run(); }
      });
    });
    // Use-this-pattern
    $('fw-rxlab-use').addEventListener('click', function () {
      if (targetInput) {
        targetInput.value = pat.value;
        targetInput.dispatchEvent(new Event('input', { bubbles: true }));
        targetInput.dispatchEvent(new Event('change', { bubbles: true }));
      }
      hide();
    });
  }

  let curTab = 'test';
  function selectTab(tab) {
    curTab = tab;
    $('fw-rxlab-tabs').querySelectorAll('button[data-tab]').forEach(function (b) {
      b.classList.toggle('active', b.dataset.tab === tab);
    });
    const isCheat = tab === 'cheat';
    $('fw-rxlab-pane-io').classList.toggle('d-none', isCheat);
    $('fw-rxlab-pane-cheat').classList.toggle('d-none', !isCheat);
    // Replacement row only on the rewrite tab.
    $('fw-rxlab-rewrite-row').classList.toggle('d-none', tab !== 'rewrite');
    // Side column: library tab shows examples big; others show notes.
    const showLib = tab === 'library';
    $('fw-rxlab-side-library').classList.toggle('d-none', false);
    $('fw-rxlab-side-notes').classList.toggle('d-none', showLib);
    if (isCheat) renderCheat();
    else run();
  }

  function modalObj() {
    const node = $('fw-rxlab');
    if (window.bootstrap && bootstrap.Modal) return bootstrap.Modal.getOrCreateInstance(node);
    return null;
  }
  function hide() { const m = modalObj(); if (m) m.hide(); else $('fw-rxlab').style.display = 'none'; }

  function run() {
    if (curTab === 'rewrite') runRewrite();
    else runTest();
  }

  function runTest() {
    const pattern = $('fw-rxlab-pattern').value;
    const lines = $('fw-rxlab-samples').value.split('\n').filter(s => s.length);
    const verdict = $('fw-rxlab-verdict');
    const out = $('fw-rxlab-results');
    if (!pattern) { verdict.textContent = ''; out.innerHTML = ''; return; }
    fetch('/regex-lab/test', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pattern, samples: lines, case_insensitive: $('fw-rxlab-ci').checked })
    }).then(r => r.json()).then(function (j) {
      if (!j.ok) { verdict.innerHTML = '<span class="text-danger">' + esc(j.error || 'test failed') + '</span>'; out.innerHTML = ''; return; }
      verdict.innerHTML = '<strong>' + j.matched + '</strong> of <strong>' + j.total + '</strong> sample(s) match.';
      out.innerHTML = (j.results || []).map(function (r) {
        if (!r.match) return '<div class="font-monospace small text-muted">✗ ' + esc(r.sample) + '</div>';
        const s = r.sample, a = r.span[0], b = r.span[1];
        let html = '✓ ' + esc(s.slice(0, a)) + '<mark>' + esc(s.slice(a, b)) + '</mark>' + esc(s.slice(b));
        if (r.groups && r.groups.length) {
          html += ' <span class="text-muted">(' +
            r.groups.map((g, i) => '$' + (i + 1) + '=' + esc(g === null ? '∅' : g)).join(', ') + ')</span>';
        }
        return '<div class="font-monospace small text-success">' + html + '</div>';
      }).join('');
    }).catch(function () { verdict.innerHTML = '<span class="text-danger">test request failed</span>'; });
  }

  function runRewrite() {
    const pattern = $('fw-rxlab-pattern').value;
    const replacement = $('fw-rxlab-replacement').value;
    const lines = $('fw-rxlab-samples').value.split('\n').filter(s => s.length);
    const verdict = $('fw-rxlab-verdict');
    const out = $('fw-rxlab-results');
    if (!pattern) { verdict.textContent = ''; out.innerHTML = ''; return; }
    fetch('/regex-lab/rewrite', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pattern, replacement, samples: lines, case_insensitive: $('fw-rxlab-ci').checked })
    }).then(r => r.json()).then(function (j) {
      if (!j.ok) { verdict.innerHTML = '<span class="text-danger">' + esc(j.error || 'test failed') + '</span>'; out.innerHTML = ''; return; }
      verdict.innerHTML = '<strong>' + j.matched + '</strong> of <strong>' + j.total + '</strong> sample(s) match &amp; rewrite.';
      out.innerHTML = (j.results || []).map(function (r) {
        if (!r.match) return '<div class="font-monospace small text-muted">✗ ' + esc(r.sample) + ' <span class="fst-italic">(no match — passes through unchanged)</span></div>';
        if (r.error) return '<div class="font-monospace small text-danger">⚠ ' + esc(r.sample) + ' — ' + esc(r.error) + '</div>';
        let html = '<div class="font-monospace small">' +
          '<span class="text-muted">' + esc(r.sample) + '</span> ' +
          '<i class="bi bi-arrow-right text-primary"></i> ' +
          '<span class="text-success fw-bold">' + esc(r.output === null ? '∅' : r.output) + '</span>';
        if (r.groups && r.groups.length) {
          html += '<br><span class="text-muted ps-3">' +
            r.groups.map((g, i) => '$' + (i + 1) + '=' + esc(g === null ? '∅' : g)).join(', ') + '</span>';
        }
        return html + '</div>';
      }).join('');
    }).catch(function () { verdict.innerHTML = '<span class="text-danger">rewrite request failed</span>'; });
  }

  function loadLibrary() {
    // reflect product radio
    const r = product === 'fortiadc' ? $('fw-rxlab-fadc') : $('fw-rxlab-fw');
    if (r) r.checked = true;
    $('fw-rxlab-lib-scope').textContent = ctx ? ('· ' + ctx) : ('· ' + (product === 'fortiadc' ? 'FortiADC' : 'FortiWeb'));
    fetch('/regex-lab/examples?context=' + encodeURIComponent(ctx || '') + '&product=' + encodeURIComponent(product))
      .then(r => r.json()).then(function (j) {
        cheatData = j.cheatsheet || [];
        const box = $('fw-rxlab-examples');
        box.innerHTML = (j.examples || []).map(function (ex, i) {
          const badge = ex.replacement ? '<span class="badge bg-primary-subtle text-primary ms-1">rewrite</span>' : '';
          return '<button type="button" class="list-group-item list-group-item-action py-1" data-i="' + i + '">' +
            '<code>' + esc(ex.pattern) + '</code>' + badge +
            (ex.replacement ? ' <i class="bi bi-arrow-right small"></i> <code>' + esc(ex.replacement) + '</code>' : '') +
            (ex.note ? '<br><span class="text-muted">' + esc(ex.note) + '</span>' : '') + '</button>';
        }).join('') || '<div class="text-muted p-2">No examples for this section.</div>';
        box.querySelectorAll('button[data-i]').forEach(function (b) {
          b.addEventListener('click', function () {
            const ex = j.examples[+b.dataset.i];
            $('fw-rxlab-pattern').value = ex.pattern;
            if (ex.replacement) { $('fw-rxlab-replacement').value = ex.replacement; if (curTab !== 'rewrite') selectTab('rewrite'); }
            const ta = $('fw-rxlab-samples');
            if (ex.sample && ta.value.indexOf(ex.sample) < 0) ta.value = (ta.value ? ta.value + '\n' : '') + ex.sample;
            run();
          });
        });
        $('fw-rxlab-notes').innerHTML = (j.notes || []).map(n => '<li>' + esc(n) + '</li>').join('');
      }).catch(function () {});
  }

  function renderCheat() {
    const box = $('fw-rxlab-cheat');
    if (!cheatData.length) { box.innerHTML = '<div class="text-muted">Loading…</div>'; return; }
    box.innerHTML = cheatData.map(function (g) {
      const rows = g.items.map(it =>
        '<tr><td class="font-monospace text-primary" style="white-space:nowrap">' + esc(it.tok) + '</td>' +
        '<td>' + esc(it.desc) + '</td>' +
        '<td class="font-monospace text-muted small">' + esc(it.ex) + '</td></tr>').join('');
      return '<div class="col-md-6"><div class="fw-bold small mb-1">' + esc(g.group) + '</div>' +
        '<table class="table table-sm table-borderless mb-3"><tbody>' + rows + '</tbody></table></div>';
    }).join('');
  }

  window.FWRegexLab = {
    open: function (inputEl, context, prod, tab) {
      buildModal();
      targetInput = inputEl || null;
      ctx = context || '';
      product = (prod === 'fortiadc') ? 'fortiadc'
        : (prod === 'fortiweb') ? 'fortiweb'
        : (document.body.dataset.product === 'fortiadc' ? 'fortiadc' : 'fortiweb');
      $('fw-rxlab-ctx').textContent = context ? ('· ' + context) : '';
      $('fw-rxlab-use').classList.toggle('d-none', !inputEl);
      if (inputEl && inputEl.value) $('fw-rxlab-pattern').value = inputEl.value;
      selectTab(tab || 'test');
      loadLibrary();
      const m = modalObj();
      if (m) m.show(); else $('fw-rxlab').style.display = 'block';
      setTimeout(run, 120);
    }
  };
})();
