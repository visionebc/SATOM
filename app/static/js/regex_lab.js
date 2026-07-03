// Regex Lab — the pattern calculator behind the ".*" button on regex-capable
// WAF fields. Self-contained: builds its modal DOM once on first open (so it
// works on full pages AND AJAX-injected editor fragments), tests patterns
// SERVER-SIDE (Python re ≈ FortiWeb's PCRE — closer than JS RegExp), and can
// write the proven pattern back into the field that opened it.
(function () {
  if (window.FWRegexLab) return;

  let targetInput = null;

  function el(tag, cls, html) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html !== undefined) e.innerHTML = html;
    return e;
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function buildModal() {
    if (document.getElementById('fw-rxlab')) return;
    const wrap = el('div');
    wrap.innerHTML = `
<div class="modal fade" id="fw-rxlab" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-lg modal-dialog-scrollable">
    <div class="modal-content">
      <div class="modal-header py-2">
        <h6 class="modal-title"><code>.*</code>&nbsp;Regex calculator <span class="text-muted small" id="fw-rxlab-ctx"></span></h6>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <div class="row g-3">
          <div class="col-md-7">
            <label class="form-label small fw-bold mb-1">Pattern</label>
            <input type="text" class="form-control form-control-sm font-monospace" id="fw-rxlab-pattern"
                   placeholder="e.g. ^/admin(/.*)?$" autocomplete="off" spellcheck="false">
            <div class="form-check form-check-inline mt-1">
              <input class="form-check-input" type="checkbox" id="fw-rxlab-ci">
              <label class="form-check-label small" for="fw-rxlab-ci">Case-insensitive</label>
            </div>
            <label class="form-label small fw-bold mb-1 mt-2">Test samples <span class="text-muted fw-normal">(one per line — paste real URLs / values)</span></label>
            <textarea class="form-control form-control-sm font-monospace" id="fw-rxlab-samples" rows="6"
                      placeholder="/admin/login.php&#10;/shop/cart&#10;/api/v2/users"></textarea>
            <div class="mt-2 small" id="fw-rxlab-verdict"></div>
            <div id="fw-rxlab-results" class="mt-1"></div>
          </div>
          <div class="col-md-5">
            <label class="form-label small fw-bold mb-1">Examples for this section <span class="text-muted fw-normal">(click to load)</span></label>
            <div id="fw-rxlab-examples" class="list-group small mb-2" style="max-height:220px;overflow:auto"></div>
            <details>
              <summary class="small fw-bold">FortiWeb regex notes</summary>
              <ul class="small text-muted mt-1 mb-0" id="fw-rxlab-notes"></ul>
            </details>
          </div>
        </div>
      </div>
      <div class="modal-footer py-2">
        <span class="me-auto small text-muted">Tested server-side (PCRE-compatible engine).</span>
        <button type="button" class="btn btn-sm btn-outline-secondary" data-bs-dismiss="modal">Close</button>
        <button type="button" class="btn btn-sm btn-fw-primary" id="fw-rxlab-use">Use this pattern</button>
      </div>
    </div>
  </div>
</div>`;
    document.body.appendChild(wrap.firstElementChild);

    const pat = document.getElementById('fw-rxlab-pattern');
    const samples = document.getElementById('fw-rxlab-samples');
    const ci = document.getElementById('fw-rxlab-ci');
    let t = null;
    const kick = () => { clearTimeout(t); t = setTimeout(runTest, 350); };
    pat.addEventListener('input', kick);
    samples.addEventListener('input', kick);
    ci.addEventListener('change', runTest);
    document.getElementById('fw-rxlab-use').addEventListener('click', function () {
      if (targetInput) {
        targetInput.value = pat.value;
        targetInput.dispatchEvent(new Event('input', { bubbles: true }));
        targetInput.dispatchEvent(new Event('change', { bubbles: true }));
      }
      hide();
    });
  }

  function modalObj() {
    const node = document.getElementById('fw-rxlab');
    if (window.bootstrap && bootstrap.Modal) return bootstrap.Modal.getOrCreateInstance(node);
    return null;
  }

  function hide() {
    const m = modalObj();
    if (m) m.hide();
    else document.getElementById('fw-rxlab').style.display = 'none';
  }

  function runTest() {
    const pattern = document.getElementById('fw-rxlab-pattern').value;
    const lines = document.getElementById('fw-rxlab-samples').value.split('\n').filter(s => s.length);
    const verdict = document.getElementById('fw-rxlab-verdict');
    const out = document.getElementById('fw-rxlab-results');
    if (!pattern) { verdict.textContent = ''; out.innerHTML = ''; return; }
    fetch('/regex-lab/test', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pattern: pattern, samples: lines,
                             case_insensitive: document.getElementById('fw-rxlab-ci').checked })
    }).then(r => r.json()).then(j => {
      if (!j.ok) {
        verdict.innerHTML = '<span class="text-danger">' + esc(j.error || 'test failed') + '</span>';
        out.innerHTML = '';
        return;
      }
      verdict.innerHTML = '<strong>' + j.matched + '</strong> of <strong>' + j.total + '</strong> sample(s) match.';
      out.innerHTML = (j.results || []).map(function (r) {
        if (!r.match) {
          return '<div class="font-monospace small text-muted">✗ ' + esc(r.sample) + '</div>';
        }
        const s = r.sample, a = r.span[0], b = r.span[1];
        let html = '✓ ' + esc(s.slice(0, a)) + '<mark>' + esc(s.slice(a, b)) + '</mark>' + esc(s.slice(b));
        if (r.groups && r.groups.length) {
          html += ' <span class="text-muted">(' +
            r.groups.map((g, i) => '$' + (i + 1) + '=' + esc(g === null ? '∅' : g)).join(', ') + ')</span>';
        }
        return '<div class="font-monospace small text-success">' + html + '</div>';
      }).join('');
    }).catch(function () {
      verdict.innerHTML = '<span class="text-danger">test request failed</span>';
    });
  }

  function loadExamples(context) {
    fetch('/regex-lab/examples?context=' + encodeURIComponent(context || ''))
      .then(r => r.json()).then(function (j) {
        const box = document.getElementById('fw-rxlab-examples');
        box.innerHTML = (j.examples || []).map(function (ex, i) {
          return '<button type="button" class="list-group-item list-group-item-action py-1" data-i="' + i + '">' +
            '<code>' + esc(ex.pattern) + '</code>' +
            (ex.note ? '<br><span class="text-muted">' + esc(ex.note) + '</span>' : '') + '</button>';
        }).join('') || '<div class="text-muted p-2">No examples for this section.</div>';
        box.querySelectorAll('button[data-i]').forEach(function (b) {
          b.addEventListener('click', function () {
            const ex = j.examples[+b.dataset.i];
            document.getElementById('fw-rxlab-pattern').value = ex.pattern;
            const ta = document.getElementById('fw-rxlab-samples');
            if (ex.sample && ta.value.indexOf(ex.sample) < 0) {
              ta.value = (ta.value ? ta.value + '\n' : '') + ex.sample;
            }
            runTest();
          });
        });
        const notes = document.getElementById('fw-rxlab-notes');
        notes.innerHTML = (j.notes || []).map(n => '<li>' + esc(n) + '</li>').join('');
      }).catch(function () {});
  }

  window.FWRegexLab = {
    open: function (inputEl, context) {
      buildModal();
      targetInput = inputEl || null;
      document.getElementById('fw-rxlab-ctx').textContent = context ? '· ' + context : '';
      if (inputEl && inputEl.value) {
        document.getElementById('fw-rxlab-pattern').value = inputEl.value;
      }
      loadExamples(context);
      const m = modalObj();
      if (m) m.show();
      else document.getElementById('fw-rxlab').style.display = 'block';
      setTimeout(runTest, 100);
    }
  };
})();
