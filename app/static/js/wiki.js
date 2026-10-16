// Operations › Wiki — the article editor (preview + tag suggestions) and the
// confirmation of every delete form (form[data-wiki-confirm]).
//
// CSP-safe: no inline handlers. The preview HTML comes from
// /wiki/api/preview, which renders with the same safe converter as the
// article page (services/wiki_markdown.py). Turbo Drive re-runs this script
// on every visit: definitions run once, init() on every visit to the editor.
(function () {
  if (!window.FWWiki) {
    function csrf() {
      const m = document.querySelector('meta[name="csrf-token"]');
      return (m && m.content) || '';
    }

    function bindConfirms() {
      document.querySelectorAll('form[data-wiki-confirm]').forEach(function (f) {
        if (f.dataset.bound) return;
        f.dataset.bound = '1';
        f.addEventListener('submit', function (ev) {
          if (!window.confirm(f.getAttribute('data-wiki-confirm'))) ev.preventDefault();
        });
      });
    }

    // Global and the ADOM boxes exclude each other; unticking the last ADOM
    // falls back to Global so the list is never left empty.
    function bindAdoms() {
      document.querySelectorAll('[data-wiki-adoms]').forEach(function (list) {
        if (list.dataset.bound) return;
        list.dataset.bound = '1';
        const glob = list.querySelector('[data-wiki-global]');
        const boxes = Array.from(list.querySelectorAll('input[name="adoms"]')).filter(b => b !== glob);
        glob.addEventListener('change', function () {
          if (glob.checked) boxes.forEach(b => { b.checked = false; });
          else if (!boxes.some(b => b.checked)) glob.checked = true;
        });
        boxes.forEach(function (b) {
          b.addEventListener('change', function () {
            if (b.checked) glob.checked = false;
            else if (!boxes.some(x => x.checked)) glob.checked = true;
          });
        });
      });
    }

    function init() {
      bindConfirms();
      bindAdoms();
      const root = document.getElementById('wiki-editor');
      if (!root || root.dataset.bound) return;
      root.dataset.bound = '1';
      const body = document.getElementById('wiki-body');
      const pane = document.getElementById('wiki-preview');
      const tabs = root.querySelectorAll('[data-wiki-tab]');

      tabs.forEach(function (btn) {
        btn.addEventListener('click', function () {
          const preview = btn.dataset.wikiTab === 'preview';
          tabs.forEach(b => b.classList.toggle('active', b === btn));
          body.classList.toggle('d-none', preview);
          pane.classList.toggle('d-none', !preview);
          if (!preview) return;
          pane.textContent = pane.dataset.loading || '…';
          fetch(root.dataset.previewUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf(), Accept: 'application/json' },
            body: JSON.stringify({ body: body.value })
          }).then(r => r.json()).then(function (data) {
            if (data && data.ok) pane.innerHTML = data.html;  // server-sanitised
            else pane.textContent = (data && data.error) || 'Preview failed.';
          }).catch(function () { pane.textContent = 'Preview failed.'; });
        });
      });

      const tags = document.getElementById('wiki-tags');
      const list = document.getElementById('wiki-tag-options');
      if (tags && list) {
        let timer = null;
        tags.addEventListener('input', function () {
          clearTimeout(timer);
          timer = setTimeout(function () {
            const parts = tags.value.split(',');
            const last = parts.pop().trim();
            const head = parts.map(s => s.trim()).filter(Boolean);
            fetch(root.dataset.tagsUrl + '?q=' + encodeURIComponent(last), { headers: { Accept: 'application/json' } })
              .then(r => r.json()).then(function (data) {
                list.replaceChildren();
                (data.tags || []).filter(t => head.indexOf(t) < 0).forEach(function (t) {
                  const o = document.createElement('option');
                  o.value = head.concat([t]).join(', ');
                  list.appendChild(o);
                });
              }).catch(function () {});
          }, 200);
        });
      }
    }

    window.FWWiki = { init: init };
  }
  window.FWWiki.init();
})();
