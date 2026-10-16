// Operations › Wiki — the article form (rich-text editor, draft autosave,
// Publish, reader preview, tag suggestions, ADOM boxes), the "New article"
// dialog, the list's ADOM filter boxes and the confirmation of every
// delete form (form[data-wiki-confirm]).
//
// The rich-text editor is Toast UI (vendored, app/static/vendor/
// toastui-editor/). It is loaded on demand — the editor page loads it at
// once, the list and the article pages only when the dialog opens — and it
// writes Markdown into the form's textarea, which stays the posted field and
// the fallback editor if the library cannot load. usageStatistics is off:
// Toast UI otherwise pings google-analytics.com from the operator's browser.
//
// CSP-safe: no inline handlers. The preview HTML comes from
// /wiki/api/preview, the same safe converter as the article page
// (services/wiki_markdown.py). Turbo Drive re-runs this script on every
// visit: definitions run once, init() on every visit.
(function () {
  if (!window.FWWiki) {
    const TOOLBAR = [
      ['heading', 'bold', 'italic', 'strike'],
      ['hr', 'quote'],
      ['ul', 'ol', 'indent', 'outdent'],
      ['table', 'link'],
      ['code', 'codeblock']
    ];
    let libPromise = null;

    function csrf() {
      const m = document.querySelector('meta[name="csrf-token"]');
      return (m && m.content) || '';
    }

    function loadScript(src) {
      return new Promise(function (resolve, reject) {
        const s = document.createElement('script');
        s.src = src;
        s.async = false;
        s.onload = resolve;
        s.onerror = reject;
        document.head.appendChild(s);
      });
    }

    // One load per browser page life; Turbo keeps window.toastui across visits.
    function loadLibrary(host) {
      if (window.toastui && window.toastui.Editor) {
        const lang = host.dataset.libI18n;
        if (!lang || (window.FWWiki.langs || {})[lang]) return Promise.resolve();
      }
      if (libPromise) return libPromise;
      if (!document.querySelector('link[data-wiki-editor-css]')) {
        const css = document.createElement('link');
        css.rel = 'stylesheet';
        css.href = host.dataset.libCss;
        css.setAttribute('data-wiki-editor-css', '');
        document.head.appendChild(css);
      }
      const base = (window.toastui && window.toastui.Editor) ? Promise.resolve() : loadScript(host.dataset.libJs);
      libPromise = base.then(function () {
        const lang = host.dataset.libI18n;
        if (!lang) return null;
        return loadScript(lang).then(function () {
          window.FWWiki.langs = window.FWWiki.langs || {};
          window.FWWiki.langs[lang] = true;
        }).catch(function () { /* English UI is fine */ });
      });
      libPromise.catch(function () { libPromise = null; });
      return libPromise;
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
    function bindAdoms(scope) {
      scope.querySelectorAll('[data-wiki-adoms]').forEach(function (list) {
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

    // Start the rich-text editor over the form's textarea (once per form).
    function startEditor(form) {
      const host = form.querySelector('[data-wiki-rich]');
      const body = form.querySelector('[data-wiki-body]');
      if (!host || !body || form._wikiEditor || host.dataset.starting) return Promise.resolve();
      host.dataset.starting = '1';
      return loadLibrary(host).then(function () {
        const ed = new window.toastui.Editor({
          el: host,
          height: '460px',
          initialEditType: 'wysiwyg',
          previewStyle: 'tab',
          initialValue: body.value,
          usageStatistics: false,
          autofocus: false,
          language: host.dataset.lang || 'en-US',
          toolbarItems: TOOLBAR,
          hooks: {
            // Pasted or dropped files would become data: URLs inside the
            // article (dropped again by the renderer). Refuse them here.
            addImageBlobHook: function () {
              window.alert(host.dataset.noUpload || 'Files are not stored in the Wiki.');
              return false;
            }
          }
        });
        form._wikiEditor = ed;
        ed.on('change', function () { form.dispatchEvent(new Event('wiki:edited')); });
        host.classList.add('is-ready');
        body.classList.add('d-none');
      }).catch(function () {
        host.classList.add('is-failed');   // the textarea stays the editor
      }).finally(function () { delete host.dataset.starting; });
    }

    // The textarea is what the server receives.
    function sync(form) {
      const body = form.querySelector('[data-wiki-body]');
      if (form._wikiEditor && body) body.value = form._wikiEditor.getMarkdown();
    }

    function bindPreview(form) {
      const tabs = form.querySelectorAll('[data-wiki-tab]');
      const pane = form.querySelector('[data-wiki-preview]');
      const host = form.querySelector('[data-wiki-rich]');
      const body = form.querySelector('[data-wiki-body]');
      tabs.forEach(function (btn) {
        btn.addEventListener('click', function () {
          const preview = btn.dataset.wikiTab === 'preview';
          tabs.forEach(b => b.classList.toggle('active', b === btn));
          const editing = form._wikiEditor ? host : body;
          editing.classList.toggle('d-none', preview);
          pane.classList.toggle('d-none', !preview);
          if (!preview) return;
          sync(form);
          pane.textContent = pane.dataset.loading || '…';
          fetch(form.dataset.previewUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf(), Accept: 'application/json' },
            body: JSON.stringify({ body: body.value })
          }).then(r => r.json()).then(function (data) {
            if (data && data.ok) pane.innerHTML = data.html;  // server-sanitised
            else pane.textContent = (data && data.error) || 'Preview failed.';
          }).catch(function () { pane.textContent = 'Preview failed.'; });
        });
      });
    }

    function bindTags(form) {
      const tags = form.querySelector('[data-wiki-tags]');
      const list = tags && document.getElementById(tags.getAttribute('list'));
      if (!tags || !list) return;
      let timer = null;
      tags.addEventListener('input', function () {
        clearTimeout(timer);
        timer = setTimeout(function () {
          const parts = tags.value.split(',');
          const last = parts.pop().trim();
          const head = parts.map(s => s.trim()).filter(Boolean);
          fetch(form.dataset.tagsUrl + '?q=' + encodeURIComponent(last), { headers: { Accept: 'application/json' } })
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

    // Autosave + Publish, for the editor page and the dialog alike. Every
    // change schedules a draft save (action=draft) 2.5 s after the last
    // keystroke; the first save of a new article creates it and the form's
    // action moves to its edit URL. draft_rev travels with every save: a
    // 409 means someone else saved the draft meanwhile — autosave stops and
    // says so, nothing is overwritten. Publish waits for a save in flight,
    // then releases the version and opens the article.
    function bindWriter(form) {
      const note = form.querySelector('[data-wiki-autosave]');
      const err = form.querySelector('[data-wiki-error]');
      const rev = form.querySelector('[data-wiki-rev]');
      let timer = null, inflight = Promise.resolve(), lastSent = null, stopped = false;

      function say(state, time) {
        if (!note) return;
        note.classList.toggle('is-failed', state === 'failed');
        if (state === 'saving') note.textContent = note.dataset.saving || '…';
        else if (state === 'saved') note.textContent = (note.dataset.saved || '{t}').replace('{t}', time || '');
        else if (state === 'failed') note.textContent = note.dataset.failed || '!';
      }
      function showErr(msg) {
        if (!err) return;
        err.textContent = msg || 'The article could not be saved.';
        err.classList.remove('d-none');
        err.scrollIntoView({ block: 'nearest' });
      }
      function payload(action) {
        sync(form);
        const fd = new FormData(form);
        fd.set('action', action);
        return fd;
      }
      function fingerprint() {
        sync(form);
        const fd = new FormData(form);
        ['draft_rev', 'csrf_token', 'action'].forEach(k => fd.delete(k));
        return JSON.stringify(Array.from(fd.entries()));
      }
      function blank() {
        sync(form);
        const t = form.querySelector('[name="title"]'), b = form.querySelector('[data-wiki-body]');
        return !(t && t.value.trim()) && !(b && b.value.trim());
      }
      function post(action) {
        return fetch(form.action, {
          method: 'POST',
          headers: { Accept: 'application/json', 'X-CSRFToken': csrf() },
          body: payload(action)
        }).then(function (r) {
          return r.json().catch(() => ({ ok: false, error: 'HTTP ' + r.status }))
            .then(d => ({ status: r.status, data: d }));
        });
      }
      function saveDraft() {
        inflight = inflight.then(function () {
          if (stopped) return null;
          const fp = fingerprint();
          if (fp === lastSent) return null;
          if (!form.dataset.articleId && blank()) return null;   // an empty new form makes no article
          say('saving');
          return post('draft').then(function (x) {
            const d = x.data || {};
            if (d.ok) {
              lastSent = fp;
              if (rev) rev.value = d.draft_rev;
              if (d.edit_url && !form.dataset.articleId) {
                form.dataset.articleId = String(d.id);
                form.action = d.edit_url;
              }
              if (err) err.classList.add('d-none');
              say('saved', d.saved_at);
            } else {
              if (x.status === 409) stopped = true;
              say('failed');
              showErr(d.error);
            }
          }).catch(function () { say('failed'); });
        });
        return inflight;
      }
      function schedule() {
        clearTimeout(timer);
        timer = setTimeout(saveDraft, 2500);
      }
      function flushBeacon() {
        if (stopped || !document.body.contains(form)) return;
        if (fingerprint() === lastSent || (!form.dataset.articleId && blank())) return;
        clearTimeout(timer);
        if (navigator.sendBeacon) navigator.sendBeacon(form.action, payload('draft'));
      }
      function leave(url) {
        stopped = true;
        lastSent = fingerprint();
        const modal = form.closest('.modal');
        if (modal && window.bootstrap) window.bootstrap.Modal.getOrCreateInstance(modal).hide();
        if (window.Turbo && window.Turbo.visit) window.Turbo.visit(url);
        else window.location.assign(url);
      }

      form.addEventListener('input', schedule);
      form.addEventListener('change', schedule);
      form.addEventListener('wiki:edited', schedule);
      form.addEventListener('submit', function (ev) {
        const btn = ev.submitter;
        if (btn && btn.hasAttribute('data-wiki-discard')) {          // plain POST to /discard
          if (!window.confirm(btn.dataset.confirmText || 'Discard?')) { ev.preventDefault(); return; }
          stopped = true;
          lastSent = fingerprint();
          clearTimeout(timer);
          return;
        }
        ev.preventDefault();
        clearTimeout(timer);
        const action = (btn && btn.value) || 'draft';
        if (action !== 'publish') { saveDraft(); return; }
        form.querySelectorAll('[data-wiki-publish]').forEach(b => { b.disabled = true; });
        inflight.then(function () { return post('publish'); }).then(function (x) {
          const d = x.data || {};
          if (d.ok && d.url) { leave(d.url); return; }
          if (x.status === 409) stopped = true;
          showErr(d.error);
        }).catch(function () { showErr(); })
          .finally(function () { form.querySelectorAll('[data-wiki-publish]').forEach(b => { b.disabled = false; }); });
      });
      // Leaving the page or closing the dialog keeps what was typed.
      window.addEventListener('beforeunload', flushBeacon);
      document.addEventListener('turbo:before-visit', flushBeacon);
      const modal = form.closest('.modal');
      if (modal) {
        modal.addEventListener('hide.bs.modal', function () {
          if (stopped) return;
          clearTimeout(timer);
          saveDraft().then(function () {
            // The new draft shows up in the list right away.
            if (form.dataset.articleId && !stopped && window.Turbo) {
              stopped = true;
              window.Turbo.visit(window.location.href, { action: 'replace' });
            }
          });
        });
      }
      return {
        // The baseline is taken once the editor has normalised the text,
        // so opening and closing an article never saves a draft.
        ready: function () { lastSent = fingerprint(); }
      };
    }

    function bindForm(form) {
      if (form.dataset.bound) return;
      form.dataset.bound = '1';
      bindAdoms(form);
      bindPreview(form);
      bindTags(form);
      const writer = bindWriter(form);
      if (form.dataset.wikiForm === 'modal') {
        // Toast UI measures itself: start it once the dialog is visible.
        const modal = form.closest('.modal');
        modal.addEventListener('shown.bs.modal', function () {
          const fresh = !form._wikiEditor;
          startEditor(form).then(function () {
            if (fresh) writer.ready();
            const t = form.querySelector('input[name="title"]');
            if (t) t.focus();
          });
        });
      } else {
        startEditor(form).then(writer.ready);
      }
    }

    // The list's ADOM boxes filter as soon as one is ticked.
    function bindAutofilter() {
      document.querySelectorAll('[data-wiki-autofilter]').forEach(function (box) {
        if (box.dataset.bound) return;
        box.dataset.bound = '1';
        box.addEventListener('change', function () {
          const f = box.closest('form');
          if (f) f.requestSubmit();
        });
      });
    }

    function init() {
      bindConfirms();
      bindAutofilter();
      document.querySelectorAll('form[data-wiki-form]').forEach(bindForm);
    }

    window.FWWiki = { init: init, langs: {} };
  }
  window.FWWiki.init();
})();
