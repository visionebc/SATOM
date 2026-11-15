/* plugin_upload.js — the plugin import says what it is doing (FA-0017).
 *
 * "When the plugin is uploaded, show that it is loading — a job would be
 * best — and do it in the background."
 *
 * 1. <form data-plugin-upload> (Plugins › Import plugin, Plugin Studio ›
 *    Apps › Import package or bundle): the file goes up by XHR with a
 *    progress bar (bytes and %), then "Checking the package…" while the
 *    server reads it, then the preview page. A refusal is shown next to the
 *    form instead of a page reload. Without JavaScript the form posts as
 *    before (the route answers JSON only to the X-SATOM-Upload header).
 * 2. <form data-plugin-install> (the preview's Install): the install runs
 *    as a job (services/device_jobs EXTRA_ENDPOINTS) — the button says so
 *    while the request starts; a long install lands on the job's wait page.
 *
 * Loaded on every visit by Turbo: one delegated listener, installed once.
 */
(function () {
  'use strict';
  if (window.__satomPluginUpload) return;
  window.__satomPluginUpload = true;

  function fmt(n) {
    if (n < 1024 * 1024) return Math.max(1, Math.round(n / 1024)) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }

  function statusBox(form) {
    var box = form.parentNode.querySelector('[data-plugin-upload-status]');
    if (box) return box;
    box = document.createElement('div');
    box.setAttribute('data-plugin-upload-status', '');
    box.setAttribute('role', 'status');
    box.setAttribute('aria-live', 'polite');
    box.className = 'fw-alert fw-alert-info mt-2 mb-0 w-100';
    var line = document.createElement('div');
    line.className = 'pu-line';
    var spin = document.createElement('span');
    spin.className = 'spinner-border spinner-border-sm me-2';
    spin.setAttribute('aria-hidden', 'true');
    var text = document.createElement('span');
    text.className = 'pu-text';
    line.appendChild(spin);
    line.appendChild(text);
    var track = document.createElement('div');
    track.className = 'progress mt-1';
    track.style.height = '6px';
    var bar = document.createElement('div');
    bar.className = 'progress-bar';
    bar.setAttribute('role', 'progressbar');
    bar.style.width = '0%';
    track.appendChild(bar);
    box.appendChild(line);
    box.appendChild(track);
    form.parentNode.insertBefore(box, form.nextSibling);
    return box;
  }

  function show(box, state, msg, pct) {
    box.hidden = false;
    box.className = 'fw-alert mt-2 mb-0 w-100 ' + (state === 'err' ? 'fw-alert-danger' : 'fw-alert-info');
    box.style.fontSize = '13px';
    box.querySelector('.pu-text').textContent = msg;
    box.querySelector('.spinner-border').hidden = (state !== 'run');
    var bar = box.querySelector('.progress-bar');
    var track = bar.parentNode;
    track.hidden = (pct == null);
    if (pct != null) {
      bar.style.width = pct + '%';
      bar.setAttribute('aria-valuenow', String(pct));
    }
  }

  function busy(form, on) {
    form.querySelectorAll('button, input[type=file], label.btn').forEach(function (el) {
      if (el.tagName === 'LABEL') el.classList.toggle('disabled', on);
      else el.disabled = on;
    });
  }

  function go(url) {
    if (window.Turbo && window.Turbo.visit) window.Turbo.visit(url);
    else window.location.assign(url);
  }

  function upload(form) {
    var input = form.querySelector('input[type=file][name=package]');
    var file = input && input.files && input.files[0];
    if (!file) return false;                       // native "required" speaks
    var box = statusBox(form);
    var fd = new FormData(form);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', form.action, true);
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
    xhr.setRequestHeader('X-SATOM-Upload', '1');
    xhr.setRequestHeader('Accept', 'application/json');
    var name = file.name, total = file.size || 0;
    show(box, 'run', 'Uploading ' + name + ' — 0 / ' + fmt(total), 0);
    busy(form, true);
    xhr.upload.onprogress = function (e) {
      if (!e.lengthComputable) return;
      var pct = Math.floor(e.loaded * 100 / e.total);
      show(box, 'run', 'Uploading ' + name + ' — ' + fmt(e.loaded) + ' / ' + fmt(e.total) +
           ' (' + pct + ' %)', pct);
    };
    xhr.upload.onload = function () {
      show(box, 'run', 'Uploaded ' + fmt(total) + '. Checking the package (signature, ' +
           'rules, what it creates)…', 100);
    };
    xhr.onload = function () {
      var j = null;
      try { j = JSON.parse(xhr.responseText); } catch (e) { j = null; }
      if (xhr.status === 200 && j && j.ok && j.next) {
        show(box, 'run', 'Checked. Opening the preview — nothing is installed until you confirm.', 100);
        go(j.next);
        return;
      }
      busy(form, false);
      input.value = '';
      var why = (j && j.error) ? j.error
        : (xhr.status === 413 ? 'The file is too large for this server.'
          : (xhr.status === 400 && /CSRF/i.test(xhr.responseText || '')
            ? 'Your session expired. Reload the page and upload again.'
            : 'Upload failed (HTTP ' + xhr.status + ').'));
      show(box, 'err', why, null);
    };
    xhr.onerror = function () {
      busy(form, false);
      show(box, 'err', 'The upload connection dropped. Try again.', null);
    };
    xhr.send(fd);
    return true;
  }

  document.addEventListener('submit', function (e) {
    var form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (form.hasAttribute('data-plugin-upload')) {
      if (!window.FormData || !window.XMLHttpRequest) return;   // plain post
      e.preventDefault();
      e.stopImmediatePropagation();                  // not Turbo's submit too
      upload(form);
      return;
    }
    if (form.hasAttribute('data-plugin-install')) {
      var sub = e.submitter;
      if (sub && sub.hasAttribute('formaction')) return;           // Cancel
      var btn = sub || form.querySelector('button[type=submit]:not([formaction])');
      var box = statusBox(form);
      show(box, 'run', 'Installing — this runs as a job (Jobs page and the dock). ' +
           'A long install opens its progress page; you can keep working.', null);
      if (btn) {
        // disabled AFTER the submit event, or the browser drops the click
        setTimeout(function () { btn.disabled = true; }, 0);
      }
    }
  }, true);

  // A page restored from Turbo's cache drops the status of a finished upload.
  document.addEventListener('turbo:load', function () {
    document.querySelectorAll('[data-plugin-upload-status]').forEach(function (b) { b.remove(); });
  });
})();
