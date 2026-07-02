/* SharedWorker — owns firmware upload TRANSFERS so they survive page navigation.

   Why a SharedWorker: in this multi-page app every navigation is a full page
   load that destroys the page's JS context and aborts any in-page XHR/fetch. A
   SharedWorker lives OUTSIDE any single page and persists across same-origin
   navigations, so an upload started here keeps going when the user changes page.
   It broadcasts progress/outcome to every connected page (the bottom-right
   toast) and answers a "query" with the current state so a freshly-loaded page
   reconnects to an in-flight transfer.

   Why XHR (not fetch): fetch() cannot report upload progress. XMLHttpRequest can
   (upload.onprogress) and IS available in a SharedWorker (unlike a ServiceWorker,
   which has no XHR). Requests are same-origin so the session cookie rides along;
   the CSRF token is sent as the X-CSRFToken header (the upload endpoint accepts
   the token from that header — no Referer needed). See app/static/js/jobs.js for
   the page side. */
"use strict";

var ports = [];        // connected page MessagePorts
var uploads = {};      // id -> { id, name, url, loaded, total, status, jobId, error }

// Best-effort breadcrumb to the server log (GET → never trips CSRF). Lets us
// prove from the logs which path ran and whether the transfer survived a nav.
function diag(ev, extra) {
  try {
    var q = "src=worker&ev=" + encodeURIComponent(ev);
    if (extra) { for (var k in extra) q += "&" + k + "=" + encodeURIComponent(extra[k]); }
    fetch("/_updiag?" + q, { credentials: "same-origin" }).catch(function () {});
  } catch (e) { /* ignore */ }
}

function broadcast(msg) {
  ports = ports.filter(Boolean);
  ports.forEach(function (p) { try { p.postMessage(msg); } catch (e) {} });
}

function snapshot(u) {
  return { type: "state", id: u.id, name: u.name, loaded: u.loaded,
           total: u.total, status: u.status, jobId: u.jobId || null,
           error: u.error || null };
}

function activeStates() {
  var out = [];
  for (var id in uploads) { if (uploads.hasOwnProperty(id)) out.push(snapshot(uploads[id])); }
  return out;
}

function startUpload(msg) {
  var id = msg.id;
  if (uploads[id] && uploads[id].status === "running") return;   // dedupe
  var file = msg.file;
  var u = uploads[id] = {
    id: id, name: msg.name || "firmware", url: msg.url,
    loaded: 0, total: (file && file.size) || 0,
    status: "running", jobId: null, error: null
  };
  diag("start", { id: id, size: u.total });

  var xhr = new XMLHttpRequest();
  xhr.open("POST", msg.url, true);
  xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
  if (msg.csrf) xhr.setRequestHeader("X-CSRFToken", msg.csrf);

  xhr.upload.onprogress = function (e) {
    if (e.lengthComputable) { u.loaded = e.loaded; u.total = e.total; }
    broadcast(snapshot(u));
  };
  xhr.onload = function () {
    var data = null;
    try { data = JSON.parse(xhr.responseText); } catch (e) { /* non-JSON */ }
    if (xhr.status >= 200 && xhr.status < 300 && data && data.job_id) {
      u.status = "success"; u.jobId = data.job_id;
      diag("done", { id: id, status: xhr.status, job: data.job_id });
    } else {
      u.status = "error";
      u.error = (data && (data.error || data.message)) ||
                (xhr.status === 413 ? "File is too large for the server limit."
                                    : "Upload failed (HTTP " + xhr.status + ").");
      diag("httpfail", { id: id, status: xhr.status });
    }
    broadcast(snapshot(u));
    setTimeout(function () { delete uploads[id]; }, 60000);   // keep for reconnects
  };
  xhr.onerror = function () {
    u.status = "error"; u.error = "Network error during upload.";
    diag("neterr", { id: id });
    broadcast(snapshot(u));
    setTimeout(function () { delete uploads[id]; }, 60000);
  };
  xhr.onabort = function () {
    // The SharedWorker was terminated mid-transfer (navigation killed it before
    // the next page reconnected). Recorded so the log tells us if this happens.
    diag("aborted", { id: id, loaded: u.loaded, total: u.total });
  };

  var fd = new FormData();
  fd.append("image", file, u.name);
  (msg.fields || []).forEach(function (kv) { fd.append(kv[0], kv[1]); });
  xhr.send(fd);
  broadcast(snapshot(u));
}

self.onconnect = function (e) {
  var port = e.ports[0];
  ports.push(port);
  diag("connect", { ports: ports.length, active: Object.keys(uploads).length });
  port.onmessage = function (ev) {
    var msg = ev.data || {};
    if (msg.type === "start") startUpload(msg);
    else if (msg.type === "query") port.postMessage({ type: "active", uploads: activeStates() });
  };
  if (port.start) port.start();
  // Greet the (re)connecting page with current state so its toast shows at once.
  port.postMessage({ type: "active", uploads: activeStates() });
};
