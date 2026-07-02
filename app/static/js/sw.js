/* Service Worker — resilient background uploads via the Background Fetch API.

   The point: a firmware .out transfer (hundreds of MB) is owned by the BROWSER,
   not the page. So it keeps going when the user navigates to another page,
   refreshes, or even closes the tab. This SW does NOT intercept normal requests
   (there is deliberately no `fetch` handler — it must not touch app traffic); it
   only wires the Background Fetch lifecycle and relays the outcome to any open
   page so the bottom-right toast can hand off to the server-side "Verifying…"
   (SHA-256) job. See app/static/js/jobs.js for the page side. */

"use strict";

self.addEventListener("install", function () {
  self.skipWaiting();               // take over without waiting for old clients
});

self.addEventListener("activate", function (event) {
  event.waitUntil(self.clients.claim());   // control already-open tabs
});

// Post a message to every open window (controlled or not).
function relay(msg) {
  return self.clients
    .matchAll({ type: "window", includeUncontrolled: true })
    .then(function (clients) {
      clients.forEach(function (c) { c.postMessage(msg); });
    });
}

// Transfer finished: the server answered 202 {job_id} — read it and tell the
// pages so the toast switches to tracking the SHA-256 finalize job.
self.addEventListener("backgroundfetchsuccess", function (event) {
  var reg = event.registration;
  event.waitUntil((async function () {
    var jobId = null, payload = null;
    try {
      var records = await reg.matchAll();
      if (records && records.length) {
        var resp = await records[0].responseReady;
        payload = await resp.json();
        jobId = payload && payload.job_id;
      }
    } catch (e) {
      /* Response unreadable — harmless: the server's finalize job still runs and
         any page reconnects to it via GET /jobs/?active=1 on next load. */
    }
    try { await event.updateUI({ title: "Upload complete — verifying…" }); }
    catch (e) { /* updateUI is best-effort */ }
    await relay({ type: "bgupload", event: "success",
                  id: reg.id, jobId: jobId, payload: payload });
  })());
});

self.addEventListener("backgroundfetchfailure", function (event) {
  event.waitUntil(
    relay({ type: "bgupload", event: "fail", id: event.registration.id }));
});

self.addEventListener("backgroundfetchabort", function (event) {
  event.waitUntil(
    relay({ type: "bgupload", event: "abort", id: event.registration.id }));
});

// Clicking the browser's background-fetch chip focuses (or opens) the app.
self.addEventListener("backgroundfetchclick", function (event) {
  event.waitUntil(
    self.clients.matchAll({ type: "window" }).then(function (clients) {
      for (var i = 0; i < clients.length; i++) {
        if ("focus" in clients[i]) return clients[i].focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow("/firmware/");
    }));
});
