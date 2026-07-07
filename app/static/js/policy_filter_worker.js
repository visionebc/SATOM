/* policy_filter_worker.js — off-main-thread regex matcher for the Server Policy
   filter bar, so a catastrophic (ReDoS) pattern the operator types can NEVER
   freeze the page.

   Why a Worker at all: the filter's text fields accept a user regex (/pat/).
   A pattern like (a+)+$ backtracks exponentially. On the MAIN thread that is
   uninterruptible — a setTimeout can't stop synchronous regex execution, the
   tab just hangs. Only terminating the JS context running the regex stops it,
   and you can only terminate a Worker. So the regex runs HERE; the page arms a
   watchdog and calls worker.terminate() if this doesn't answer in time.

   Why a static file (not a Blob worker): the app's CSP has no worker-src/child-src,
   so it falls back to script-src = 'self' … . A same-origin /static file matches
   'self'; a URL.createObjectURL(blob) worker would need worker-src blob: and is
   BLOCKED. Hence this ships as a real file, loaded via asset() like every other JS.

   Dual-mode: the pure functions are exported for the Node test
   (tests/js/test_policy_filter_worker.js); the self.onmessage wiring only arms
   inside a real browser dedicated-worker context. */
"use strict";

(function () {
  function compileSafe(source, flags) {
    try { return new RegExp(source, flags || ""); }
    catch (e) { return null; }   // invalid → caller treats as no-constraint
  }

  // Returns the ids of rows that FAIL at least one regex field (i.e. must be
  // hidden). A row is kept only if EVERY active regex field matches it (AND).
  // An invalid pattern is skipped (never hides everything on a mid-typing typo).
  function computeHideIds(regexFields, rows) {
    var compiled = [];
    for (var i = 0; i < regexFields.length; i++) {
      var f = regexFields[i];
      var re = compileSafe(f.source, f.flags);
      if (re) compiled.push({ field: f.field, re: re });   // compile ONCE, not per row
    }
    var hide = [];
    if (!compiled.length) return hide;
    for (var r = 0; r < rows.length; r++) {
      var row = rows[r];
      for (var c = 0; c < compiled.length; c++) {
        var val = row[compiled[c].field] || "";
        if (!compiled[c].re.test(val)) { hide.push(row.id); break; }
      }
    }
    return hide;
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { computeHideIds: computeHideIds, compileSafe: compileSafe };
  }

  // Real browser dedicated-worker context only (not the page, not Node).
  var inDedicatedWorker =
    typeof self !== "undefined" &&
    typeof self.postMessage === "function" &&
    typeof self.addEventListener === "function" &&
    typeof window === "undefined";

  if (inDedicatedWorker) {
    // Process fields ONE AT A TIME, announcing each before it runs. If the page
    // has to terminate us, the last 'field-start' it saw names the runaway
    // pattern's field — so it can flag exactly that input box red.
    self.addEventListener("message", function (ev) {
      var msg = ev.data || {};
      var fields = msg.regexFields || [];
      var rows = msg.rows || [];
      var hideSet = Object.create(null);
      for (var i = 0; i < fields.length; i++) {
        self.postMessage({ type: "field-start", seq: msg.seq, field: fields[i].field });
        var ids = computeHideIds([fields[i]], rows);       // union across fields
        for (var k = 0; k < ids.length; k++) hideSet[ids[k]] = 1;
      }
      self.postMessage({ type: "result", seq: msg.seq, hideIds: Object.keys(hideSet) });
    });
  }
})();
