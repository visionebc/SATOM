/* scout_objects.js — the object picker on the Scout walk form.
 *
 * Picking an appliance asks it what it publishes and fills a <select>. Three
 * decisions are the whole file:
 *
 *  1. THE SELECT IS NOT THE FIELD. It writes into #sc-policy, which is what
 *     the form posts. An object the device will not list (an unlicensed
 *     FortiWeb-VM answers -20010 to every cmdb endpoint) must still be
 *     walkable, and a picker that is the only way in is a cage. Without this
 *     file the form behaves exactly as it did before: type the name.
 *
 *  2. A LATE ANSWER FOR THE PREVIOUS DEVICE IS DROPPED, not painted. Two
 *     changes in quick succession can return out of order, and device A's
 *     policies listed under device B's name look exactly like device B's
 *     policies. The response carries appliance_id and it is checked.
 *
 *  3. A FAILED LOAD SAYS SO. An empty picker and a picker that could not ask
 *     are the same picture on screen and opposite facts, so the note line
 *     always carries which one it is; it is written by the server, which is
 *     the half that knows.
 *
 * Body-block script: Turbo re-executes it on every visit, so binding is
 * per-element and idempotent (the elements are new each visit; a document
 * listener would accumulate).
 */
(function () {
  'use strict';

  function init() {
    var appl = document.getElementById('sc-appl');
    var pick = document.getElementById('sc-object');
    var name = document.getElementById('sc-policy');
    var note = document.getElementById('sc-object-note');
    if (!appl || !pick || !name || pick.dataset.scoutBound === '1') return;
    pick.dataset.scoutBound = '1';

    var url = pick.getAttribute('data-objects-url') || '';
    var seq = 0;

    function say(text) { if (note) note.textContent = text || ''; }

    function reset(label, enabled) {
      pick.innerHTML = '';
      var o = document.createElement('option');
      o.value = '';
      o.textContent = label;
      pick.appendChild(o);
      pick.disabled = !enabled;
    }

    function paint(data) {
      var list = (data && data.objects) || [];
      if (!list.length) {
        reset('— nothing to pick —', false);
        say([data.note, data.escape].filter(Boolean).join(' '));
        return;
      }
      //  The plural comes from the server: "server policy" + "s" is
      //  "server policys", and it was printed on this very label.
      reset('— ' + list.length + ' ' +
            (list.length === 1 ? (data.noun || 'object')
                               : (data.noun_plural || 'objects')) + ' —', true);
      var wanted = name.value;
      var labels = data.group_label || {};
      //  An <option> does not wrap, so a provenance SUFFIX is cut off by the
      //  column and there is no way for the control to say it was cut. The
      //  odd groups come FIRST: they are small, and a row that only one
      //  source knows about is the reason both are offered — buried under
      //  forty ordinary rows it might as well not be there.
      ['live', 'harvest', 'both', 'sole'].forEach(function (src) {
        var rows = list.filter(function (r) { return r.source === src; });
        if (!rows.length) return;
        var into = pick;
        if (labels[src]) {
          into = document.createElement('optgroup');
          //  Count first: it is the half worth reading when the column cuts
          //  the rest, and the full sentence is in the legend below.
          into.label = rows.length + ' · ' + labels[src];
          pick.appendChild(into);
        }
        rows.forEach(function (row) {
          var o = document.createElement('option');
          o.value = row.name;
          o.textContent = row.name + (row.detail ? '  ·  ' + row.detail : '');
          if (row.name === wanted) o.selected = true;
          into.appendChild(o);
        });
      });
      var bits = [data.note];
      //  The <optgroup> heading is cut by the column and cannot say so, so
      //  every group that carries a claim is written out in full down here,
      //  where the text wraps. The wording is the server's, not ours.
      ['live', 'harvest'].forEach(function (src) {
        var n = list.filter(function (r) { return r.source === src; }).length;
        var full = (list.filter(function (r) { return r.source === src; })[0]
                    || {}).note;
        if (n && full) { bits.push(n + ' ' + full + '.'); }
      });
      if (data.capped) {
        bits.push('Not shown — ' + data.capped + ' more of ' + data.total +
                  ', trimmed by this page, not by the device.');
      }
      bits.push(data.escape);
      say(bits.filter(Boolean).join(' '));
    }

    function load() {
      var id = appl.value;
      if (!id) {
        reset('— pick an appliance first —', false);
        say('');
        return;
      }
      var mine = ++seq;
      reset('— asking the appliance… —', false);
      say('');
      fetch(url + '?appliance_id=' + encodeURIComponent(id),
            { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
        .then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json();
        })
        .then(function (data) {
          // Stale answers are dropped, never painted (decision 2 above).
          if (mine !== seq || String(data.appliance_id) !== String(appl.value)) return;
          paint(data);
        })
        .catch(function (e) {
          if (mine !== seq) return;
          reset('— could not ask —', false);
          say('The picker could not be loaded (' + e.message + '). Type the ' +
              'name: this only offers names, it is not how the walk finds them.');
        });
    }

    appl.addEventListener('change', load);
    pick.addEventListener('change', function () {
      if (pick.value) { name.value = pick.value; }
    });
    if (appl.value) { load(); }
  }

  document.addEventListener('turbo:load', init);
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
