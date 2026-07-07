"use strict";
// Tests for app/static/js/policy_filter_worker.js
//  1) computeHideIds — pure matcher correctness (the logic the worker runs).
//  2) The real ReDoS defence: a catastrophic pattern run inside a Worker is
//     KILLED by terminate() within a deadline. A main-thread setTimeout could
//     never interrupt synchronous regex backtracking; Worker.terminate() can.
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { Worker } = require('node:worker_threads');

const WORKER = path.resolve(__dirname, '../../app/static/js/policy_filter_worker.js');
const { computeHideIds, compileSafe } = require(WORKER);

test('computeHideIds hides rows that fail a regex field', () => {
  const rows = [
    { id: 'a', name: 'pol-shop' },
    { id: 'b', name: 'vs-web' },
    { id: 'c', name: 'pol-pay' },
  ];
  const hide = computeHideIds([{ field: 'name', source: '^pol', flags: 'i' }], rows);
  assert.deepStrictEqual(hide.sort(), ['b']);
});

test('computeHideIds ANDs fields — a row hidden if it fails ANY field', () => {
  const rows = [
    { id: 'a', name: 'pol-shop', backends: '192.0.2.5' },
    { id: 'b', name: 'pol-pay',  backends: '192.168.1.1' },
  ];
  const hide = computeHideIds(
    [{ field: 'name', source: '^pol' }, { field: 'backends', source: '^10\\.' }], rows);
  assert.deepStrictEqual(hide.sort(), ['b']);
});

test('computeHideIds treats an INVALID regex as no-constraint (never hides all)', () => {
  const rows = [{ id: 'a', name: 'x' }, { id: 'b', name: 'y' }];
  assert.deepStrictEqual(computeHideIds([{ field: 'name', source: '(' }], rows), []);
  assert.strictEqual(compileSafe('(', ''), null);
});

test('ReDoS defence: terminate() kills a catastrophic regex within the deadline', async () => {
  // (a+)+$ against a long non-matching string backtracks exponentially → would
  // hang for many seconds. The worker must never reply; the watchdog terminates.
  const code = `
    const { workerData, parentPort } = require('node:worker_threads');
    const { computeHideIds } = require(workerData.worker);
    const evil = '/'.repeat(0) + 'a'.repeat(42) + '!';
    computeHideIds([{ field: 'v', source: '(a+)+$' }], [{ id: '1', v: evil }]);
    parentPort.postMessage('done');   // must NOT reach here before terminate
  `;
  const DEADLINE = 200;
  const started = Date.now();
  const w = new Worker(code, { eval: true, workerData: { worker: WORKER } });
  const outcome = await new Promise((resolve) => {
    const t = setTimeout(() => { w.terminate(); resolve('terminated'); }, DEADLINE);
    w.on('message', (m) => { clearTimeout(t); resolve('replied:' + m); });
    w.on('error', (e) => { clearTimeout(t); resolve('error:' + e.message); });
  });
  const elapsed = Date.now() - started;
  assert.strictEqual(outcome, 'terminated', 'worker should be killed, not reply');
  assert.ok(elapsed < 2000, 'terminate must fire promptly (was ' + elapsed + 'ms)');
});
