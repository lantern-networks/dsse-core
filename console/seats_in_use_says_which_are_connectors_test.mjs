import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

// 0.4.1 acceptance B rerun: the licence table read "in use 2" for an organization whose Devices screen said
// "1 device". The second seat was its connector. Both screens that show the count now say which.
const ui = readFileSync(new URL('./ui.js', import.meta.url), 'utf8');
const start = ui.indexOf('function uiSeatsInUse(');
const fn = ui.slice(start, ui.indexOf('\n}\n', start) + 3);

function said(lang, used, connectors) {
  const ctx = { bl: (m) => m[lang] };
  vm.runInNewContext(fn + '\nglobalThis.out = uiSeatsInUse(' + JSON.stringify(used) + ', ' + JSON.stringify(connectors) + ');', ctx);
  return ctx.out;
}

test('a count that includes a connector says so', () => {
  assert.equal(said('ja', 2, 1), '2（端末 1・コネクタ 1）');
  assert.equal(said('en', 2, 1), '2 (1 device, 1 connector)');
  assert.equal(said('en', 5, 2), '5 (3 devices, 2 connectors)');
});

test('a count with no connector is just the number, and an older control plane changes nothing', () => {
  assert.equal(said('ja', 3, 0), '3');
  assert.equal(said('ja', 3, undefined), '3');
});

test('both screens that show the count use it', () => {
  for (const name of ['licensing.js', 'operatorhome.js']) {
    const src = readFileSync(new URL('./' + name, import.meta.url), 'utf8');
    assert.match(src, /uiSeatsInUse\(/, name + ' shows the seats in use another way');
  }
});
