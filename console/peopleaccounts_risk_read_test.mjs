import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';

const source = readFileSync(new URL('./peopleaccounts.js', import.meta.url), 'utf8');

async function readRisk(reply) {
  const calls = [];
  const context = vm.createContext({apiFetch: (...args) => {calls.push(args); return reply;}});
  vm.runInContext(source, context);
  const marks = await context.paLoadRiskMarks();
  assert.deepEqual(calls, [['GET', '/admin/risk-signals', null, undefined]]);
  return marks && {...marks};
}

test('a denied risk read does not imply Normal risk', async () => {
  assert.equal(await readRisk({ok: false, status: 403}), null);
});

test('a failed or malformed risk read remains unknown', async () => {
  assert.equal(await readRisk({ok: false, status: 503}), null);
  assert.equal(await readRisk({ok: true, body: {}}), null);
  assert.equal(await readRisk(Promise.reject(new Error('offline'))), null);
});

test('a valid risk map remains available to permitted editors', async () => {
  assert.deepEqual(await readRisk({ok: true, body: {high_risk: {alice: 'high'}}}), {alice: 'high'});
  assert.deepEqual(await readRisk({ok: true, body: {high_risk: {}}}), {});
});
