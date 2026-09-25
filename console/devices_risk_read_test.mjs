import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';

const source = readFileSync(new URL('./devices.js', import.meta.url), 'utf8');

function fixture(reply) {
  const calls = [];
  const context = vm.createContext({apiFetch: (...args) => {calls.push(args); return reply;}});
  vm.runInContext(source, context);
  return {context, calls};
}

test('denied overlay read keeps explicit effective risk and unknown missing risk', async () => {
  const {context, calls} = fixture({ok: false, status: 403});
  assert.equal(await context.deviceRiskMarks(), null);
  assert.deepEqual(calls, [['GET', '/admin/risk-signals']]);
  assert.equal(context.deviceEffectiveRiskWithoutOverlay('high'), 'high');
  assert.equal(context.deviceEffectiveRiskWithoutOverlay(undefined), 'unknown');
  assert.equal(context.deviceEffectiveRiskWithoutOverlay('garbled'), 'unknown');
});

test('other risk read failures do not masquerade as an empty overlay', async () => {
  await assert.rejects(fixture({ok: false, status: 503}).context.deviceRiskMarks(), /HTTP 503/);
  await assert.rejects(fixture({ok: true, body: {}}).context.deviceRiskMarks(), /Invalid risk response/);
  await assert.rejects(fixture(Promise.reject(new Error('offline'))).context.deviceRiskMarks(), /offline/);
});

test('a valid risk map remains available for permitted editors', async () => {
  const marks = await fixture({ok: true, body: {high_risk: {device1: 'critical'}}}).context.deviceRiskMarks();
  assert.deepEqual({...marks}, {device1: 'critical'});
});
