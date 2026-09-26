import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';

const source = readFileSync(new URL('./peopleaccounts.js', import.meta.url), 'utf8');

async function readRisk(reply, tenant = 'tenant-lab') {
  const calls = [];
  const context = vm.createContext({apiFetch: (...args) => {calls.push(args); return reply;}});
  vm.runInContext(source, context);
  const marks = await context.paLoadRiskMarks(tenant);
  assert.deepEqual(calls, [['GET', '/admin/risk-signals?entity_type=user', undefined, 'control']]);
  return marks && {...marks};
}

test('a denied risk read does not imply Normal risk', async () => {
  assert.equal(await readRisk({ok: false, status: 403}), null);
});

test('a failed or malformed risk read remains unknown', async () => {
  assert.equal(await readRisk({ok: false, status: 503}), null);
  assert.equal(await readRisk({ok: true, body: {}}), null);
  assert.equal(await readRisk({ok: true, body: {high_risk: {}}}), null);
  assert.equal(await readRisk({ok: true, body: {entity_type: 'device', tenant_id: 'tenant-lab', high_risk: {}}}), null);
  assert.equal(await readRisk({ok: true, body: {entity_type: 'user', tenant_id: 'tenant-other', high_risk: {alice: 'high'}}}), null);
  assert.equal(await readRisk(Promise.reject(new Error('offline'))), null);
});

test('a valid risk map remains available to permitted editors', async () => {
  assert.deepEqual(await readRisk({ok: true, body: {entity_type: 'user', tenant_id: 'tenant-lab', high_risk: {alice: 'high'}}}), {alice: 'high'});
  assert.deepEqual(await readRisk({ok: true, body: {entity_type: 'user', tenant_id: 'tenant-lab', high_risk: {}}}), {});
});

test('operator sees unresolved legacy count without changing person marks', async () => {
  const context = vm.createContext({apiFetch: () => ({ok: true, body: {
    entity_type: 'user', tenant_id: 'tenant-lab', high_risk: {alice: 'high'}, legacy_unattributed_count: 2,
  }})});
  vm.runInContext(source, context);
  const snapshot = await context.paLoadRiskSnapshot('tenant-lab');
  assert.equal(snapshot.legacyCount, 2);
  assert.deepEqual({...snapshot.marks}, {alice: 'high'});
});
