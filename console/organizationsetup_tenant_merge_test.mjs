import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

function setupContext(answerForPlane) {
  const context = vm.createContext({
    apiFetch: async (_method, _path, _body, plane) => ({ok: true, body: answerForPlane[plane]}),
    bl: labels => labels.en,
  });
  vm.runInContext(readFileSync(new URL('./organizationsetup.js', import.meta.url), 'utf8'), context);
  return context;
}

test('setup summary never merges another tenant from one plane into the requested tenant', async () => {
  const context = setupContext({
    control: {tenant_id: 'Acme', measured_on: 'cp', items: [
      {key: 'registry', state: 'done', blocking: true},
      {key: 'device_identity', state: 'not_here', blocking: true},
    ]},
    edge: {tenant_id: 'acme', measured_on: 'edge', items: [
      {key: 'device_identity', state: 'done', blocking: true, values: {count: 1}},
    ]},
  });
  const result = await context.organizationSetupMerged('Acme');
  assert.equal(result.tenant_id, 'Acme');
  assert.equal(result.operational, 'unknown');
  assert.equal(result.items.find(item => item.key === 'device_identity').state, 'not_here');
  assert.equal(result.silent.length, 1);
});

test('setup summary is unavailable when neither plane proves the requested tenant', async () => {
  const context = setupContext({
    control: {tenant_id: 'Other', measured_on: 'cp', items: [{key: 'registry', state: 'done'}]},
    edge: {tenant_id: 'Other', measured_on: 'edge', items: [{key: 'registry', state: 'done'}]},
  });
  assert.equal(await context.organizationSetupMerged('Acme'), null);
});
