import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const app = readFileSync(new URL('./app.js', import.meta.url), 'utf8');

test('a pending control-plane retry cannot move an operation into a newly selected tenant', async () => {
  const calls = [];
  const context = vm.createContext({
    localStorage: {getItem: () => ''},
    fetch: async (url, options) => {
      calls.push({url, tenant: options.headers['x-operate-tenant']});
      if (calls.length === 1) {
        vm.runInContext('operateTenant = "tenant-b"', context);
        return {status: 409, ok: false, text: async () => JSON.stringify({error: 'ask the control plane'})};
      }
      return {status: 200, ok: true, text: async () => '{}'};
    },
  });
  vm.runInContext(app.slice(app.indexOf('const CP_AUTHORED_WRITES = ['), app.indexOf('// offerOperatorElevation asks')) +
    '\noperateTenant = "tenant-a";', context);
  const result = await context.apiFetch('POST', '/admin/test-operation', {enabled: true});
  assert.equal(result.status, 409);
  assert.deepEqual(calls, [{url: '/admin/test-operation', tenant: 'tenant-a'}]);
});

test('an explicitly targeted control-plane retry keeps its original tenant', async () => {
  const calls = [];
  const context = vm.createContext({
    localStorage: {getItem: () => ''},
    fetch: async (url, options) => {
      calls.push({url, tenant: options.headers['x-operate-tenant']});
      if (calls.length === 1) {
        vm.runInContext('operateTenant = "tenant-b"', context);
        return {status: 409, ok: false, text: async () => JSON.stringify({error: 'ask the control plane'})};
      }
      return {status: 200, ok: true, text: async () => '{}'};
    },
  });
  vm.runInContext(app.slice(app.indexOf('const CP_AUTHORED_WRITES = ['), app.indexOf('// offerOperatorElevation asks')) +
    '\noperateTenant = "tenant-a";', context);
  const result = await context.apiFetch('POST', '/admin/test-operation', {enabled: true}, undefined, undefined, 'tenant-a');
  assert.equal(result.status, 200);
  assert.deepEqual(calls, [
    {url: '/admin/test-operation', tenant: 'tenant-a'},
    {url: '/control/admin/test-operation', tenant: 'tenant-a'},
  ]);
});

test('switching tenant while considering an elevation does not grant it or replay the write', async () => {
  const calls = [];
  const context = vm.createContext({
    localStorage: {getItem: () => ''},
    bl: value => value.en,
    uiConfirm: async () => {
      vm.runInContext('operateTenant = "tenant-b"', context);
      return true;
    },
    uiToast: () => {},
    fetch: async (url, options) => {
      calls.push({url, tenant: options.headers['x-operate-tenant']});
      return {status: 403, ok: false, text: async () => JSON.stringify({elevation_required: {tenant_id: 'tenant-a', why: 'test'}})};
    },
  });
  vm.runInContext(app.slice(app.indexOf('const CP_AUTHORED_WRITES = ['), app.indexOf('// Rendering')) +
    '\noperateTenant = "tenant-a";', context);
  const result = await context.apiFetch('POST', '/admin/test-operation', {enabled: true});
  assert.equal(result.status, 403);
  assert.deepEqual(calls, [{url: '/admin/test-operation', tenant: 'tenant-a'}]);
});
