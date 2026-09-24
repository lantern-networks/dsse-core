import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

// An Edge is started and stopped at any time, so what the fleet observed — east-west flows and policy
// candidates — is held by the control plane. The Console must read and act on it there.
const source = process.env.APP_JS_UNDER_TEST || new URL('./app.js', import.meta.url);
const app = readFileSync(source, 'utf8');
function fixture() {
  const requests = [];
  const context = vm.createContext({
    localStorage: { getItem: () => '' },
    fetch: async (url, options) => {
      requests.push({ url, options });
      return { status: 200, ok: true, text: async () => '{}' };
    },
  });
  const start = app.indexOf('const CP_AUTHORED_WRITES = [');
  const end = app.indexOf('// offerOperatorElevation asks');
  assert.ok(start >= 0 && end > start);
  vm.runInContext(app.slice(start, end), context);
  return { context, requests };
}

test('observations and candidates are read from the control plane', async () => {
  const { context, requests } = fixture();
  for (const path of ['/admin/east-west/observations', '/admin/policy-candidates?expected_tenant_id=a']) {
    await vm.runInContext(`apiFetch('GET', ${JSON.stringify(path)})`, context);
    assert.equal(requests.at(-1).url, '/control' + path);
  }
});

test('acting on a candidate or an observation goes to the control plane', async () => {
  const { context, requests } = fixture();
  for (const path of [
    '/admin/policy-candidates/learn-1/review',
    '/admin/policy-candidates/certpin-1/materialize',
    '/admin/policy-candidates/conn-1/approve-private-app',
    '/admin/policy-candidates',
    '/admin/connector-discovery/refresh',
    '/admin/east-west/observations/adopt',
  ]) {
    await vm.runInContext(`apiFetch('POST', ${JSON.stringify(path)}, {})`, context);
    assert.equal(requests.at(-1).url, '/control' + path, path);
  }
});

test('what the serving Edge enforces is still asked of the Edge', async () => {
  const { context, requests } = fixture();
  await vm.runInContext("apiFetch('GET', '/admin/intercept/bypass-hosts?scoped=1')", context);
  assert.equal(requests.at(-1).url, '/admin/intercept/bypass-hosts?scoped=1');
});
