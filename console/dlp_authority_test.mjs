import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

// Exercise the actual request routing against distinct authority and enforcement answers.
const app = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
function fixture(source = app) {
  const requests = [];
  const context = vm.createContext({
    localStorage: { getItem: () => '' },
    fetch: async (url, options) => {
      requests.push({ url, options });
      return { status: 200, ok: true, text: async () => JSON.stringify({
        policies: url.startsWith('/control/') ? [{ id: 'saved-policy' }] : [],
      }) };
    },
  });
  const start = source.indexOf('const CP_AUTHORED_WRITES = [');
  const end = source.indexOf('// offerOperatorElevation asks');
  assert.ok(start >= 0 && end > start);
  vm.runInContext(source.slice(start, end) + '\noperateTenant = "customer-a";', context);
  return { context, requests };
}

test('saved DLP definitions remain available to the rule editor and detector library', async () => {
  const { context, requests } = fixture();
  for (const path of ['/admin/dlp-policies', '/admin/dlp-classifiers', '/admin/dlp-fingerprints']) {
    const answer = await vm.runInContext(`apiFetch('GET', ${JSON.stringify(path)})`, context);
    assert.equal(answer.body.policies[0]?.id, 'saved-policy');
    assert.equal(requests.at(-1).url, '/control' + path);
    assert.equal(requests.at(-1).options.headers['x-operate-tenant'], 'customer-a');
  }
});

test('explicit Edge reads and effective enforcement still ask the Edge', async () => {
  const { context, requests } = fixture();
  await vm.runInContext("apiFetch('GET', '/admin/dlp-policies', undefined, 'edge')", context);
  assert.equal(requests.at(-1).url, '/admin/dlp-policies');
  await vm.runInContext("apiFetch('GET', '/admin/egress-effective-rules')", context);
  assert.equal(requests.at(-1).url, '/admin/egress-effective-rules');
});
