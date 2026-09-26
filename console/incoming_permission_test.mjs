import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

const source = readFileSync(new URL('./incoming.js', import.meta.url), 'utf8');
const savedException = {
  id: 'ex-1', tenant_id: 'tenant_lab_001', source_server: '192.0.2.10', device_group: 'ops',
  service_family: '', protocol: 'tcp', port: 8443, business_owner: 'secops',
  expires_at: '2030-01-01T00:00:00Z', max_session_seconds: 0, approval_required: false,
  mode: 'allow', status: 'active',
};

async function renderFor(permissions) {
  const requests = [];
  const node = (tag, props = {}, children = []) => ({tag, props, children: Array.isArray(children) ? children : [children],
    appendChild(child) { this.children.push(child); }, innerHTML: ''});
  const content = node('main');
  const context = vm.createContext({
    idpSession: {permissions},
    bl: value => value.en,
    el: node,
    uiBadge: text => node('badge', {text}),
    uiState: (host, kind) => { host.state = kind; },
    freshRender: () => () => true,
    apiFetch: async (method, path) => {
      requests.push([method, path]);
      if (path === '/admin/server-initiated') return {ok: true, status: 200, body: {server_initiated_enabled: true}};
      if (path === '/admin/legacy-exceptions') return {ok: true, status: 200,
        body: {schema_version: 'admin_legacy_exceptions.v1', exceptions: [savedException]}};
      throw new Error(`unexpected request: ${method} ${path}`);
    },
    window: {dsseFormatTime: value => value},
  });
  vm.runInContext(source, context);
  await context.renderIncomingView(content);
  await new Promise(resolve => setImmediate(resolve));
  const labels = [];
  function visit(item) {
    if (!item || typeof item !== 'object') return;
    if (item.tag === 'button') labels.push(item.props.text);
    for (const child of item.children || []) visit(child);
  }
  visit(content);
  return {labels, requests, content};
}

test('auditor sees confirmed incoming policy and exception without write controls', async () => {
  const {labels, requests, content} = await renderFor(['admin.serverinitiated.read']);
  assert.deepEqual(labels, []);
  assert.equal(content.children.length > 0, true);
  assert.deepEqual(requests, [['GET', '/admin/server-initiated'], ['GET', '/admin/legacy-exceptions']]);
});

test('administrator keeps ordinary incoming write controls', async () => {
  const {labels} = await renderFor(['admin.serverinitiated.read', 'admin.serverinitiated.write']);
  assert.deepEqual(labels, ['+ Add exception', 'Switch to allow by default', 'Edit', 'Delete']);
});

test('unconfirmed permissions stay read-only while wildcard authority retains controls', async () => {
  assert.deepEqual((await renderFor([])).labels, []);
  assert.deepEqual((await renderFor(['*'])).labels,
    ['+ Add exception', 'Switch to allow by default', 'Edit', 'Delete']);
});
