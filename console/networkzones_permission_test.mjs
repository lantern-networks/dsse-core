import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

const source = readFileSync(new URL('./networkzones.js', import.meta.url), 'utf8');

async function renderFor(permissions) {
  const node = (tag, props = {}, children = []) => ({
    tag, props, children: Array.isArray(children) ? children : [children],
    appendChild(child) { this.children.push(child); }, innerHTML: '',
  });
  const section = node('section');
  const context = vm.createContext({
    idpSession: {permissions}, el: node, bl: value => value.en,
    uiState() {}, freshRender: () => () => true,
    apiFetch: async (_method, path) => ({ok: true, body: path === '/admin/vlan-objects'
      ? {objects: [{id: 'net-1', name: 'Office', cidrs: ['192.0.2.0/24']}]}
      : {sites: []}}),
  });
  vm.runInContext(source, context);
  await context.renderZones(section);
  const buttons = [], headers = [];
  function visit(item) {
    if (Array.isArray(item)) { item.forEach(visit); return; }
    if (!item || typeof item !== 'object') return;
    if (item.tag === 'button') buttons.push(item.props.text);
    if (item.tag === 'th') headers.push(item.props.text);
    (item.children || []).forEach(visit);
  }
  visit(section);
  return {buttons, headers};
}

test('network reader can view catalog without write controls', async () => {
  const view = await renderFor(['admin.vlan.read', 'admin.connectors.read']);
  assert.deepEqual(view.buttons, []);
  assert.equal(view.headers.includes('Manage'), false);
  assert.equal(view.headers.includes('Network'), true);
});

test('network editor retains Add and Delete controls', async () => {
  const view = await renderFor(['admin.vlan.read', 'admin.vlan.write', 'admin.connectors.read']);
  assert.deepEqual(view.buttons, ['+ Add network', 'Delete']);
  assert.equal(view.headers.includes('Manage'), true);
});

test('missing permissions stay read-only while wildcard keeps controls', async () => {
  assert.deepEqual((await renderFor([])).buttons, []);
  assert.deepEqual((await renderFor(['*'])).buttons, ['+ Add network', 'Delete']);
});
