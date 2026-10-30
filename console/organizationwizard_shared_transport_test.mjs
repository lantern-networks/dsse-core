import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

test('new organizations use the deployment transport hostname', async () => {
  let dialog;
  let created;
  const el = (tag, props = {}, children = []) => ({
    tag, ...props, children,
    addEventListener(event, handler) { this[event] = handler; },
  });
  const context = vm.createContext({
    el,
    document: {createTextNode: text => ({text})},
    bl: labels => labels.en,
    uiField: spec => ({el: el('input'), validate: () => true,
      get: () => spec.value || (spec.name === 'name' ? 'Example' : ''),
      focus() {}, setError() {}}),
    uiModal: spec => { dialog = spec; return {close() {}}; },
    uiToast() {},
    apiFetch: async (method, path, body) => {
      if (method === 'GET') return {ok: true, body: {edges: [{region_id: 'region-a'}]}};
      created = {method, path, body};
      return {ok: false, status: 400, body: {error: 'fixture stop'}};
    },
  });
  vm.runInContext(readFileSync(new URL('./tenant_fleet_settings.js', import.meta.url), 'utf8'), context);
  vm.runInContext(readFileSync(new URL('./organizationwizard.js', import.meta.url), 'utf8'), context);
  await context.openOrganizationWizard({});
  assert.doesNotMatch(JSON.stringify(dialog.body), /Give them their own address on the Edges/);
  const submit = dialog.footer.find(node => node.text === 'Create tenant');
  await submit.click();
  assert.equal(created.method, 'POST');
  assert.equal(created.path, '/admin/tenants');
  assert.equal(created.body.transport_authority, false);
});
