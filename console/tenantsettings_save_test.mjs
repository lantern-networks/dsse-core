import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

test('tenant settings can be retried after an unconfirmed save', async () => {
  const calls = [];
  const notices = [];
  const saved = {display_name: 'Example', timezone: 'UTC', status: 'active'};
  let failWrite = true;
  function el(tag, props = {}, children = []) {
    const node = {tag, ...props, children: [], handlers: {}, disabled: false,
      appendChild(child) { this.children.push(child); },
      addEventListener(name, handler) { this.handlers[name] = handler; }};
    Object.defineProperty(node, 'innerHTML', {set() { this.children = []; }});
    for (const child of children) node.appendChild(child);
    return node;
  }
  const root = el('div');
  const fields = [];
  const context = vm.createContext({el, bl: x => x.en, freshRender: () => () => true,
    uiState() {}, uiToast: (message, kind) => notices.push({message, kind}),
    uiField: ({value}) => {
      const field = {value, el: el('input'), get() {return this.value;},
        setError(message) {this.error = message;}};
      fields.push(field);
      return field;
    },
    apiFetch: async (method, path, body) => {
      calls.push({method, path, body});
      if (method === 'GET') return {ok: true, body: {...saved}};
      if (failWrite) throw new TypeError('offline');
      Object.assign(saved, body);
      return {ok: true, body: {...saved}};
    },
    ensureSignedIn: async () => true,
  });
  vm.runInContext(readFileSync(new URL('./tenantsettings.js', import.meta.url), 'utf8'), context);
  await context.loadTenantSettings(root, root);
  const name = fields[0];
  name.value = 'Changed';
  const nodes = node => [node, ...node.children.flatMap(nodes)];
  const save = nodes(root).find(n => n.tag === 'button' && n.text === 'Save');
  await save.handlers.click();
  assert.equal(save.disabled, false);
  assert.equal(name.value, 'Changed');
  assert.equal(notices.at(-1).kind, 'err');
  assert.match(notices.at(-1).message, /confirm|verify|確認/i);
  assert.equal(calls.filter(c => c.method === 'POST').length, 1);
  failWrite = false;
  await save.handlers.click();
  assert.equal(calls.filter(c => c.method === 'POST').length, 2);
  assert.equal(saved.display_name, 'Changed');
  assert.equal(saved.status, 'active');
  assert.equal(notices.at(-1).kind, 'ok');
});
