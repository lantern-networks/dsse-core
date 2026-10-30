import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

const source = readFileSync(new URL('./licensing.js', import.meta.url), 'utf8');

function fixture() {
  const nodes = [], calls = [], toasts = [];
  let modal;
  let rejectNext = false;
  function el(tag, attrs = {}, children = []) {
    const node = { tag, ...attrs, children: [], handlers: {}, value: '',
      addEventListener(name, callback) { this.handlers[name] = callback; },
      appendChild(child) { if (child) this.children.push(child); return child; },
    };
    Object.defineProperty(node, 'innerHTML', { set(value) { assert.equal(value, ''); node.children = []; } });
    for (const child of Array.isArray(children) ? children : [children]) node.appendChild(child);
    nodes.push(node);
    return node;
  }
  const c = vm.createContext({
    el, bl: text => text.en, uiToast: (text, kind) => toasts.push({ text, kind }),
    uiModal: options => { modal = { options, closed: false, close() { this.closed = true; } }; return modal; },
    apiFetch: async (method, path, body) => {
      calls.push({ method, path, body });
      if (rejectNext) { rejectNext = false; throw new Error('network unavailable'); }
      return path.endsWith('dry_run=true')
        ? { ok: true, status: 200, body: { change: { seats_now: 1, seats_after: 2, expires_at: '2027-01-01T00:00:00Z' } } }
        : { ok: true, status: 200, body: {} };
    },
    window: { dsseFormatTime: value => value },
    renderLicensingView: () => {},
  });
  vm.runInContext(source, c);
  c.renderLicensingView = () => {};
  return { c, nodes, calls, toasts, rejectNext() { rejectNext = true; }, get modal() { return modal; } };
}

test('changing licence bytes after dry run requires a new preview before applying', async () => {
  const f = fixture();
  await f.c.openApplyLicence({});
  const area = f.nodes.find(node => node.tag === 'textarea');
  const apply = f.nodes.find(node => node.text === 'Check this licence');
  area.value = 'licence-A';
  await apply.handlers.click();
  assert.deepEqual(f.calls.map(call => [call.path, call.body]), [['/admin/license?dry_run=true', 'licence-A']]);
  area.value = 'licence-B';
  await apply.handlers.click();
  assert.deepEqual(f.calls.map(call => [call.path, call.body]), [
    ['/admin/license?dry_run=true', 'licence-A'],
    ['/admin/license?dry_run=true', 'licence-B'],
  ]);
  assert.equal(f.modal.closed, false);
  await apply.handlers.click();
  assert.deepEqual(f.calls.at(-1), { method: 'POST', path: '/admin/license', body: 'licence-B' });
  assert.equal(f.modal.closed, true);
});

test('network failure during preview leaves the licence dialog retryable', async () => {
  const f = fixture();
  await f.c.openApplyLicence({});
  const area = f.nodes.find(node => node.tag === 'textarea');
  const apply = f.nodes.find(node => node.text === 'Check this licence');
  area.value = 'licence-A';
  f.rejectNext();
  await apply.handlers.click();
  assert.equal(apply.disabled, false);
  assert.equal(f.modal.closed, false);
  assert.equal(f.toasts.at(-1)?.kind, 'err');
  await apply.handlers.click();
  assert.equal(f.calls.at(-1).path, '/admin/license?dry_run=true');
});
