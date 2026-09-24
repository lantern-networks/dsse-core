import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

async function dnsEditorFixture() {
  const writes = [], notices = [], confirmations = [];
  const policy = {deny: ['blocked.example'], sinkhole: {'redirect.example': '192.0.2.25'},
    stub_ipv4: {'fixed.example': '192.0.2.40'}, ech_strip: false,
    forward_zones: [{zone: 'corp.example', upstream: '10.40.0.53:53'}]};
  function el(tag, props = {}, children = []) {
    const node = {tag, ...props, style: {}, value: props.value || '', children: [], handlers: {},
      appendChild(child) { if (child) { child.parent = this; this.children.push(child); } },
      addEventListener(event, handler) { this.handlers[event] = handler; }};
    Object.defineProperty(node, 'innerHTML', {set() { this.children = []; }});
    for (const child of [children].flat(Infinity)) node.appendChild(child);
    return node;
  }
  const root = el('div');
  const context = vm.createContext({el, bl: x => x.en, freshRender: () => () => true,
    uiState() {}, answeringForTheDeployment: () => true, uiBadge: text => el('span', {text}),
    uiField: ({value}) => ({el: el('input'), get: () => value}),
    uiToast: (message, kind) => notices.push({message, kind}),
    uiConfirm: async options => { confirmations.push(options); return true; },
    apiFetch: async (method, path, body) => {
      if (method === 'PUT') { writes.push(JSON.parse(JSON.stringify(body))); return {ok: true}; }
      return {ok: true, body: path === '/admin/dns-policy' ? structuredClone(policy) : {connectors: []}};
    }});
  vm.runInContext(readFileSync(new URL('./dns.js', import.meta.url), 'utf8'), context);
  context.renderDnsView = () => {};
  await context.loadDns(root, root);
  const nodes = node => [node, ...node.children.flatMap(nodes)];
  const input = placeholder => nodes(root).find(n => n.placeholder === placeholder);
  const fill = (placeholder, value) => { const n = input(placeholder); n.value = value; n.handlers.input(); };
  const click = text => { const n = nodes(root).find(n => n.tag === 'button' && n.text === text); return (n.onClick || n.handlers.click)(); };
  const remove = placeholder => input(placeholder).parent.children.find(n => n.text === 'Remove').onClick();
  return {policy, writes, notices, confirmations, input, fill, click, remove};
}

for (const placeholder of ['ads.example', '100.64.0.250', 'corp.example.com', 'internal DNS 10.10.0.10:53']) {
  test('incomplete DNS edit retains input and cannot silently delete a rule: ' + placeholder, async () => {
    const f = await dnsEditorFixture();
    const previous = f.input(placeholder).value;
    f.fill(placeholder, '   ');
    await f.click('Review & apply');
    assert.equal(f.writes.length, 0);
    assert.equal(f.confirmations.length, 0);
    assert.equal(f.notices.at(-1).kind, 'err');
    assert.equal(f.input(placeholder).value, '   ');
    f.fill(placeholder, previous);
    await f.click('Review & apply');
    assert.deepEqual(f.writes, [f.policy]);
  });
}

test('explicit DNS row removal still saves and preserves other settings', async () => {
  const f = await dnsEditorFixture();
  f.remove('ads.example');
  f.remove('corp.example.com');
  await f.click('Review & apply');
  assert.deepEqual(f.writes, [{...f.policy, sinkhole: {}, forward_zones: []}]);
});

test('new empty DNS rows require completion or explicit removal', async () => {
  const f = await dnsEditorFixture();
  await f.click('+ Add redirect');
  await f.click('+ Add zone');
  await f.click('Review & apply');
  assert.equal(f.writes.length, 0);
  assert.equal(f.confirmations.length, 0);
});
