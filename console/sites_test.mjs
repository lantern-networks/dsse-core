import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';

const source = readFileSync(new URL('./sites.js', import.meta.url), 'utf8');
function fixture(overrides = {}) {
  const states = [], calls = [];
  function el(tag, props = {}, children = []) {
    const node = {tag, ...props, style: {}, disabled: !!props.disabled, children: [],
      textContent: props.text || '', appendChild(child) { if (child) this.children.push(child); },
      querySelectorAll(selector) { const tags = selector.split(','); return this.children.flatMap(n => [n, ...n.querySelectorAll(selector)]).filter(n => tags.includes(n.tag)); },
      scrollIntoView() {},
    };
    Object.defineProperty(node, 'innerHTML', {set() { this.children = []; }});
    for (const child of [children].flat(Infinity)) node.appendChild(child);
    return node;
  }
  const reply = async (method, path) => {
    calls.push([method, path]);
    const key = path.endsWith('/networks') ? 'networks' : path === '/admin/vlan-objects' ? 'objects' : 'connectors';
    if (overrides[key] instanceof Error) throw overrides[key];
    return overrides[key] || {ok: true, body: {[key]: []}};
  };
  const context = vm.createContext({el, apiFetch: reply, bl: x => x.en, uiBadge: () => el('span'), uiToast() {},
    uiState(host, state, message, retry) { host.innerHTML = ''; states.push({state, message, retry}); },
    freshRender(host) { const seq = (host.__renderSeq || 0) + 1; host.__renderSeq = seq; return () => host.__renderSeq === seq; },
    renderConnectorRouteGovernance() {},
  });
  vm.runInContext(source, context);
  const host = el('div');
  return {context, host, states, calls, reply};
}

for (const key of ['networks', 'objects', 'connectors']) {
  test(`${key} read failures refuse editing and provide retry`, async () => {
    for (const response of [{ok: false, status: 503}, {ok: true, body: {}}, {ok: true, body: {[key]: {}}}, {ok: true, body: {[key]: [42]}}, new Error('offline')]) {
      const f = fixture({[key]: response});
      await f.context.renderSiteNetworks(f.host, 'site', {});
      assert.equal(f.states.at(-1).state, 'error');
      assert.equal(f.states.at(-1).retry.label, 'Retry');
      assert.equal(f.host.querySelectorAll('button,input,select').length, 0);
      await f.context.siteNetworkAction('site', {action: 'add', fqdn: 'example.test'}, f.host, {});
      assert.equal(f.calls.filter(([method]) => method === 'POST').length, 0);
    }
  });
}

test('valid empty slices permit editing; connectors are selected by site', async () => {
  for (const empty of [null, []]) {
    const f = fixture(Object.fromEntries(['networks', 'objects', 'connectors'].map(k => [k, {ok: true, body: {[k]: empty}}])));
    await f.context.renderSiteNetworks(f.host, 'site', {});
    assert.ok(f.host.__siteNetworkEditor);
    assert.ok(f.host.querySelectorAll('button').some(b => b.text === 'Add'));
  }
  const f = fixture({connectors: {ok: true, body: {connectors: [{id: 'a', connector_group_id: 'site'}, {id: 'b', connector_group_id: 'other'}]}}});
  assert.deepEqual(JSON.parse(JSON.stringify((await f.context.loadSiteNetworkData('site')).conns)), [{id: 'a', connector_group_id: 'site'}]);
});

test('malformed binding, catalog and connector fields are rejected before rendering', async () => {
  for (const [key, row] of [
    ['networks', {}], ['networks', {kind: 'network'}], ['networks', {kind: 'fqdn'}], ['networks', {kind: 'cidr'}],
    ['networks', {kind: 'network', network_id: 'n', network_cidrs: {}}],
    ['networks', {kind: 'fqdn', fqdn: 'example.test', cidr: {}}], ['networks', {kind: 'fqdn', fqdn: 'example.test', cidr: '192.0.2.0/24'}],
    ['objects', {id: 'n', cidrs: [42]}], ['objects', {id: 'n', name: {}}], ['objects', {}],
    ['connectors', {id: 'c', attached_region_id: {}}], ['connectors', {}],
  ]) {
    const f = fixture({[key]: {ok: true, body: {[key]: [row]}}});
    await f.context.renderSiteNetworks(f.host, 'site', {});
    assert.equal(f.states.at(-1).state, 'error', JSON.stringify(row));
    assert.equal(f.host.__siteNetworkEditor, null);
  }
});

test('obsolete success and failure cannot replace a newer render', async () => {
  for (const fail of [false, true]) {
    const f = fixture(); let finish;
    f.context.loadSiteNetworkData = () => new Promise((resolve, reject) => { finish = () => fail ? reject(Error('old error')) : resolve({rows: [], catalog: [], conns: []}); });
    const old = f.context.renderSiteNetworks(f.host, 'site', {});
    f.context.loadSiteNetworkData = async () => ({rows: [], catalog: [], conns: []});
    await f.context.renderSiteNetworks(f.host, 'site', {});
    const editor = f.host.__siteNetworkEditor;
    finish(); await old;
    assert.equal(f.host.__siteNetworkEditor, editor);
    assert.equal(f.states.some(s => s.state === 'error'), false);
  }
});

test('in-flight mutations suppress repeats and restore controls after errors', async () => {
  const f = fixture(); await f.context.renderSiteNetworks(f.host, 'site', {});
  const editor = f.host.__siteNetworkEditor;
  editor.controls[0].disabled = true;
  const prior = editor.controls.map(c => c.disabled);
  let reject; f.context.apiFetch = async (method, path) => {
    f.calls.push([method, path]); return new Promise((_resolve, r) => { reject = r; });
  };
  const first = f.context.siteNetworkAction('site', {action: 'add', fqdn: 'example.test'}, f.host, {});
  assert.equal(editor.busy, true); assert.ok(editor.controls.every(c => c.disabled));
  await f.context.siteNetworkAction('site', {action: 'remove', fqdn: 'example.test'}, f.host, {});
  assert.equal(f.calls.filter(([method]) => method === 'POST').length, 1);
  reject(Error('<b>offline</b>')); await first;
  assert.equal(editor.error.textContent, '<b>offline</b>'); assert.equal(editor.error.style.display, '');
  assert.deepEqual(editor.controls.map(c => c.disabled), prior); assert.equal(editor.busy, false);
  f.context.apiFetch = async (method, path) => method === 'POST' ? {ok: false, status: 500, body: {error: 'save refused'}} : f.reply(method, path);
  await f.context.siteNetworkAction('site', {action: 'add'}, f.host, {});
  assert.equal(editor.error.textContent, 'save refused'); assert.equal(editor.busy, false);
  f.context.apiFetch = async (method, path) => method === 'POST' ? {ok: true} : f.reply(method, path);
  await f.context.siteNetworkAction('site', {action: 'add'}, f.host, {});
  assert.notEqual(f.host.__siteNetworkEditor, editor);
});

test('closing or replacing the editor suppresses late mutation results', async () => {
  for (const fail of [false, true]) {
    const f = fixture(); await f.context.renderSiteNetworks(f.host, 'site', {});
    const editor = f.host.__siteNetworkEditor; let finish;
    f.context.apiFetch = () => new Promise((resolve, reject) => { finish = () => fail ? reject(Error('late')) : resolve({ok: true}); });
    const save = f.context.siteNetworkAction('site', {action: 'add'}, f.host, {});
    f.context.freshRender(f.host); // The modal's onClose invalidates this render.
    finish(); await save;
    assert.equal(editor.error.textContent, '');
    assert.equal(f.states.length, 1);
    assert.equal(editor.busy, false);
  }
});

test('successful mutation followed by unavailable reads shows Retry without controls', async () => {
  const f = fixture(); await f.context.renderSiteNetworks(f.host, 'site', {});
  f.context.apiFetch = async method => method === 'POST' ? {ok: true} : {ok: false, status: 503};
  await f.context.siteNetworkAction('site', {action: 'add'}, f.host, {});
  assert.equal(f.states.at(-1).state, 'error');
  assert.equal(f.host.__siteNetworkEditor, null);
  assert.equal(f.host.querySelectorAll('button,input,select').length, 0);
});

function siteEditorFixture(existing, language = 'en') {
  const fields = {}, writes = [], notices = [];
  let modal;
  const context = vm.createContext({
    bl: text => text[language],
    el: (tag, props) => ({tag, ...props}),
    uiToast: (...args) => notices.push(args),
    uiField(spec) {
      const input = {disabled: false, validity: {badInput: false}};
      const field = {spec, value: String(spec.value || ''), error: '', input,
        el: {querySelector: () => input}, get() {return this.value.trim();}, focus() {},
        validate() {this.error = spec.required && !this.get() ? 'required' : spec.validate?.(this.get()) || ''; return !this.error;},
      };
      fields[spec.name] = field; return field;
    },
    uiModal(spec) {modal = spec; return {close() {throw Error('unexpected confirmed write');}};},
    async apiFetch(method, path, body) {writes.push({method, path, body: JSON.parse(JSON.stringify(body))}); return {ok: false, status: 503};},
  });
  vm.runInContext(source, context);
  context.openSiteForm({}, existing);
  return {context, fields, writes, notices, get modal() {return modal;}, submit: () => modal.footer.at(-1).onclick()};
}

for (const value of ['1.5', '-1', '1e2', '+2', '0x10', '9007199254740992', 'NaN', 'Infinity', 'two']) {
  test(`site editor rejects invalid connector count ${value} without writing`, async () => {
    const f = siteEditorFixture({site_id: 's', expected_connector_count: 3});
    f.fields.expected.value = value; await f.submit();
    assert.equal(f.writes.length, 0); assert.ok(f.fields.expected.error); assert.ok(!f.modal.footer.at(-1).disabled);
  });
}
for (const [value, expected] of [['', 0], ['0', 0], ['0002', 2], [' 3 ', 3], ['9007199254740991', 9007199254740991]]) {
  test(`site editor sends exact connector count ${JSON.stringify(value)}`, async () => {
    const f = siteEditorFixture({site_id: 's'}); f.fields.expected.value = value; await f.submit();
    assert.equal(f.writes[0].body.expected_connector_count, expected);
  });
}
test('site editor preserves hidden metadata captured when opened, excluding server-managed fields', async () => {
  const site = {site_id: 's', name: 'old', region: 'r', deployment_type: 'vm', expected_connector_count: 0,
    routing_namespace: 'route', ha_policy: 'active-passive', bootstrap_secret_hash: 'secret', created_at: 'old', tenant_id: 'other'};
  const f = siteEditorFixture(site); assert.equal(f.fields.expected.value, '0'); assert.equal(f.fields.site_id.input.disabled, true);
  site.ha_policy = 'changed'; site.routing_namespace = 'changed'; site.site_id = 'changed';
  f.fields.name.value = 'new'; await f.submit();
  assert.deepEqual(f.writes, [{method: 'POST', path: '/admin/sites', body: {site_id: 's', name: 'new', region: 'r', deployment_type: 'vm', routing_namespace: 'route', ha_policy: 'active-passive', expected_connector_count: 0}}]);
});
for (const key of ['routing_namespace', 'ha_policy']) {
  test(`site editor refuses malformed hidden ${key}`, () => {
    for (const value of [42, {}, [], false]) {const f = siteEditorFixture({site_id: 's', [key]: value}); assert.equal(f.modal, undefined); assert.equal(f.writes.length, 0); assert.equal(f.notices[0][1], 'err');}
  });
}
test('site editor accepts absent or empty hidden metadata without inventing policy', async () => {
  for (const value of [undefined, null, '']) {const f = siteEditorFixture({site_id: 's', routing_namespace: value, ha_policy: value}); await f.submit(); assert.equal(f.writes[0].body.ha_policy, undefined); assert.equal(f.writes[0].body.routing_namespace, undefined);}
});
test('site editor does not treat native number input badInput as an intentionally blank target', async () => {
  const f = siteEditorFixture({site_id: 's'}); f.fields.expected.value = ''; f.fields.expected.input.validity.badInput = true;
  await f.submit(); assert.equal(f.writes.length, 0); assert.ok(f.fields.expected.error);
});
test('site creation validates the target and required identity before writing', async () => {
  const f = siteEditorFixture(); f.fields.expected.value = '2'; await f.submit(); assert.equal(f.writes.length, 0);
  f.fields.site_id.value = 'new-site'; await f.submit(); assert.equal(f.writes[0].body.expected_connector_count, 2); assert.equal(f.writes[0].body.site_id, 'new-site');
});
test('site editor provides Japanese validation and hidden-setting read errors', async () => {
  const f = siteEditorFixture({site_id: 's'}, 'ja'); f.fields.expected.value = '-1'; await f.submit();
  assert.match(f.fields.expected.error, /整数/); assert.match(f.fields.expected.spec.hint, /空欄/);
  const bad = siteEditorFixture({site_id: 's', ha_policy: {}}, 'ja'); assert.match(bad.notices[0][0], /再読込/);
});

test('site editor displays a zero target omitted by the site list projection', () => {
  const edit = siteEditorFixture({site_id: 's'}); assert.equal(edit.fields.expected.value, '0');
  const create = siteEditorFixture(); assert.equal(create.fields.expected.value, '');
});
