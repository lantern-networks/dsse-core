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

function programFixture() {
 const f=fixture();Object.assign(f.context,{baseForPlane:()=>'/control',operateTenant:'',idpSession:{id:'admin'}});
 const p={platform:'linux',arch:'amd64',file_name:'connector.tar.gz',size:3,sha256:'a'.repeat(64)};
 const response={ok:true,status:200,body:{programs:[p],count:1}};
 f.context.apiFetch=async()=>response;
 return {...f,p,response};
}
for(const mode of ['http','partial','network','body','array','count','row','digest','size','target','filename','version','duplicate'])test('program catalogue rejects '+mode+' instead of empty',async()=>{
 const f=programFixture(),r=f.response,p=f.p;
 if(mode==='http')r.ok=false;if(mode==='partial')r.status=206;if(mode==='network')f.context.apiFetch=async()=>{throw Error('offline')};
 if(mode==='body')delete r.body;if(mode==='array')r.body.programs=null;if(mode==='count')r.body.count=3;if(mode==='row')r.body.programs=[null];
 if(mode==='digest')p.sha256='bad';if(mode==='size')p.size=-1;if(mode==='target')p.platform='..';if(mode==='filename')p.file_name='../bad';if(mode==='version')p.version={};if(mode==='duplicate'){r.body.programs.push({...p});r.body.count=2}
 await assert.rejects(f.context.connectorProgramsFetch());
});
test('program catalogue accepts explicit empty, legacy zero bytes and optional metadata',async()=>{
 const f=programFixture();f.p.size=0;assert.equal((await f.context.connectorProgramsFetch()).length,1);f.response.body={programs:[],count:0};assert.equal((await f.context.connectorProgramsFetch()).length,0);
});
test('program read error offers a read-only retry and clears old content',async()=>{
 const f=programFixture(),rendered=[],methods=[];let fail=true;
 f.context.apiFetch=async(method)=>{methods.push(method);if(fail)throw Error('private storage path');return f.response};
 const refresh=f.context.connectorProgramsLoader(f.host,p=>rendered.push(p));
 await refresh();assert.equal(f.states.at(-1).state,'error');assert.equal(rendered.length,0);assert.doesNotMatch(f.states.at(-1).message,/private/);
 fail=false;await f.states.at(-1).retry.onClick();assert.equal(rendered.length,1);assert.deepEqual(methods,['GET','GET']);
});
for(const kind of ['selection','session','authority','token','disconnected','parent','newer'])for(const fail of [true,false])test(`program read discards ${kind} late ${fail?'failure':'success'}`,async()=>{
 const f=programFixture();let done,parent=true,rendered=0;
 f.context.connectorProgramsFetch=()=>new Promise((resolve,reject)=>{done=()=>fail?reject(Error('old')):resolve([])});
 const refresh=f.context.connectorProgramsLoader(f.host,()=>rendered++,()=>parent),pending=refresh();
 if(kind==='token')f.context.localStorage={getItem:()=> 'new'};if(kind==='selection')f.context.operateTenant='other';if(kind==='session')f.context.idpSession={id:'new'};if(kind==='authority')f.context.baseForPlane=()=>'/other';if(kind==='disconnected')f.host.isConnected=false;if(kind==='parent')parent=false;if(kind==='newer')f.context.freshRender(f.host);
 done();await pending;assert.equal(rendered,0);assert.equal(f.states.some(s=>s.state==='error'),false);
});

function programDownloadFixture() {
 const f=programFixture(),downloads=[],toasts=[],requests=[],timers=[];let valid=true;
 const bytes=new Uint8Array([1,2,3]);f.p.sha256='039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81';
 const response={ok:true,status:200,blob:async()=>new Blob([bytes])};
 Object.assign(f.context,{crypto:globalThis.crypto,localStorage:{getItem:()=>''},fetch:async(...a)=>{requests.push(a);return response},uiToast:m=>toasts.push(m),URL:{createObjectURL:()=> 'blob:program',revokeObjectURL(){}},setTimeout:fn=>timers.push(fn),document:{body:{appendChild(){}},createElement:()=>{const a={click(){downloads.push(a.download)},remove(){}};return a}}});
 return {...f,response,downloads,toasts,requests,timers,invalidate:()=>valid=false,run:()=>f.context.downloadConnectorProgram(f.p,()=>valid)};
}
test('connector download checks original bytes and request options',async()=>{
 const f=programDownloadFixture();assert.equal(await f.run(),true);assert.deepEqual(f.downloads,['connector.tar.gz']);assert.equal(f.toasts.length,0);
 const [url,opts]=f.requests[0];assert.match(url,/platform=linux&arch=amd64/);assert.equal(opts.redirect,'error');assert.equal(opts.cache,'no-store');assert.equal(opts.credentials,'include');assert.equal(f.timers.length,1);
});
for(const kind of ['size','digest','partial','redirect','http','network','blob','hash','metadata','filename'])test('connector refuses unverified download '+kind,async()=>{
 const f=programDownloadFixture();
 if(kind==='size')f.response.blob=async()=>new Blob(['x']);if(kind==='digest')f.response.blob=async()=>new Blob(['bad']);
 if(kind==='partial')f.response.status=206;if(kind==='redirect')f.response.redirected=true;if(kind==='http')f.response.ok=false;
 if(kind==='network')f.context.fetch=async()=>{throw Error('private-path')};if(kind==='blob')f.response.blob=async()=>{throw Error('private-path')};
 if(kind==='hash')f.context.crypto={subtle:{digest:async()=>{throw Error('private-path')}}};
 if(kind==='metadata')f.p.sha256='invalid';if(kind==='filename')f.p.file_name='../bad';
 assert.equal(await f.run(),false);assert.equal(f.downloads.length,0);assert.equal(f.toasts.length,1);assert.doesNotMatch(f.toasts[0],/private-path/);
 if(['size','digest'].includes(kind))assert.match(f.toasts[0],/Do not distribute/);
 if(kind==='hash')assert.match(f.toasts[0],/does not establish.*corrupt/);
});
for(const stage of ['fetch','blob','bytes','hash'])for(const failure of [false,true])test(`connector discards late ${stage} ${failure?'failure':'success'}`,async()=>{
 const f=programDownloadFixture();let finish,enter;const entered=new Promise(r=>enter=r);
 const wait=value=>{enter();return new Promise((resolve,reject)=>{finish=()=>failure?reject(Error('late private-path')):resolve(value)})};
 if(stage==='fetch')f.context.fetch=()=>wait(f.response);
 if(stage==='blob')f.response.blob=()=>wait(new Blob([new Uint8Array([1,2,3])]));
 if(stage==='bytes')f.response.blob=async()=>({size:3,arrayBuffer:()=>wait(new Uint8Array([1,2,3]).buffer)});
 if(stage==='hash')f.context.crypto={subtle:{digest:()=>wait(new Uint8Array(32).buffer)}};
 const pending=f.run();await entered;f.invalidate();finish();assert.equal(await pending,false);assert.equal(f.downloads.length,0);assert.equal(f.toasts.length,0);
});
for(const key of ['selection','session','authority','token'])test('connector discards changed '+key,async()=>{
 const f=programDownloadFixture();let finish;f.context.fetch=()=>new Promise(r=>finish=()=>r(f.response));const run=f.run();
 if(key==='selection')f.context.operateTenant='other';if(key==='session')f.context.idpSession={};if(key==='authority')f.context.baseForPlane=()=>'/new';if(key==='token')f.context.localStorage.getItem=()=> 'new';
 finish();await run;assert.equal(f.downloads.length,0);assert.equal(f.toasts.length,0);
});
test('connector captures displayed metadata before asynchronous work',async()=>{
 const f=programDownloadFixture();let finish;f.context.fetch=()=>new Promise(r=>finish=()=>r(f.response));const run=f.run();f.p.file_name='changed';f.p.sha256='b'.repeat(64);finish();assert.equal(await run,true);assert.deepEqual(f.downloads,['connector.tar.gz']);
});
for(const reason of ['size','digest','verification','transfer'])test('connector guidance has safe Japanese '+reason,()=>{
 const f=programDownloadFixture();f.context.bl=x=>x.ja;assert.match(f.context.connectorProgramDownloadError(reason),/[ぁ-んァ-ン一-龥]/);
});

function siteEditorFixture(existing, language = 'en') {
  const fields = {}, writes = [], notices = [];
  let modal, closed = 0, reloads = 0;
  const host = {isConnected: true}, state = {authority: '', token: ''};
  const context = vm.createContext({
    baseForPlane: () => state.authority, localStorage: {getItem: () => state.token},
    bl: text => text[language],
    el: (tag, props) => ({tag, ...props, style: {}}),
    uiToast: (...args) => notices.push(args),
    uiField(spec) {
      const input = {disabled: false, validity: {badInput: false}};
      const field = {spec, value: String(spec.value || ''), error: '', input,
        el: {querySelector: () => input}, get() {return this.value.trim();}, focus() {},
        validate() {this.error = spec.required && !this.get() ? 'required' : spec.validate?.(this.get()) || ''; return !this.error;},
      };
      fields[spec.name] = field; return field;
    },
    uiModal(spec) {modal = spec; return {close() {closed++; spec.onClose?.();}};},
    async apiFetch(method, path, body) {writes.push({method, path, body: JSON.parse(JSON.stringify(body))}); return {ok: false, status: 503};},
  });
  vm.runInContext(source, context);
  context.renderSiteList = () => {reloads++;};
  context.openSiteForm(host, existing);
  return {context, fields, writes, notices, host, state, get closed() {return closed;}, get reloads() {return reloads;}, get modal() {return modal;}, submit: () => modal.footer.at(-1).onclick()};
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

const siteRequest = {site_id: 's', name: 'Name', region: 'region-a', deployment_type: 'vm', expected_connector_count: 2, routing_namespace: 'route', ha_policy: 'active-passive'};
const savedSite = () => ({managed: true, ...siteRequest});
const siteResponse = body => ({ok: true, status: 200, body});
for (const [name, response] of [
  ['empty body', siteResponse({})], ['array', siteResponse([])], ['null', siteResponse(null)],
  ['204', {ok: true, status: 204, body: savedSite()}], ['HTTP failure', {ok: false, status: 500, body: savedSite()}],
  ['other ID', siteResponse({...savedSite(), site_id: 'other'})], ['unmanaged', siteResponse({...savedSite(), managed: false})],
  ['wrong count', siteResponse({...savedSite(), expected_connector_count: 1})], ['string count', siteResponse({...savedSite(), expected_connector_count: '2'})],
  ['lost policy', siteResponse({...savedSite(), ha_policy: undefined})], ['wrong name', siteResponse({...savedSite(), name: 'old'})],
  ['null name', siteResponse({...savedSite(), name: null})], ['lost routing', siteResponse({...savedSite(), routing_namespace: undefined})],
]) test(`site acknowledgement rejects ${name}`, () => {
  const f = siteEditorFixture(siteRequest); assert.equal(f.context.siteSaveAcknowledged(response, siteRequest), false);
});
test('site acknowledgement accepts real detail shape while readback confirms configured region', () => {
  const f = siteEditorFixture(siteRequest);
  assert.equal(f.context.siteSaveAcknowledged(siteResponse({...savedSite(), region: {home_regions: []}}), siteRequest), true);
  assert.equal(f.context.siteSaveReadback(siteResponse({sites: [savedSite()]}), siteRequest), true);
  for (const sites of [null, {}, [], [null], [savedSite(), savedSite()], [{...savedSite(), region: 'wrong'}], [{...savedSite(), region: {}}]])
    assert.equal(f.context.siteSaveReadback(siteResponse({sites}), siteRequest), false);
  assert.equal(f.context.siteSaveReadback({ok: false, status: 503, body: {sites: [savedSite()]}}, siteRequest), false);
});
test('site save accepts omitted optional empty fields and zero count, but not null', () => {
  const f = siteEditorFixture(); const request = {site_id: 's', name: '', region: '', deployment_type: '', expected_connector_count: 0};
  const row = {site_id: 's', managed: true};
  assert.equal(f.context.siteSaveAcknowledged(siteResponse(row), request), true);
  assert.equal(f.context.siteSaveReadback(siteResponse({sites: [row]}), request), true);
  assert.equal(f.context.siteSaveAcknowledged(siteResponse({...row, expected_connector_count: null}), request), false);
});
function deferredSiteReply() {let resolve, reject; const promise = new Promise((a,b) => {resolve = a; reject = b;}); return {promise,resolve,reject};}
test('site save locks fields, suppresses duplicate submit and confirms readback before success', async () => {
  const f = siteEditorFixture(siteRequest), post = deferredSiteReply(), read = deferredSiteReply(), calls = [];
  f.context.apiFetch = async (method, path, body, plane) => {calls.push({method,path,body,plane}); return method === 'POST' ? post.promise : read.promise;};
  const pending = f.submit(); assert.ok(Object.values(f.fields).every(field => field.input.disabled)); await f.submit(); assert.equal(calls.length,1);
  f.fields.name.value = 'changed after submit'; post.resolve(siteResponse(savedSite())); await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls.length,2); assert.equal(calls[0].body.name, 'Name'); assert.equal(calls[1].method,'GET'); assert.equal(calls[1].plane,'control'); assert.equal(f.closed,0);
  read.resolve(siteResponse({sites:[savedSite()]})); await pending; assert.equal(f.closed,1); assert.equal(f.reloads,1); assert.equal(f.notices.at(-1)[1],'ok');
});
for (const failure of ['empty', 'network', 'http', 'readback', 'read-network']) test(`site ${failure} failure retains input and shows safe uncertainty`, async () => {
  const f = siteEditorFixture(siteRequest);let posts = 0;
  f.context.apiFetch = async method => {if(method==='POST'){posts++;if(failure==='network')throw Error('sensitive backend');if(failure==='empty')return siteResponse({});if(failure==='http')return {ok:false,status:500,body:{error:'sensitive backend'}};return siteResponse(savedSite());}if(failure==='read-network')throw Error('sensitive backend');return siteResponse({sites:[]});};
  await f.submit(); assert.equal(posts,1);assert.equal(f.closed,0);assert.equal(f.reloads,0);assert.equal(f.fields.name.value,'Name');assert.equal(f.fields.name.input.disabled,false);assert.equal(f.fields.site_id.input.disabled,true);
  const alert=f.modal.body.at(-1);assert.match(alert.textContent,/may already have been applied/);assert.ok(!alert.textContent.includes('sensitive backend'));assert.equal(f.notices.length,0);
});
const siteContextChanges = {
  selection: f => {f.context.operateTenant='other';}, session: f => {f.context.idpSession={user:'other'};},
  authority: f => {f.state.authority='other';}, credential: f => {f.state.token='other';},
  generation: f => {f.host.__renderSeq=2;}, detached: f => {f.host.isConnected=false;}, closed: f => {f.modal.onClose();},
};
for (const [name, change] of Object.entries(siteContextChanges)) {
  test(`site ${name} change before submit prevents writes`, async () => {
    const f=siteEditorFixture(siteRequest);change(f);await f.submit();assert.equal(f.writes.length,0);assert.equal(f.notices.length,0);
  });
  for (const stage of ['POST','GET']) test(`site ${name} change during ${stage} discards late success and failure`, async () => {
    for(const fail of [false,true]){
      const f=siteEditorFixture(siteRequest),gate=deferredSiteReply(),calls=[];
      f.context.apiFetch=async method=>{calls.push(method);return method===stage?gate.promise:siteResponse(savedSite());};
      const pending=f.submit();await new Promise(resolve=>setImmediate(resolve));change(f);if(fail)gate.reject(Error('private error'));else gate.resolve(stage==='POST'?siteResponse(savedSite()):siteResponse({sites:[savedSite()]}));await pending;
      assert.equal(f.notices.length,0);assert.equal(f.reloads,0);assert.equal(calls.length,stage==='POST'?1:2);assert.ok(!f.modal.body.at(-1).textContent);
    }
  });
}
test('site uncertain save guidance is Japanese and inputs remain available for explicit retry', async () => {
  const f=siteEditorFixture(siteRequest,'ja');await f.submit();assert.match(f.modal.body.at(-1).textContent,/すでに反映/);assert.match(f.modal.body.at(-1).textContent,/新たな保存操作/);assert.equal(f.modal.footer.at(-1).disabled,false);
});
