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

const listSite = () => ({site_id:'s',name:'Site',managed:true,health:'unknown',connector_count:0,online_count:0,regions:[]});
const listConnector = () => ({id:'c',name:'Connector',tenant_id:'tenant-a',connector_group_id:'s',online:true});
const catalogueResponse = (key, rows) => ({ok:true,status:200,body:{[key]:rows,count:rows?.length || 0}});
function siteListFixture(options={}) {
  const f=fixture(),state={authority:'',token:''},calls=[];
  f.context.baseForPlane=()=>state.authority;f.context.localStorage={getItem:()=>state.token};f.context.idpSession={auth_method:'admin_session',tenant_id:'tenant-a'};
  f.host.__siteCreateButton={disabled:false};
  const read=async(method,path)=>{calls.push([method,path]);const key=path==='/admin/tenant'?'tenant':path==='/admin/sites'?'sites':'connectors';const response=options[key];if(response instanceof Error)throw response;if(response!==undefined)return response;return key==='tenant'?{ok:true,status:200,body:{tenant_id:'tenant-a'}}:catalogueResponse(key,key==='sites'?[listSite()]:[]);};
  f.context.apiFetch=read;
  return {...f,state,calls,read,render:()=>f.context.renderSiteList(f.host)};
}
for(const key of ['sites','connectors']){
 for(const [name,response] of [
  ['HTTP 503',{ok:false,status:503,body:{error:'private diagnostic'}}],['204',{ok:true,status:204,body:{[key]:[],count:0}}],
  ['missing rows',{ok:true,status:200,body:{count:0}}],['object rows',{ok:true,status:200,body:{[key]:{},count:0}}],
  ['missing count',{ok:true,status:200,body:{[key]:[]}}],['wrong count',{ok:true,status:200,body:{[key]:[],count:1}}],
  ['null row',catalogueResponse(key,[null])],['array row',catalogueResponse(key,[[]])],['network',new Error('private diagnostic')],
 ])test(`site list ${key} ${name} is unavailable rather than empty`,async()=>{
  const f=siteListFixture({[key]:response});await f.render();assert.equal(f.states.at(-1).state,'error');assert.equal(f.host.__siteListReady,false);assert.equal(f.host.__siteCreateButton.disabled,true);assert.equal(f.host.children.length,0);assert.ok(!f.states.at(-1).message.includes('private diagnostic'));
 });
}
for(const [name,patch] of [['identity',{site_id:' '}],['name',{name:{}}],['region',{region:[]}],['policy',{ha_policy:42}],['managed',{managed:1}],['expected',{expected_connector_count:-1}],['count',{connector_count:'0'}],['online',{online_count:1}],['health',{health:'bad'}],['regions',{regions:{}}],['region element',{regions:[null]}],['tenant',{tenant_id:'foreign'}]]){
 test(`site list rejects malformed site ${name}`,async()=>{const f=siteListFixture({sites:catalogueResponse('sites',[{...listSite(),...patch}])});await f.render();assert.equal(f.states.at(-1).state,'error');});
}
for(const [name,patch] of [['identity',{id:''}],['tenant',{tenant_id:'foreign'}],['online',{online:'true'}],['group',{connector_group_id:{}}],['group whitespace',{connector_group_id:' s '}],['name',{name:null}],['heartbeat',{last_heartbeat_at:42}]]){
 test(`site list rejects malformed connector ${name}`,async()=>{const f=siteListFixture({connectors:catalogueResponse('connectors',[{...listConnector(),...patch}])});await f.render();assert.equal(f.states.at(-1).state,'error');});
}
test('site list rejects duplicate identities instead of rendering conflicting controls',async()=>{
 for(const key of ['sites','connectors']){const row=key==='sites'?listSite():listConnector();const f=siteListFixture({[key]:catalogueResponse(key,[row,row])});await f.render();assert.equal(f.states.at(-1).state,'error');}
});
test('site list supports verified empty arrays and nil Go slices, then retry restores a valid catalogue',async()=>{
 for(const empty of [[],null]){const f=siteListFixture({sites:catalogueResponse('sites',empty),connectors:catalogueResponse('connectors',empty)});await f.render();assert.equal(f.states.at(-1).state,'empty');assert.equal(f.host.__siteListReady,true);assert.equal(f.host.__siteCreateButton.disabled,false);}
 const options={connectors:{ok:false,status:503}};const f=siteListFixture(options);await f.render();options.connectors=catalogueResponse('connectors',[]);await f.states.at(-1).retry.onClick();assert.equal(f.host.__siteListReady,true);assert.equal(f.host.__siteCreateButton.disabled,false);assert.ok(f.host.children.length);
});
test('site list groups reserved property names and keeps unknown groups visible',async()=>{
 const f=siteListFixture({sites:catalogueResponse('sites',[{...listSite(),site_id:'__proto__',connector_count:1,online_count:1}]),connectors:catalogueResponse('connectors',[{...listConnector(),name:'Owned connector',connector_group_id:'__proto__'},{...listConnector(),id:'other',name:'Unassigned connector',connector_group_id:'constructor'}])});
 await f.render();const text=node=>[node.textContent||'',...(node.children||[]).map(text)].join(' ');const content=text(f.host);assert.match(content,/Owned connector/);assert.match(content,/Unassigned connector/);assert.match(content,/Connectors not assigned/);assert.equal(f.host.__siteListReady,true);
});
test('site list checks the selected tenant and authenticated cookie session without new permissions',async()=>{
 const selected=siteListFixture({connectors:catalogueResponse('connectors',[listConnector()])});selected.context.operateTenant='other';await selected.render();assert.equal(selected.states.at(-1).state,'error');
 for(const tenant_id of [undefined, null, '', ' tenant-a', 42]){const f=siteListFixture();f.context.idpSession={auth_method:'admin_session',tenant_id};await f.render();assert.equal(f.states.at(-1).state,'error');assert.equal(f.calls.length,0);}
});
test('connector-only token does not need the tenant-model endpoint; unknown scope still rejects mixed tenants',async()=>{
 for(const mixed of [false,true]){const conns=[listConnector()];if(mixed)conns.push({...listConnector(),id:'other',tenant_id:'foreign'});const f=siteListFixture({connectors:catalogueResponse('connectors',conns)});f.context.idpSession=null;f.state.token='connector-only';await f.render();assert.equal(f.calls.length,2);assert.ok(f.calls.every(([,path])=>path!='/admin/tenant'));assert.equal(f.host.__siteListReady,!mixed);}
});

const listContextChanges={selection:f=>{f.context.operateTenant='other';},session:f=>{f.context.idpSession={};},authority:f=>{f.state.authority='other';},credential:f=>{f.state.token='other';},detached:f=>{f.host.isConnected=false;},generation:f=>{f.context.freshRender(f.host);}};
for(const [name,change] of Object.entries(listContextChanges))for(const stage of ['catalogues'])test(`site list drops late ${stage} ${name} responses`,async()=>{
 for(const fail of [false,true]){
  const f=siteListFixture(),gate=deferredSiteReply();f.context.apiFetch=async(method,path)=>{if((stage==='tenant'&&path==='/admin/tenant')||(stage==='catalogues'&&path==='/admin/sites'))return gate.promise;return f.read(method,path);};
  const pending=f.render();await new Promise(r=>setImmediate(r));change(f);if(fail)gate.reject(Error('private diagnostic'));else gate.resolve(stage==='tenant'?{ok:true,status:200,body:{tenant_id:'tenant-a'}}:catalogueResponse('sites',[listSite()]));await pending;assert.equal(f.states.at(-1).state,'loading');assert.equal(f.host.__siteListReady,false);assert.equal(f.host.__siteCreateButton.disabled,true);assert.equal(f.host.children.length,0);
 }
});
test('site list Japanese error distinguishes unavailable data from no connectors',async()=>{const f=siteListFixture({connectors:{ok:false,status:503}});f.context.bl=x=>x.ja;await f.render();assert.match(f.states.at(-1).message,/確認できませんでした/);assert.equal(f.states.at(-1).retry.label,'再試行');});

for (const group of ['s', '', '__proto__']) for (const reverse of [false,true]) {
 test(`site availability follows the server answer for group ${JSON.stringify(group)} with reversed order ${reverse}`,async()=>{
  const conns=[
   {...listConnector(),id:'z',name:'Zulu',connector_group_id:group,online:true,tunnel_connected:null,status:'offline'},
   {...listConnector(),id:'a',name:'Alpha',connector_group_id:group,online:true,tunnel_connected:false},
   {...listConnector(),id:'offline',name:'Not online',connector_group_id:group,online:false,tunnel_connected:true,status:'healthy'},
  ];if(reverse)conns.reverse();
  const f=siteListFixture({sites:catalogueResponse('sites',group?[{...listSite(),site_id:group,connector_count:3,online_count:2}]:[]),connectors:catalogueResponse('connectors',conns)});
  f.context.uiBadge=(text,kind)=>f.context.el('span',{text,badgeKind:kind});await f.render();
  const text=node=>[node.textContent||'',...(node.children||[]).map(text)].join(' ');
  const rendered=f.host.querySelectorAll('tr').filter(n=>n.children[0]?.tag==='td');assert.equal(rendered.length,3);
  for(const row of rendered){
   const name=text(row.children[0]);const badge=row.children[1].children[0];assert.equal(badge.textContent,name.includes('Not online')?'Offline':'Online');assert.equal(badge.badgeKind,name.includes('Not online')?'danger':'ok');
  }
  const content=text(f.host);assert.match(content,/Availability/);assert.ok(!/\bActive\b|\bStandby\b|\bConnected\b/.test(content));assert.match(content,/recent heartbeats/);
 });
}
test('site availability labels and explanation are Japanese',async()=>{
 const f=siteListFixture({connectors:catalogueResponse('connectors',[listConnector(),{...listConnector(),id:'offline',online:false}])});f.context.bl=x=>x.ja;f.context.uiBadge=(text,kind)=>f.context.el('span',{text,badgeKind:kind});await f.render();const text=n=>[n.textContent||'',...(n.children||[]).map(text)].join(' ');assert.match(text(f.host),/稼働状態/);assert.match(text(f.host),/オンライン/);assert.match(text(f.host),/オフライン/);assert.ok(!/アクティブ|スタンバイ/.test(text(f.host)));
});

function siteDeleteFixture(language = 'en') {
  const f = fixture(), notices = [], modals = [], calls = [];
  const state = {authority: 'https://control.test', token: '', reloads: 0, detailClosed: 0};
  f.host.isConnected = true; f.host.__renderSeq = 1;
  f.context.operateTenant = ''; f.context.idpSession = {auth_method: 'admin_session', tenant_id: 'tenant-a'};
  f.context.baseForPlane = () => state.authority;
  f.context.localStorage = {getItem: () => state.token}; f.context.bl = x => x[language];
  f.context.uiToast = (...args) => notices.push(args);
  f.context.renderSiteList = () => state.reloads++;
  f.context.uiModal = opts => {
    const modal = {opts, el: {isConnected: true}, close() { if (this.el.isConnected) { this.el.isConnected = false; opts.onClose?.(); } }};
    modals.push(modal); return modal;
  };
  f.context.apiFetch = async (...args) => {
    calls.push(args);
    return args[0] === 'DELETE' ? {ok: true, status: 200, body: {site_id: 'site/id', deleted: true}}
      : {ok: true, status: 200, body: {sites: [], count: 0}};
  };
  const detail = {el: {isConnected: true}, close() {state.detailClosed++; this.el.isConnected = false;}};
  const open = () => f.context.deleteSite('site/id', 'Review site', detail, f.host);
  open();
  const modal = modals[0], confirm = modal.opts.footer[1], notice = modal.opts.body[1];
  return {...f, state, notices, modals, calls, detail, open, modal, confirm, notice};
}
const deletedCatalogue = (rows = []) => ({ok: true, status: 200, body: {sites: rows, count: rows.length}});
const derivedSite = (overrides = {}) => ({site_id: 'site/id', tenant_id: 'tenant-a', health: 'healthy', connector_count: 1, online_count: 1, ...overrides});

test('site deletion verifies the identity acknowledgement and persistent record disappearance', async () => {
  const f = siteDeleteFixture(); await f.confirm.onclick();
  assert.deepEqual(f.calls.map(c => [c[0], c[1], c[3]]), [['DELETE', '/admin/sites/site%2Fid', 'control'], ['GET', '/admin/sites', 'control']]);
  assert.equal(f.modal.el.isConnected, false); assert.equal(f.state.detailClosed, 1);
  assert.equal(f.state.reloads, 1); assert.equal(f.notices[0][1], 'ok');
  assert.equal(f.host.__siteDeletions.size, 0);
});

for (const [name, response] of [
  ['empty', {}], ['null', null], ['array', []], ['wrong identity', {site_id: 'other', deleted: true}],
  ['false', {site_id: 'site/id', deleted: false}], ['string', {site_id: 'site/id', deleted: 'true'}],
  ['missing deleted', {site_id: 'site/id'}], ['missing identity', {deleted: true}],
]) test(`site deletion rejects ${name} acknowledgement without a second destructive attempt`, async () => {
  const f = siteDeleteFixture(); f.context.apiFetch = async (...args) => {f.calls.push(args); return {ok: true, status: 200, body: response};};
  await f.confirm.onclick(); await f.confirm.onclick();
  assert.equal(f.calls.length, 1); assert.equal(f.confirm.disabled, true); assert.equal(f.modal.el.isConnected, true);
  assert.match(f.notice.textContent, /may already have been applied/); assert.equal(f.notices.length, 0); assert.equal(f.state.reloads, 0);
});

for (const [name, response] of [
  ['HTTP failure', {ok: false, status: 503, body: {error: 'private diagnostic'}}],
  ['wrong status', {ok: true, status: 202, body: {site_id: 'site/id', deleted: true}}],
  ['transport exception', new Error('private diagnostic')],
]) test(`site deletion contains ${name} without exposing raw diagnostics`, async () => {
  const f = siteDeleteFixture('ja'); f.context.apiFetch = async () => {if (response instanceof Error) throw response; return response;};
  await f.confirm.onclick(); assert.match(f.notice.textContent, /削除を確認できません/);
  assert.doesNotMatch(f.notice.textContent, /private diagnostic/); assert.equal(f.notices.length, 0);
});

for (const [name, readback] of [
  ['still managed', deletedCatalogue([derivedSite({managed: true})])],
  ['null managed', deletedCatalogue([derivedSite({managed: null})])],
  ['duplicate rows', deletedCatalogue([derivedSite(), derivedSite()])],
  ['foreign tenant', deletedCatalogue([derivedSite({tenant_id: 'tenant-b'})])],
  ['missing rows', {ok: true, status: 200, body: {count: 0}}],
  ['wrong count', {ok: true, status: 200, body: {sites: [], count: 1}}],
  ['read HTTP failure', {ok: false, status: 503, body: {error: 'private diagnostic'}}],
  ['read exception', new Error('private diagnostic')],
]) test(`site deletion does not confirm ${name} readback`, async () => {
  const f = siteDeleteFixture(), reply = f.context.apiFetch;
  f.context.apiFetch = async (...args) => {if (args[0] === 'DELETE') return reply(...args); if (readback instanceof Error) throw readback; return readback;};
  await f.confirm.onclick(); assert.match(f.notice.textContent, /could not be confirmed/);
  assert.equal(f.notices.length, 0); assert.equal(f.state.detailClosed, 0);
});

test('site deletion accepts derived connector groups with omitted or false managed and Go nil lists', async () => {
  for (const readback of [deletedCatalogue([derivedSite()]), deletedCatalogue([derivedSite({managed: false})]), {ok: true, status: 200, body: {sites: null, count: 0}}]) {
    const f = siteDeleteFixture(), reply = f.context.apiFetch;
    f.context.apiFetch = (...args) => args[0] === 'DELETE' ? reply(...args) : Promise.resolve(readback);
    await f.confirm.onclick(); assert.equal(f.state.reloads, 1); assert.equal(f.notices.length, 1);
  }
});

const changeDeleteContext = {
  selection: f => {f.context.operateTenant = 'tenant-b';}, session: f => {f.context.idpSession = {...f.context.idpSession};},
  authority: f => {f.state.authority = 'https://elsewhere.test';}, token: f => {f.state.token = 'new-token';},
  generation: f => {f.host.__renderSeq++;}, detached: f => {f.host.isConnected = false;},
  detail: f => {f.detail.el.isConnected = false;}, closed: f => {f.modal.close();},
};
for (const [name, change] of Object.entries(changeDeleteContext)) {
  test(`site deletion rejects ${name} context changes during confirmation`, async () => {
    const f = siteDeleteFixture(); change(f); await f.confirm.onclick();
    assert.equal(f.calls.length, 0); assert.equal(f.notices.length, 0); assert.equal(f.state.reloads, 0);
  });
  test(`site deletion discards late DELETE and readback after ${name} context changes`, async () => {
    for (const step of ['DELETE', 'GET']) for (const fail of [false, true]) {
      const f = siteDeleteFixture(), reply = f.context.apiFetch, gate = deferredSiteReply();
      f.context.apiFetch = async (...args) => {if (args[0] === step) {f.calls.push(args); return gate.promise;} return reply(...args);};
      const done = f.confirm.onclick();
      if (step === 'GET') await new Promise(resolve => setImmediate(resolve));
      change(f);
      if (fail) gate.reject(new Error('old private error'));
      else gate.resolve(step === 'DELETE' ? {ok: true, status: 200, body: {site_id: 'site/id', deleted: true}} : deletedCatalogue());
      await done; assert.equal(f.calls.length, step === 'DELETE' ? 1 : 2);
      assert.equal(f.notices.length, 0); assert.equal(f.state.reloads, 0); assert.equal(f.notice.textContent, '');
    }
  });
}

test('site deletion suppresses duplicate dialogs and clicks until a dismissed request finishes', async () => {
  const f = siteDeleteFixture(), gate = deferredSiteReply(); f.context.apiFetch = async (...args) => {f.calls.push(args); return gate.promise;};
  f.open(); assert.equal(f.modals.length, 1);
  const done = f.confirm.onclick(); await f.confirm.onclick(); f.modal.close(); f.open();
  assert.equal(f.modals.length, 1); assert.equal(f.calls.length, 1); assert.equal(f.confirm.disabled, true);
  gate.resolve({ok: true, status: 200, body: {site_id: 'site/id', deleted: true}}); await done;
  assert.equal(f.host.__siteDeletions.size, 0); f.open(); assert.equal(f.modals.length, 2);
});

test('cancelled site deletion permits a fresh confirmation without writing', () => {
  const f = siteDeleteFixture(); f.modal.close(); f.open(); assert.equal(f.modals.length, 2); assert.equal(f.calls.length, 0);
});

test('invalid cookie tenant refuses a site deletion dialog; scoped API token needs no tenant read', async () => {
  for (const tenant of [undefined, null, '', ' ']) {
    const f = siteDeleteFixture(); f.modal.close(); f.context.idpSession = {auth_method: 'admin_session', tenant_id: tenant}; f.open(); assert.equal(f.modals.length, 1);
  }
  const f = siteDeleteFixture(); f.modal.close(); f.context.idpSession = null; f.open();
  await f.modals.at(-1).opts.footer[1].onclick(); assert.equal(f.state.reloads, 1);
  assert.equal(f.calls.some(c => c[1] === '/admin/tenant'), false);
});
