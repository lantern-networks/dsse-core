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
