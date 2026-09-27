import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';
const source = readFileSync(new URL('./certs.js', import.meta.url), 'utf8');
function fixture(authority, language = 'en') {
  const calls = [], notices = [], fields = [], modals = [];
  function el(tag, attrs = {}, children = []) {
    const node = {tag, ...attrs, style: {}, children: [], listeners: {}, disabled: false,
      textContent: attrs.text || '',
      appendChild(child) { if (child) this.children.push(child); return child; },
      addEventListener(name, handler) { this.listeners[name] = handler; }};
    for (const child of [children].flat(Infinity)) node.appendChild(child);
    return node;
  }
  const c = vm.createContext({el, bl: value => value[language], operateTenant: '',
    uiField: opts => {const f = {el: el('textarea'), get: () => 'synthetic-' + opts.name, setError(message) {f.error = message;}}; fields.push(f); return f;},
    uiModal: opts => {const m = {...opts, closed: false, close() {this.closed = true;}}; modals.push(m); return m;},
    uiToast: (message, kind) => notices.push({message, kind}),
    apiFetch: async (...args) => {calls.push(args); return {ok: true, body: {staged: true}};},
  });
  vm.runInContext(source, c);
  c.pkiDeploymentAct = () => false;
  c.originalLoadCertMap = c.loadCertMap;
  c.loadCertMap = () => {};
  vm.runInContext('_pkiTenantInterception = ' + JSON.stringify(authority) + ';', c);
  const card = c.tenantInterceptionCAControl(el('div'));
  const buttons = node => [...(node.tag === 'button' ? [node] : []), ...(node.children || []).flatMap(buttons)];
  return {c, calls, notices, fields, modals, card, buttons: buttons(card)};
}
for (const language of ['en', 'ja']) {
  test(`existing authority offers staged replacement even when an Edge cannot answer (${language})`, async () => {
    const f = fixture({has_authority: true, staged: false}, language);
    const b = f.buttons.find(b => b.textContent === (language === 'en' ? 'Stage a replacement CA' : '次のCAを登録'));
    assert.ok(b); assert.notEqual(b.style.display, 'none'); assert.equal(b.disabled, false);
    b.listeners.click(); const m = f.modals[0];
    await m.footer.at(-1).listeners.click();
    assert.equal(f.calls.length, 1); assert.equal(f.calls[0][1], '/admin/tenant-interception-authority');
    assert.equal(Object.hasOwn(f.calls[0][2], 'tenant_id'), false);
    assert.equal(m.closed, true); assert.match(f.notices[0].message, language === 'en' ? /current authority remains in use/ : /現在のCAは使用を続けます/);
  });
}
test('an authority already awaiting adoption cannot stage a second replacement', () => {
  const f = fixture({has_authority: true, staged: true});
  assert.equal(f.buttons.length, 1); assert.equal(f.buttons[0].disabled, true);
});
test('unknown authority is not treated as a new tenant eligible for import', () => {
  const f = fixture(null); assert.equal(f.buttons.length, 1); assert.equal(f.buttons[0].disabled, true);
});
test('first import distinguishes saving from deployment propagation', async () => {
  const f = fixture({has_authority: false, staged: false});
  f.c.apiFetch = async () => ({ok: true, body: {staged: false}});
  f.buttons.find(b => b.textContent === "Load this tenant's interception CA").listeners.click();
  await f.modals[0].footer.at(-1).listeners.click();
  assert.match(f.notices[0].message, /Each Edge applies it on its next refresh/);
});
test('failed replacement stays open for retry and does not announce a switch', async () => {
  const f = fixture({has_authority: true, staged: false});
  f.c.apiFetch = async () => ({ok: false, status: 400, body: {error: 'Save refused'}});
  f.buttons[0].listeners.click(); const m = f.modals[0]; await m.footer.at(-1).listeners.click();
  assert.equal(m.closed, false); assert.equal(m.footer.at(-1).disabled, false);
  assert.deepEqual(f.notices, [{message: 'Save refused', kind: 'err'}]);
});

test('history failure stays unavailable and Retry can recover to a verified empty history',async()=>{
 const f=fixture(null),states=[];let unavailable=true;
 f.c.uiState=(host,kind,message,action)=>{host.children=[];states.push({kind,message,action})};
 f.c.apiFetch=async()=>unavailable?{ok:false,status:503,body:{error:'private detail'}}:{ok:true,status:200,body:{versions:[]}};
 await f.c.showCertHistory({label:{en:'Node'},plane:'control'},'node',{});
 assert.equal(states.at(-1).kind,'error');assert.match(states.at(-1).message,/could not be read/);assert.doesNotMatch(states.at(-1).message,/private detail/);
 unavailable=false;await states.at(-1).action.onClick();const host=f.modals[0].body[0];assert.ok(host.children.some(n=>String(n.text).includes('No previous versions')));
});

const dependencies = ['/admin/tenant-cas','/admin/pki/operations','/admin/pki/paths','/admin/pki/trust-refusals','/admin/transport-trust-anchors','/admin/interception-intermediate','/admin/tenant-device-authority?readiness=1','/admin/tenant-transport-authority','/admin/tenant-interception-authority','/admin/transport-name-rename','/admin/interception-authority-rotation'];
const certificate = {id:'synthetic-node', role:'node', subject:'CN=fixture.example', not_after:'2027-01-01T00:00:00Z', sha256:'synthetic-fingerprint', active:true};
const textOf = node => [node.textContent || '', ...(node.children || []).map(textOf)].join(' ');
const buttonsOf = node => [...(node.tag === 'button' ? [node] : []), ...(node.children || []).flatMap(buttonsOf)];
function inventoryFixture(language='en') {
  const f=fixture(null,language); f.host=f.c.el('div'); f.states=[];
  Object.defineProperty(f.host,'innerHTML',{set(){this.children=[]}});
  f.c.freshRender=()=>()=>true;
  f.c.uiState=(h,kind,message,action)=>{h.innerHTML='';f.states.push({kind,message,action})};
  f.c.loadCertMap=f.c.originalLoadCertMap;
  f.c.apiFetch=async(method,path,body,plane)=>{
    f.calls.push({method,path,plane});
    if(path===f.failedPath)return {ok:false,status:f.status || 403,body:{error:'internal detail'}};
    if(path==='/admin/pki/certificates') {
      if(plane===f.failedPlane)return {ok:false,status:403};
      return {ok:true,body:f.inventory || {items:[certificate],measured_on:plane || 'edge'}};
    }
    return {ok:true,body:{has_authority:false,tenant_cas:[],paths:[],refusals:[],anchors:[]}};
  };
  f.failedPlane='neither'; return f;
}
for(const path of dependencies)for(const status of [403,503])test(`inventory remains readable when ${path} returns ${status}`,async()=>{
  const f=inventoryFixture();f.failedPath=path;f.status=status;
  await f.c.loadCertMap(f.host);
  assert.match(textOf(f.host),/fixture.example/);assert.match(textOf(f.host),/2027-01-01/);
  assert.match(textOf(f.host),/synthetic-fingerprint/);assert.match(textOf(f.host),/Changes are unavailable/);
  assert.doesNotMatch(textOf(f.host),/internal detail/);
  assert.deepEqual(buttonsOf(f.host).map(b=>b.textContent),['Retry']);
  assert.ok(f.calls.every(c=>c.method==='GET'));
});
test('partial inventory distinguishes an unreadable node from an empty node (Japanese)',async()=>{
  const f=inventoryFixture('ja');f.failedPath=dependencies[0];f.failedPlane='control';f.inventory={items:[]};
  await f.c.loadCertMap(f.host);
  assert.match(textOf(f.host),/一覧は空/);assert.match(textOf(f.host),/状態は不明/);
  assert.equal(buttonsOf(f.host)[0].textContent,'再試行');
});
test('same responding node is shown only once',async()=>{
 const f=inventoryFixture();f.failedPath=dependencies[0];f.inventory={items:[certificate],measured_on:'same-node'};
 await f.c.loadCertMap(f.host);assert.equal(textOf(f.host).split('fixture.example').length-1,1);
});
test('retry recovers the full map after missing information becomes readable',async()=>{
 const f=inventoryFixture();f.failedPath=dependencies[0];
 await f.c.loadCertMap(f.host);const retry=buttonsOf(f.host)[0];
 f.failedPath=null;f.inventory={items:[]};f.c.pkiDeploymentAct=()=>true;
 await retry.onClick();assert.doesNotMatch(textOf(f.host),/Changes are unavailable|synthetic-fingerprint/);
 assert.equal(f.states.at(-1).kind,'loading');assert.equal(buttonsOf(f.host).length,0);
});
test('missing or malformed certificate lists are never accepted as empty inventory',async()=>{
 for(const body of [{},{items:{}},{items:[null]}]) {
  const f=inventoryFixture();f.inventory=body;
  await f.c.loadCertMap(f.host);assert.equal(f.states.at(-1).kind,'error');
  assert.match(f.states.at(-1).message,/Invalid certificate list/);
 }
});
test('certificate read denial does not assert that delegation is the only cause',async()=>{
 const f=inventoryFixture();f.failedPath='/admin/pki/certificates';
 await f.c.loadCertMap(f.host);assert.equal(f.states.at(-1).kind,'error');
 assert.match(f.states.at(-1).message,/read permissions/);
});
