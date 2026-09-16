import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';
const source = readFileSync(new URL('./predefined_catalog.js', import.meta.url), 'utf8');
const ok = body => ({ ok: true, status: 200, body });
const entry = () => ({ id: 'service', name: '', vendor: '', category: '', risk: '', description: '', patterns: ['service.example'] });
const envelope = () => ({ type: 'predefined_catalog_feed', version: 'v2', payload: { version: 2, entries: [entry()] }, checksum: 'fixture', signature: 'fixture', signing_key_id: 'fixture', created_at: '', expires_at: '', status: 'active', metadata: null });
const applied = () => ({ catalog_version: 2, entries: [entry()], envelope_version: 'v2', signing_key_id: 'fixture', created_at: '', expires_at: '', applied_at: '2026-09-17T00:00:00Z', envelope: envelope() });
const status = () => ({ source: 'feed', catalog_version: 2, stale: false, current: applied(), history: [applied()] });
const doc = () => ({ source: 'feed', version: 2, entries: [entry()], overrides: [] });
const scoped = (data, scope = 'tenant', tenant_id = 'own') => ok({ data, scope, tenant_id });
function fixture() {
  const requests = [], paints = [], versions = new WeakMap();
  const controls = [{ disabled: false }], textarea = { value: 'draft', disabled: false };
  const node = () => ({ isConnected: true, innerHTML: '', textContent: '', setAttribute() {}, querySelectorAll: () => controls, querySelector: () => textarea });
  const content = node(), container = node(), feed = node(), ver = node(), button = node(), message = node();
  const ctx = vm.createContext({ bl: o => o.en, operateTenant: '', freshRender: n => { const i = (versions.get(n) || 0) + 1; versions.set(n, i); return () => versions.get(n) === i; }, apiFetch: async (method, path, body) => {
    requests.push({ method, path, body });
    if (method === 'POST') return scoped({ entry_id: 'service', mode: 'disabled', updated_at: '2026-09-17T00:00:00Z' });
    if (path === '/admin/tenant') return ok({ tenant_id: 'own' });
    return path.includes('/feed') ? scoped(status(), 'deployment') : scoped(doc());
  } });
  vm.runInContext(source, ctx);
  ctx.paintCatalog = (_, __, d) => paints.push(d);
  ctx.paintCatalogFeed = (_, s) => paints.push(s);
  const view = ctx.catalogView(content, container, ver, feed, button, message);
  const write = () => view.write('/admin/predefined-catalog/overrides', { entry_id: 'service', mode: 'disabled' }, 'tenant', x => ctx.catalogOverride(x) && x.entry_id === 'service' && x.mode === 'disabled');
  return { ctx, view, requests, paints, content, container, feed, button, message, controls, textarea, write };
}
for (const [name, mutate] of Object.entries({ missing: () => ({}), null: () => null, legacy: () => doc(), owner: x => ({ ...x, tenant_id: 'other' }), scope: x => ({ ...x, scope: 'deployment' }), version: x => ({ ...x, data: { ...doc(), version: '2' } }), entries: x => ({ ...x, data: { ...doc(), entries: null } }), empty: x => ({ ...x, data: { ...doc(), entries: [] } }), duplicate: x => ({ ...x, data: { ...doc(), entries: [entry(), entry()] } }), overrides: x => ({ ...x, data: { ...doc(), overrides: [{ entry_id: 'service', mode: 'bogus' }] } }) })) {
  test(`catalog ${name} discards old editable content`, async () => { const f = fixture(); await f.view.load(); const normal = f.ctx.apiFetch; f.ctx.apiFetch = (m, p, b) => p.includes('predefined-catalog?') ? ok(mutate(scoped(doc()).body)) : normal(m, p, b); await f.view.load(); assert.match(f.message.textContent, /Could not verify/); assert.equal(f.container.innerHTML, ''); assert.equal(f.controls[0].disabled, true); assert.equal(await f.write(), false); assert.equal(f.requests.filter(r => r.method === 'POST').length, 0); });
}
for (const [name, value] of Object.entries({ missing: {}, legacy: status(), wrongScope: { ...scoped(status(), 'tenant').body }, owner: { ...scoped(status(), 'deployment', 'other').body }, nullHistory: { ...status(), history: null }, stringStale: { ...status(), stale: 'false' }, version: { ...status(), catalog_version: 3 }, mixedEntries: { ...status(), current: { ...applied(), entries: [{ ...entry(), patterns: ['other'] }] } }, missingCurrent: { ...status(), current: null }, missingHistory: { ...status(), history: [] } })) {
  test(`feed ${name} cannot produce editable builtin defaults`, async () => { const f = fixture(), normal = f.ctx.apiFetch; f.ctx.apiFetch = (m, p, b) => p.includes('/feed') ? ok(['missing','legacy','wrongScope','owner'].includes(name) ? value : scoped(value, 'deployment').body) : normal(m, p, b); await f.view.load(); assert.equal(f.paints.length, 0); assert.match(f.message.textContent, /Could not verify/); });
}
test('builtin null history and optional unavailable feed are distinct', async () => {
  for (const unavailable of [false, true]) { const f = fixture(), normal = f.ctx.apiFetch; f.ctx.apiFetch = (m,p,b) => p.includes('/feed') ? unavailable ? {ok:false,status:503} : scoped({source:'builtin',catalog_version:2,stale:false,current:null,history:null},'deployment') : p.includes('predefined-catalog?') ? scoped({...doc(),source:'builtin'}) : normal(m,p,b); await f.view.load(); assert.equal(f.message.textContent, ''); assert.equal(f.controls[0].disabled, false); if (unavailable) assert.match(f.feed.textContent, /unavailable/); }
});
test('signed optional fields materialize correctly and history may repeat versions', () => { const f = fixture(), a = applied(); a.envelope.payload.entries = [{id:'service',patterns:['service.example']}]; assert.equal(f.ctx.catalogApplied(a),true); const s = status(); s.history.push(applied()); assert.equal(f.ctx.catalogFeedStatus(s),true); assert.equal(f.ctx.catalogSameEnvelope({...envelope(),metadata:undefined},envelope()),true); assert.equal(f.ctx.catalogSameEnvelope({...envelope(),signature:'other'},envelope()),false); });
test('unrelated historical override is permitted, duplicate override is not',()=>{const f=fixture(),o={entry_id:'absent',mode:'disabled',updated_at:'2026-09-17T00:00:00Z'};assert.equal(f.ctx.catalogDocument({...doc(),overrides:[o]}),true);assert.equal(f.ctx.catalogDocument({...doc(),overrides:[o,o]}),false)});
test('late read cannot overwrite a newer reload',async()=>{const f=fixture(),normal=f.ctx.apiFetch;let release,first=true;f.ctx.apiFetch=(m,p,b)=>p.includes('/feed')&&first?(first=false,new Promise(r=>release=r)):normal(m,p,b);const pending=f.view.load();await new Promise(setImmediate);await f.view.load();const count=f.paints.length;release(ok({}));await pending;assert.equal(f.paints.length,count);assert.equal(f.message.textContent,'')});
for(const kind of ['selection','replacement','disconnect'])test(`${kind} rejects late reads and sends no stale write`,async()=>{const f=fixture(),normal=f.ctx.apiFetch;let release;f.ctx.apiFetch=(m,p,b)=>p.includes('/feed')?new Promise(r=>release=r):normal(m,p,b);const pending=f.view.load();await new Promise(setImmediate);if(kind==='selection')f.ctx.operateTenant='other';if(kind==='replacement')f.ctx.freshRender(f.content);if(kind==='disconnect')f.content.isConnected=false;release(scoped(status(),'deployment'));await pending;assert.equal(f.paints.length,0);assert.equal(await f.write(),false);assert.equal(f.requests.filter(r=>r.method==='POST').length,0)});
for(const response of [ok({}),ok({tenant_id:'other'}),{ok:false,status:503}])test('unverified preflight sends zero writes',async()=>{const f=fixture();await f.view.load();const normal=f.ctx.apiFetch;f.ctx.apiFetch=(m,p,b)=>p==='/admin/tenant'?response:normal(m,p,b);assert.equal(await f.write(),false);assert.equal(f.requests.filter(r=>r.method==='POST').length,0);assert.equal(f.controls[0].disabled,true)});
for(const response of [ok({}),scoped({entry_id:'other',mode:'disabled',updated_at:'2026-09-17T00:00:00Z'}),scoped({entry_id:'service',mode:'force_inspect',updated_at:'2026-09-17T00:00:00Z'}),scoped({},'tenant','other'),{ok:false,status:500}])test('unconfirmed acknowledgement keeps draft and blocks repeat writes',async()=>{const f=fixture();await f.view.load();const normal=f.ctx.apiFetch;f.ctx.apiFetch=(m,p,b)=>m==='POST'?response:normal(m,p,b);assert.equal(await f.write(),false);assert.match(f.message.textContent,/Could not confirm/);assert.equal(f.textarea.value,'draft');assert.equal(f.controls[0].disabled,true);assert.equal(await f.write(),false)});
test('pending operations suppress duplicate POST and reload; failed transport retains input',async()=>{const f=fixture();await f.view.load();const normal=f.ctx.apiFetch;let reject;f.ctx.apiFetch=(m,p,b)=>m==='POST'?new Promise((_,r)=>reject=r):normal(m,p,b);const first=f.write();await new Promise(setImmediate);assert.equal(f.button.disabled,true);assert.equal(await f.write(),false);const n=f.requests.length;await f.view.load();assert.equal(f.requests.length,n);reject(new Error('private server detail'));assert.equal(await first,false);assert.match(f.message.textContent,/Could not confirm/);assert.doesNotMatch(f.message.textContent,/private/);assert.equal(f.textarea.value,'draft');assert.equal(f.button.disabled,false)});
test('confirmed writes carry context and require a fresh read',async()=>{const f=fixture();await f.view.load();assert.equal(await f.write(),true);assert.match(f.requests.at(-1).path,/\?scoped=1&expected_tenant_id=own$/);assert.equal(f.controls[0].disabled,true);await f.view.load();assert.equal(f.controls[0].disabled,false)});

for (const change of [{created_at: 123}, {expires_at: "invalid"}, {metadata: []}]) test('malformed envelope metadata or timestamps are not valid feed acknowledgements', () => { const f = fixture(); assert.equal(f.ctx.catalogEnvelope({...envelope(), ...change}), false); });

for (const updated_at of [undefined, '']) test('legacy optional override timestamp is readable but not a fresh write acknowledgement', () => { const f = fixture(), o = {entry_id:'service', mode:'disabled', updated_at}; assert.equal(f.ctx.catalogDocument({...doc(), overrides:[o]}), true); assert.equal(f.ctx.catalogOverride(o), false); });
test('malformed optional override timestamp still rejects the complete read', () => { const f = fixture(); for (const updated_at of [null, 'invalid', 123]) assert.equal(f.ctx.catalogDocument({...doc(), overrides:[{entry_id:'service',mode:'disabled',updated_at}]}), false); });
