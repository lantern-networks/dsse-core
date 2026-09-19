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

for(const path of ['/admin/tenant-cas','/admin/pki/operations','/admin/pki/paths','/admin/pki/trust-refusals','/admin/transport-trust-anchors','/admin/tenant-device-authority?readiness=1','/admin/tenant-transport-authority','/admin/tenant-interception-authority','/admin/transport-name-rename','/admin/interception-authority-rotation'])test('PKI map refuses missing dependency '+path,async()=>{
 const f=fixture(null),states=[];f.c.freshRender=()=>()=>true;f.c.uiState=(h,kind,message,action)=>states.push({kind,message,action});
 f.c.apiFetch=async(method,p)=>p===path?{ok:false,status:503,body:{error:'internal'}}:{ok:true,status:200,body:{has_authority:false,tenant_cas:[],paths:[],refusals:[],anchors:[],items:[]}};
 // The form fixture substitutes this function; restore the production loader.
 await f.c.originalLoadCertMap({});assert.equal(states.at(-1).kind,'error');assert.match(states.at(-1).message,/Required PKI information/);assert.equal(states.at(-1).action.label,'Retry');
});
