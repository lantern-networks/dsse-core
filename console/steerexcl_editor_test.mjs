import {readFileSync} from 'node:fs';
import {webcrypto} from 'node:crypto';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';
const source = readFileSync(new URL('./steerexcl.js', import.meta.url), 'utf8');
const ok = body => ({ok:true, status:200, body});
const policy = () => ({id:'sx_owned', tenant_id:'own', scope_type:'tenant', scope_id:'', excluded_app_signing_ids:['one','two'], note:'reason', status:'active'});
const tick = () => new Promise(r => setImmediate(r));
function fixture() {
  const nodes=[], listeners=new Map(), requests=[];
  function el(tag, props={}, children=[]) {
    const n={tag, ...props, children:Array.isArray(children)?children:[children], isConnected:true, handlers:{},
      appendChild(x){this.children.push(x);}, remove(){this.isConnected=false;}, setAttribute(k,v){this[k]=v;},
      addEventListener(k,v){this.handlers[k]=v;},
      querySelectorAll(){return fields;},
    };
    nodes.push(n); return n;
  }
  const fields=[{disabled:false}], host=el('div'); let observed;
  const c=vm.createContext({el, crypto:webcrypto, bl:x=>x.en, operateTenant:'',
    document:{body:el('body'),addEventListener:(k,v)=>listeners.set(k,v), removeEventListener:k=>listeners.delete(k)},
    MutationObserver:class {constructor(f){observed=f;} observe(){} disconnect(){observed=null;}},
    apiFetch:async(...args)=>{requests.push(args);return ok({tenant_id:'own'});},
  });
  vm.runInContext(source,c);
  return {c, nodes, fields, host, requests, listeners, mutation:()=>observed?.()};
}
const validator=fixture().c;
for (const [name, change] of [
  ['empty',r=>r.body={}],['null',r=>r.body=null],['array',r=>r.body=[]],['wrong status',r=>r.status=201],['not ok',r=>r.ok=false],
  ['wrong id',r=>r.body.id='other'],['wrong tenant',r=>r.body.tenant_id='other'],['wrong scope',r=>r.body.scope_type='device'],
  ['wrong scope id',r=>r.body.scope_id='other'],['wrong note',r=>r.body.note='other'],['inactive',r=>r.body.status='disabled'],
  ['missing app',r=>r.body.excluded_app_signing_ids.pop()],['extra app',r=>r.body.excluded_app_signing_ids.push('three')],
  ['duplicate app',r=>r.body.excluded_app_signing_ids=['one','one']],['null app',r=>r.body.excluded_app_signing_ids=null],
]) test('save ACK rejects '+name,()=>{const r=ok(policy());change(r);assert.equal(validator.steerExclSaveConfirmed(r,policy()),false);});
test('save ACK accepts normalized app order and valid scopes',()=>{
  for(const scope of ['tenant','device_group','device']){const p=policy();p.scope_type=scope;p.scope_id=scope==='tenant'?'':'target';const r=ok({...p,excluded_app_signing_ids:['two','one']});assert.equal(validator.steerExclSaveConfirmed(r,p),true);}
});
for (const [name,change] of [
  ['empty',r=>r.body={}],['null',r=>r.body=null],['false',r=>r.body.deleted=false],['truthy',r=>r.body.deleted='true'],
  ['id',r=>r.body.id='other'],['tenant',r=>r.body.tenant_id='other'],['missing tenant',r=>delete r.body.tenant_id],
  ['status',r=>r.status=204],['HTTP failure',r=>r.ok=false],
]) test('delete ACK rejects '+name,()=>{const r=ok({deleted:true,id:'owned',tenant_id:'own'});change(r);assert.equal(validator.steerExclDeleteConfirmed(r,'owned','own'),false);});
test('delete ACK accepts matching result',()=>assert.equal(validator.steerExclDeleteConfirmed(ok({deleted:true,id:'owned',tenant_id:'own'}),'owned','own'),true));
test('new IDs have 128-bit random identity',()=>{const ids=new Set(Array.from({length:100},()=>validator.steerExclNewID()));assert.equal(ids.size,100);for(const id of ids)assert.match(id,/^sx_[a-f0-9]{32}$/);});
function dialog(f, opts={}) {
  let successes=0;
  f.c.steerExclMutationDialog({host:f.host,title:'Editor',body:[],submitLabel:'Save',onSubmit:async()=>{},onSuccess:()=>successes++,...opts});
  return {get successes(){return successes;},submit:f.nodes.find(n=>n.text==='Save'),cancel:f.nodes.find(n=>n.text==='Cancel'),retry:f.nodes.find(n=>n.text==='Retry'),notice:f.nodes.find(n=>n.role==='status'),backdrop:f.nodes.find(n=>n.class==='ui-modal-backdrop')};
}
test('pending write locks fields, Escape, backdrop, cancel and duplicate submissions',async()=>{
  const f=fixture();let release, calls=0;const d=dialog(f,{onSubmit:()=>{calls++;return new Promise(r=>release=r);}});await tick();
  const pending=d.submit.handlers.click();assert.equal(f.fields[0].disabled,true);assert.equal(d.cancel.disabled,true);
  await d.submit.handlers.click();d.cancel.onClick();f.listeners.get('keydown')({key:'Escape'});d.backdrop.onClick({target:d.backdrop});
  assert.equal(calls,1);assert.equal(d.backdrop.isConnected,true);release();await pending;assert.equal(d.successes,1);assert.equal(d.backdrop.isConnected,false);
});
test('unconfirmed write stays editable and retry does not reload tenant or lose form',async()=>{
  const f=fixture();let calls=0;const d=dialog(f,{onSubmit:async t=>{assert.equal(t,'own');if(++calls===1)throw Error('HTTP 500');}});await tick();
  await d.submit.handlers.click();assert.equal(d.successes,0);assert.equal(d.backdrop.isConnected,true);assert.equal(f.fields[0].disabled,false);assert.equal(d.notice.role,'alert');assert.match(d.notice.textContent,/may already be saved/);
  await d.submit.handlers.click();assert.equal(d.successes,1);assert.equal(f.requests.length,1);
});
test('validation failure sends nothing and unlocks editor',async()=>{const f=fixture();const d=dialog(f,{onSubmit:async()=>false});await tick();await d.submit.handlers.click();assert.equal(d.successes,0);assert.equal(d.submit.disabled,false);assert.equal(d.backdrop.isConnected,true);});
for(const kind of ['page','tenant']) test('leaving '+kind+' suppresses completion',async()=>{
  const f=fixture();let release;const d=dialog(f,{onSubmit:()=>new Promise(r=>release=r)});await tick();const pending=d.submit.handlers.click();
  if(kind==='page')f.host.isConnected=false;else f.c.operateTenant='other';f.mutation();assert.equal(d.backdrop.isConnected,false);release();await pending;assert.equal(d.successes,0);
});
for(const kind of ['HTTP','empty','foreign row','foreign selection']) test('organization '+kind+' cannot write and can retry',async()=>{
  const f=fixture();if(kind==='foreign selection')f.c.operateTenant='own';let valid=false,writes=0;
  f.c.apiFetch=async()=>valid?ok({tenant_id:'own'}):kind==='HTTP'?{ok:false,status:503}:kind==='empty'?ok({}):ok({tenant_id:'foreign'});
  const d=dialog(f,{tenantID:kind==='foreign row'?'own':undefined,onSubmit:async()=>writes++});await tick();await d.submit.handlers.click();assert.equal(writes,0);assert.equal(d.submit.disabled,true);assert.equal(d.retry.hidden,false);
  valid=true;await d.retry.handlers.click();assert.equal(d.submit.disabled,false);await d.submit.handlers.click();assert.equal(writes,1);
});
test('closing while organization loads discards late readiness',async()=>{
  const f=fixture();let release;f.c.apiFetch=()=>new Promise(r=>release=r);const d=dialog(f);assert.equal(d.submit.disabled,true);d.cancel.onClick();release(ok({tenant_id:'own'}));await tick();assert.equal(d.backdrop.isConnected,false);await d.submit.handlers.click();assert.equal(d.successes,0);
});
