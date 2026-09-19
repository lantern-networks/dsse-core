import {readFileSync} from 'node:fs';import vm from 'node:vm';import assert from 'node:assert/strict';import test from 'node:test';
const c=vm.createContext({bl:x=>x.en});vm.runInContext(readFileSync(new URL('./incoming.js',import.meta.url),'utf8'),c);
const plain=x=>JSON.parse(JSON.stringify(x));
const current={id:'legacy',source_server:'10.0.0.1',service_family:'custom',protocol:'tcp',port:4444,status:'disabled',mode:'warn',approval_required:true,max_session_seconds:77,expires_at:'2027-01-01T15:12:13Z'};
test('owner-only edit retains exact constraints, disabled state and expiry instant',()=>{const got=plain(c.incomingExceptionPayload(current,{id:current.id,business_owner:'New owner',mode:current.mode},'__raw__',[],'2027-01-01'));for(const k of ['service_family','protocol','port','status','mode','approval_required','max_session_seconds','expires_at'])assert.deepEqual(got[k],current[k],k)});
test('catalog display name does not become service family and multiport selection is explicit',()=>{const choices=plain(c.incomingServiceChoices([{id:'s',alias:'Finance service',ports:[{protocol:'tcp',port:22},{protocol:'tcp',port:2222},{protocol:'udp',port:22}]}]));assert.equal(choices.length,2);assert.notEqual(choices[0].value,choices[1].value);const got=c.incomingExceptionPayload(null,{id:'new'},choices[1].value,choices,'2027-02-01');assert.equal(got.service_family,'');assert.equal(got.protocol,'tcp');assert.equal(got.port,2222);assert.equal(got.expires_at,'2027-02-01T00:00:00.000Z')});
test('only explicit Any clears a prior service; unknown selection refuses save',()=>{const got=c.incomingExceptionPayload(current,{},'',[],'2027-01-01');assert.equal(got.port,0);assert.equal(got.protocol,'');assert.equal(got.service_family,'');assert.throws(()=>c.incomingExceptionPayload(current,{},'missing',[],'2027-01-01'),/unavailable/)});
test('invalid ports and unsupported UDP do not masquerade as supported services',()=>{assert.equal(c.incomingServiceChoices([{id:'s',ports:[{protocol:'udp',port:53},{protocol:'tcp',port:0},{protocol:'tcp',port:65536}]}]).length,0)});

test('unreadable defaults never render an allow state or an edit action',async()=>{
 for(const response of [{ok:false,status:503,body:{}},{ok:true,status:200,body:{}},{ok:true,status:200,body:{server_initiated_enabled:'false'}}]){
  const host={},states=[],f=vm.createContext({bl:x=>x.en,uiState:(h,kind,message,action)=>states.push({kind,message,action}),freshRender:()=>()=>true,apiFetch:async()=>response,el:()=>{throw Error('must not offer editing')}});
  vm.runInContext(readFileSync(new URL('./incoming.js',import.meta.url),'utf8'),f);
  await f.renderIncomingView(host);assert.equal(states.at(-1).kind,'error');assert.equal(states.at(-1).action.label,'Retry');assert.equal(typeof states.at(-1).action.onClick,'function');
 }
 assert.equal(c.incomingDefaultBody({ok:true,status:200,body:{server_initiated_enabled:false}}),false);
 assert.equal(c.incomingDefaultBody({ok:true,status:200,body:{server_initiated_enabled:true}}),true);
});
test('failed asset catalogue cannot open an empty incoming editor',async()=>{
 const toasts=[],f=vm.createContext({bl:x=>x.en,catalogIndex:async()=>{throw Error('unavailable')},uiToast:x=>toasts.push(x),uiField:()=>{throw Error('editor opened')}});
 vm.runInContext(readFileSync(new URL('./incoming.js',import.meta.url),'utf8'),f);
 await f.openExceptionForm({});assert.match(toasts[0],/catalog could not be read/);
});
