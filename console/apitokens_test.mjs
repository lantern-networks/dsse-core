import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('./apitokens.js',import.meta.url),'utf8');

test('token catalog uses the API roles and never invents fallback authority',async()=>{
 for(const body of [{api_token_roles:[{role:'analyst'}]}, {}, {api_token_roles:[]}, {api_token_roles:[{}]}]){
  const c=vm.createContext({apiFetch:async()=>({ok:true,body})});vm.runInContext(source,c);
  if(body.api_token_roles?.[0]?.role){const opts=await vm.runInContext('loadRoleOptions()',c);assert.equal(opts[0].value,'analyst');}
  else await assert.rejects(vm.runInContext('loadRoleOptions()',c));
 }
});

test('create posts the selected role as the API roles array',async()=>{
 let submit,posted;const c=vm.createContext({bl:v=>v.en,uiToast:()=>assert.fail('unexpected error'),
 uiField:f=>({el:{},get:()=>f.name==='role'?'analyst':'name',validate:()=>true,focus(){},setError(){}}),
 el:(tag,attrs)=>({...attrs,addEventListener:(event,fn)=>submit=fn}),uiModal:()=>({close(){}}),
 apiFetch:async(method,path,body)=>{if(method==='GET')return {ok:true,body:{api_token_roles:[{role:'analyst'}]}};posted=body;return {ok:true,body:{raw_token:'exact-secret'}};}});
 vm.runInContext(source,c);vm.runInContext('showSecretOnce=()=>{};renderApiTokensView=()=>{}',c);await vm.runInContext('openTokenForm({})',c);await submit();assert.equal(posted.name,'name');assert.deepEqual(Array.from(posted.roles),['analyst']);assert.equal(posted.role,undefined);
});

test('secret disclosure uses raw_token, not the token metadata object',()=>{
 const modals=[],errors=[];const c=vm.createContext({bl:v=>v.en,uiToast:(...a)=>errors.push(a),el:(tag,attrs)=>attrs,uiModal:m=>modals.push(m)});vm.runInContext(source,c);
 vm.runInContext('showSecretOnce({token:{id:"id"},raw_token:"exact-secret"},"created")',c);assert.equal(modals[0].body[1].text,'exact-secret');assert.equal(errors.length,0);
 for(const body of [{token:{id:'id'}},{raw_token:{}},{raw_token:''},{}]){c.body=body;vm.runInContext('showSecretOnce(body,"created")',c);}
 assert.equal(modals.length,1);assert.equal(errors.length,4);assert.ok(errors.every(e=>e[1]==='err'));
});

test('rotation and revocation transport errors do not escape or announce success',async()=>{
 for(const fn of ['rotateToken("id",{})','revokeToken("id","name",{})']){
  const errors=[];const c=vm.createContext({bl:v=>v.en,uiToast:(...a)=>errors.push(a),uiConfirm:async()=>true,apiFetch:async()=>{throw Error('offline');}});vm.runInContext(source,c);await vm.runInContext(fn,c);assert.equal(errors.length,1);assert.equal(errors[0][1],'err');
 }
});


test('catalog default role is the initial selection instead of a stronger first entry',async()=>{
 const c=vm.createContext({apiFetch:async()=>({ok:true,body:{api_token_default_role:'auditor',api_token_roles:[{role:'owner'},{role:'auditor'}]}})});vm.runInContext(source,c);const opts=await vm.runInContext('loadRoleOptions()',c);assert.equal(opts[0].value,'auditor');
});

function deferred(){let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};}
function actionFixture(){
 const confirm=deferred(),response=deferred(),calls=[],secrets=[],notices=[];let confirmations=0;
 const c=vm.createContext({bl:v=>v.en,uiConfirm:()=>{confirmations++;return confirm.promise;},
 uiToast:(...args)=>notices.push(args),apiFetch:async(...args)=>{calls.push(args);return response.promise;}});
 vm.runInContext(source,c);c.showSecretOnce=body=>secrets.push(body);c.renderTokList=()=>{};
 return {c,confirm,response,calls,secrets,notices,confirmations:()=>confirmations};
}
for(const second of ['rotate','revoke'])test(`a pending rotation blocks a second ${second} even from a reloaded list`,async()=>{
 const f=actionFixture();const first=f.c.rotateToken('same-token',{});
 const other=second==='rotate'?f.c.rotateToken('same-token',{}):f.c.revokeToken('same-token','name',{});
 assert.equal(f.confirmations(),1);
 f.confirm.resolve(true);await Promise.resolve();
 await (second==='rotate'?f.c.rotateToken('same-token',{}):f.c.revokeToken('same-token','name',{}));
 assert.equal(f.calls.length,1);
 f.response.resolve({ok:true,body:{raw_token:'synthetic-secret'}});await Promise.all([first,other]);
 assert.equal(f.secrets.length,1);
});
test('revocation blocks duplicate confirmation and rotation of the same token',async()=>{
 const f=actionFixture();const first=f.c.revokeToken('same-token','name',{});
 const second=f.c.revokeToken('same-token','name',{}),third=f.c.rotateToken('same-token',{});
 assert.equal(f.confirmations(),1);f.confirm.resolve(true);await Promise.resolve();
 f.response.resolve({ok:true});await Promise.all([first,second,third]);assert.equal(f.calls.length,1);
});
test('cancel or failed response releases the token for a subsequent deliberate action',async()=>{
 const f=actionFixture();f.confirm.resolve(false);await f.c.rotateToken('id',{});
 f.c.uiConfirm=async()=>true;f.response.resolve({ok:false,status:503});
 await f.c.rotateToken('id',{});await f.c.revokeToken('id','name',{});
 assert.equal(f.calls.length,2);assert.equal(f.secrets.length,0);
});
test('different tokens can be operated independently',async()=>{
 const f=actionFixture();const a=f.c.rotateToken('a',{}),b=f.c.revokeToken('b','name',{});
 assert.equal(f.confirmations(),2);f.confirm.resolve(true);await Promise.resolve();
 f.response.resolve({ok:true,body:{raw_token:'synthetic-secret'}});await Promise.all([a,b]);assert.equal(f.calls.length,2);
});

function createFixture(){
 const f={posts:[],notices:[],modals:[],secrets:[],host:{__tokenView:1},session:{},tenant:'tenant-a',base:'https://cp-a.example',token:'synthetic-auth'};
 const c=vm.createContext({bl:v=>v.en,idpSession:f.session,operateTenant:f.tenant,baseForPlane:()=>f.base,
 localStorage:{getItem:()=>f.token},uiToast:(...a)=>f.notices.push(a),
 uiField:opts=>({el:{},get:()=>opts.name==='role'?'auditor':'test integration',validate:()=>true,focus(){},setError(){}}),
 el:(tag,attrs)=>({...attrs,addEventListener:(event,fn)=>{if(attrs.text==='Create token')f.submit=fn;}}),
 uiModal:opts=>{const modal={...opts,close(){opts.onClose?.();}};f.modals.push(modal);return modal;},
 apiFetch:async(method,path,body)=>{if(method==='GET')return {ok:true,body:{api_token_roles:[{role:'auditor'}]}};f.posts.push({method,path,body,tenant:c.operateTenant});return {ok:true,body:{raw_token:'synthetic-secret'}};}});
 vm.runInContext(source,c);c.showSecretOnce=body=>f.secrets.push(body);c.renderApiTokensView=()=>{};f.c=c;return f;
}
const changeContext={tenant:f=>f.c.operateTenant='tenant-b',session:f=>f.c.idpSession={},connection:f=>f.base='https://cp-b.example',credential:f=>f.token='synthetic-new-auth',page:f=>f.host.__tokenView++,navigation:f=>f.host.firstChild={},detached:f=>f.host.isConnected=false};
for(const [name,change] of Object.entries(changeContext))test(`token creation refuses a changed ${name}`,async()=>{
 const f=createFixture();await f.c.openTokenForm(f.host);change(f);await f.submit();
 assert.equal(f.posts.length,0);assert.equal(f.secrets.length,0);assert.match(f.notices.at(-1)[0],/changed/);
});
test('closing creation before submission prevents later submit events',async()=>{
 const f=createFixture();await f.c.openTokenForm(f.host);f.modals[0].close();await f.submit();assert.equal(f.posts.length,0);
});
test('late role catalog does not open a form for a different tenant',async()=>{
 const f=createFixture(),roles=deferred();f.c.apiFetch=()=>roles.promise;
 const opening=f.c.openTokenForm(f.host);f.c.operateTenant='tenant-b';roles.resolve({ok:true,body:{api_token_roles:[{role:'auditor'}]}});await opening;
 assert.equal(f.modals.length,0);assert.match(f.notices.at(-1)[0],/changed/);
});
test('late creation response is not disclosed in another tenant view',async()=>{
 const f=createFixture(),response=deferred();await f.c.openTokenForm(f.host);
 f.c.apiFetch=()=>response.promise;const creating=f.submit();f.c.operateTenant='tenant-b';
 response.resolve({ok:true,body:{raw_token:'synthetic-secret'}});await creating;
 assert.equal(f.secrets.length,0);assert.match(f.notices.at(-1)[0],/changed/);
});
for(const action of ['rotate','revoke'])test(`${action} confirmation cannot act after the tenant changes`,async()=>{
 const f=actionFixture();f.c.operateTenant='tenant-a';const task=action==='rotate'?f.c.rotateToken('id',{}):f.c.revokeToken('id','name',{});
 f.c.operateTenant='tenant-b';f.confirm.resolve(true);await task;assert.equal(f.calls.length,0);assert.match(f.notices.at(-1)[0],/changed/);
});
test('a late rotation response is not disclosed after switching tenants',async()=>{
 const f=actionFixture();f.c.operateTenant='tenant-a';f.confirm.resolve(true);const task=f.c.rotateToken('id',{});await new Promise(setImmediate);
 f.c.operateTenant='tenant-b';f.response.resolve({ok:true,body:{raw_token:'synthetic-secret'}});await task;
 assert.equal(f.calls.length,1);assert.equal(f.secrets.length,0);assert.match(f.notices.at(-1)[0],/changed/);
});
