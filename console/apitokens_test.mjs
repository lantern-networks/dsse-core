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
