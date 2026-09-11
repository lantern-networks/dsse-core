import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';
const source=readFileSync(new URL('./tenant_restriction.js',import.meta.url),'utf8');

test('existing provider form saves a managed M365 allowlist and context without legacy references',async()=>{
 const fields={},buttons=[],requests=[];
 const context=vm.createContext({
  bl:x=>x.en,
  uiField:options=>{const field={el:{},get:()=>field.value,value:options.value,focus(){},setError(){}};fields[options.name]=field;return field;},
  el:(tag,props)=>{const x={addEventListener:(_event,fn)=>{x.click=fn}};if(tag==='button')buttons.push(x);return x;},
  uiModal:()=>({close(){}}),uiToast(){},
  apiFetch:async(method,path,body)=>{requests.push({method,path,body});return {ok:true};},
 });
 vm.runInContext(source+'\nrenderTenantRestrictionView=()=>{};',context);
 vm.runInContext('openTrForm({}, {provider:"microsoft_365",managed:true,active:false})',context);
 assert.equal(fields.enforce.value,false);
 fields.value.value='company.example';fields.context_tenant_id.value='11111111-1111-4111-8111-111111111111';fields.enforce.value=true;
 await buttons[0].click();
 assert.equal(requests[0].body.provider,'microsoft_365');assert.equal(requests[0].body.allowed_value,'company.example');assert.equal(requests[0].body.context_tenant_id,fields.context_tenant_id.value);assert.equal(requests[0].body.enabled,true);assert.equal(requests[0].body.header_value_updates,undefined);
 fields.value.value='';fields.context_tenant_id.value='';fields.enforce.value=false;await buttons[0].click();
 assert.equal(requests[1].body.allowed_value,undefined);assert.equal(requests[1].body.context_tenant_id,undefined);assert.equal(requests[1].body.enabled,false);
});

test('SaaS reads and saves use the CP and retain the operated tenant',async()=>{
 const app=readFileSync(new URL('./app.js',import.meta.url),'utf8');const requests=[];
 const context=vm.createContext({localStorage:{getItem:()=>''},fetch:async(url,options)=>{requests.push({url,options});return {ok:true,status:200,text:async()=>JSON.stringify({rules:[]})};}});
 vm.runInContext(app.slice(app.indexOf('const CP_AUTHORED_WRITES = ['),app.indexOf('// offerOperatorElevation asks'))+'\noperateTenant="customer-one";',context);
 await vm.runInContext('apiFetch("GET","/admin/swg/tenant-restriction")',context);
 await vm.runInContext('apiFetch("POST","/admin/swg/tenant-restriction",{provider:"openai_chatgpt",enabled:false})',context);
 for(const req of requests){assert.equal(req.url,'/control/admin/swg/tenant-restriction');assert.equal(req.options.headers['x-operate-tenant'],'customer-one');}
});
