import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';

const context = vm.createContext({bl:b=>b.en,httpErr:r=>r?.body?.error||'request failed'});
vm.runInContext(readFileSync(new URL('./rules.js',import.meta.url),'utf8'),context);
const expected={id:'draft-1',plane:'egress',priority:12,name:'Example',source:['*'],destination:['endpoint-1'],action:{access:'allow',inspection:'bypass',require_workload_attestation:true}};
const saved={...expected,tenant_id:'customer-a',status:'active',stage:'enforce'};
const response=body=>({ok:true,status:200,body});

test('rule save acknowledgment must match identity, tenant and authored fields',()=>{
  context.validateRuleSave(response(saved),expected,'customer-a');
  for(const body of [{},{...saved,id:'another'},{...saved,tenant_id:'customer-b'},{...saved,priority:13},{...saved,source:[]},{...saved,destination:['other']},{...saved,status:'disabled'},{...saved,action:{access:'allow',inspection:'inspect'}},{...saved,action:{access:'allow',inspection:'bypass'}}]) {
    assert.throws(()=>context.validateRuleSave(response(body),expected,'customer-a'));
  }
  assert.throws(()=>context.validateRuleSave({...response(saved),status:202},expected,'customer-a'));
  assert.throws(()=>context.validateRuleSave({ok:false,status:500,body:{error:'save failed'}},expected,'customer-a'),/save failed/);
});
test('DLP acknowledgment must retain the selected policy and identifiers',()=>{
  const want={...expected,action:{access:'allow',inspection:'inspect',dlp:{policy_id:'dlp-1',identifiers:['secret']}}};
  const got={...saved,action:{...want.action,dlp:{...want.action.dlp,action:''}}};
  context.validateRuleSave(response(got),want,'customer-a');
  assert.throws(()=>context.validateRuleSave(response({...got,action:{...got.action,dlp:{policy_id:'dlp-1'}}}),want,'customer-a'));
});
test('missing or malformed catalog cannot become an empty successful list',async()=>{
  for(const body of [null,{},'invalid']) {
    context.apiFetch=async()=>({ok:true,status:200,body});
    await assert.rejects(context.loadList('/admin/assets/endpoints'));
  }
  context.apiFetch=async()=>({ok:false,status:503,body:{error:'unavailable'}});
  await assert.rejects(context.loadList('/admin/assets/endpoints'),/HTTP 503/);
  context.apiFetch=async()=>({ok:true,status:200,body:[]});
  assert.equal((await context.loadList('/admin/assets/endpoints')).length,0);
});
test('tenant verification rejects missing context and propagates transport failure',async()=>{
  for(const body of [{},{tenant_id:''},{tenant_id:7}]) {
    context.apiFetch=async()=>({ok:true,status:200,body});
    await assert.rejects(context.ruleEditorTenant());
  }
  context.apiFetch=async()=>{throw new Error('transport down')};
  await assert.rejects(context.ruleEditorTenant(),/transport down/);
  context.apiFetch=async()=>({ok:true,status:200,body:{tenant_id:'customer-a'}});
  assert.equal(await context.ruleEditorTenant(),'customer-a');
});
test('unsupported inspection sources explain the remaining access and inspection scopes',()=>{assert.match(context.inspectionSourceWarningText('identity_context_unavailable'),/Only device sources/);assert.match(context.inspectionSourceWarningText('identity_context_unavailable'),/access rules still apply/);assert.match(context.inspectionSourceWarningText('no_resolved_device'),/No source device/);assert.match(context.inspectionSourceWarningText('future_reason'),/Check the inspection source/)});
