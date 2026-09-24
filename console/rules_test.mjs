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


test('cert-pin summary only represents unmodified unrestricted allow/bypass rules',()=>{
 const r={id:'certpin-rule-saved',plane:'egress',source:['*'],destination:['endpoint'],action:{access:'allow',inspection:'bypass'},status:'active'};
 assert.equal(context.isCertPinSummaryRule(r),true);
 assert.equal(context.isCertPinSummaryRule({...r,status:'disabled'}),true);
 for(const changed of [
  {...r,action:{access:'allow',inspection:'inspect'}},
  {...r,action:{access:'deny',inspection:'bypass'}},
  {...r,action:{...r.action,require_workload_attestation:true}},
  {...r,source:['device-a']}, {...r,destination:['a','b']},
  {...r,service_id:'ssh'}, {...r,risk_at_least:'high'}, {...r,allowed_tool_ids:['tool']},
  {...r,id:'ordinary-rule'}, {...r,plane:'eastwest'},
 ]) assert.equal(context.isCertPinSummaryRule(changed),false,JSON.stringify(changed));
});

function observationAdoptionFixture(reply) {
  const writes=[],editors=[],errors=[];
  const ctx=vm.createContext({bl:b=>b.en,SUBJECT_ANY:'*',uiToast:(...a)=>errors.push(a),
    apiFetch:async(method,path,body)=>{if(method==='GET')return reply;writes.push({path,body});return{ok:true,body:{id:'endpoint'}};},
    loadList:async()=>[],uiPrompt:async()=> 'host',openRuleEditor:(...a)=>editors.push(a)});
  vm.runInContext(readFileSync(new URL('./eastwestadvanced.js',import.meta.url),'utf8'),ctx);
  return{ctx,writes,editors,errors};
}
test('observation adoption refuses unavailable or removed inventory before any write',async()=>{
  for(const reply of [{ok:false,status:503},{ok:true,body:{observations:[]}}]){
    const f=observationAdoptionFixture(reply);await f.ctx.adoptFlowIntoRule({observation_id:'flow',destination:'stale',port:22},{});
    assert.equal(f.writes.length,0);assert.equal(f.editors.length,0);assert.equal(f.errors.length,1);
  }
});
test('observation adoption uses the refreshed flow before endpoint creation',async()=>{
  const f=observationAdoptionFixture({ok:true,body:{observations:[{observation_id:'flow',destination:'fresh',port:445,service_family:'smb'}]}});
  await f.ctx.adoptFlowIntoRule({observation_id:'flow',destination:'stale',port:22},{});
  assert.equal(f.writes[0].body.address,'fresh');assert.match(f.editors[0][3].name,/fresh:445/);
});

function dlpSelectorFixture(reply, existing='saved-policy') {
  const select={disabled:false,value:'',options:[],replaceChildren(...options){this.options=options;this.value=options[0]?.value||'';}};
  const errors=[];const field={el:{querySelector:()=>select},setError:m=>errors.push(m)};
  const ctx=vm.createContext({bl:b=>b.en,el:(_tag,props)=>props,apiFetch:()=>reply});
  vm.runInContext(readFileSync(new URL('./rules.js',import.meta.url),'utf8'),ctx);
  return {select,errors,start:()=>ctx.loadRuleDLPPolicies(field,existing)};
}
test('rule DLP selection survives loading and a temporarily unavailable list',async()=>{
  let resolve;const f=dlpSelectorFixture(new Promise(r=>resolve=r));const pending=f.start();
  assert.equal(f.select.value,'saved-policy');assert.equal(f.select.disabled,true);
  resolve({ok:false,status:503});await pending;
  assert.equal(f.select.value,'saved-policy');assert.equal(f.select.disabled,true);assert.match(f.errors.at(-1),/unchanged/);
});
test('deleted policy remains selectable until the operator explicitly chooses None',async()=>{
  const f=dlpSelectorFixture(Promise.resolve({ok:true,body:{policies:[]}}));await f.start();
  assert.equal(f.select.value,'saved-policy');assert.equal(f.select.disabled,false);
  assert.deepEqual(f.select.options.map(x=>x.value),['','saved-policy']);assert.match(f.errors.at(-1),/not available/);
  f.select.value='';assert.equal(f.select.value,'');
});
test('available policies replace placeholders without losing the current reference',async()=>{
  const f=dlpSelectorFixture(Promise.resolve({ok:true,body:{policies:[{id:'saved-policy',name:'Protection'},{id:'other',name:'Other'}]}}));await f.start();
  assert.equal(f.select.value,'saved-policy');assert.equal(f.select.disabled,false);assert.equal(f.select.options[1].text,'Protection');assert.equal(f.select.options.length,3);
});
