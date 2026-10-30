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

test('identity directory groups named like Object properties remain selectable',()=>{
 const tree=context.identityTreeFromDirectory([
  {department:'__proto__',subject:'alice',display_name:'Alice'},
  {department:'constructor',subject:'bob',display_name:'Bob'},
  {department:'Finance',subject:'cara',display_name:'Cara'},
 ]);
 assert.deepEqual(JSON.parse(JSON.stringify(tree)),[
  {group:'Finance',people:[{id:'cara',label:'Cara'}]},
  {group:'__proto__',people:[{id:'alice',label:'Alice'}]},
  {group:'constructor',people:[{id:'bob',label:'Bob'}]},
 ]);
 assert.equal(vm.runInContext('({}).alice',context),undefined);
});

test('an IdP group named __proto__ starts collapsed and can be expanded',()=>{
 const make=(tag,attrs={},children=[])=>{
  const node={tag,className:attrs.class||'',style:{},children:[],value:attrs.value||'',checked:false,
   textContent:attrs.text||'',events:{},classList:{add(){},toggle(){}},
   appendChild(child){this.children.push(child);return child},
   addEventListener(name,fn){this.events[name]=fn}};
  for(const child of (Array.isArray(children)?children:[children])) if(child) node.appendChild(child);
  return node;
 };
 const c=vm.createContext({bl:b=>b.en,el:make,uiBadge:(label)=>make('span',{text:label})});
 vm.runInContext(readFileSync(new URL('./rules.js',import.meta.url),'utf8'),c);
 const picker=c.subjectPicker('Source',[],{identityGroups:true,idpTree:[{group:'__proto__',people:[{id:'alice',label:'Alice'}]}]});
 const find=(node,cls)=>{
  if(node.className.split(' ').includes(cls)) return node;
  for(const child of node.children){const found=find(child,cls);if(found)return found}
  return null;
 };
 const person=find(picker.el,'subject-idp-person');
 const expand=find(picker.el,'subject-idp-expand');
 assert.equal(person.style.display,'none');
 expand.events.click();
 assert.equal(person.style.display,'');
});

test('max sign-in age keeps omitted, one-request, and exact positive seconds distinct',()=>{
 assert.equal(context.maxAgeMinutesFromAction({}), '');
 assert.equal(context.maxAgeMinutesFromAction({max_age_seconds:0}), '0');
 assert.equal(context.maxAgeMinutesFromAction({max_age_seconds:90}), '1.5');
 assert.equal(context.parseMaxAgeMinutes(''), null);
 assert.equal(context.parseMaxAgeMinutes('0'), 0);
 assert.equal(context.parseMaxAgeMinutes('1.5'), 90);
 assert.equal(context.parseMaxAgeMinutes(context.maxAgeMinutesFromAction({max_age_seconds:1})), 1);
 assert.equal(context.parseMaxAgeMinutes(context.maxAgeMinutesFromAction({max_age_seconds:Number.MAX_SAFE_INTEGER}), Number.MAX_SAFE_INTEGER), Number.MAX_SAFE_INTEGER);
 for(const bad of ['-1','NaN','Infinity','1e3','0.01','1.01','0.000000000001','9007199254740991']) {
  assert.throws(()=>context.parseMaxAgeMinutes(bad), undefined, bad);
 }
});
