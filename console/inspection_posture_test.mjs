import {readFileSync} from 'node:fs';import vm from 'node:vm';import test from 'node:test';import assert from 'node:assert/strict';
const context=vm.createContext({bl:b=>b.en});vm.runInContext(readFileSync(new URL('./effective_policy.js',import.meta.url),'utf8'),context);
const settings={tenant_id:'operator',scope:'deployment',default_mode:'decrypt_all',configurable:true,runtime_available:true,can_manage_rules:true,known_bypass_enabled:true,decrypt_allowlist_hosts:[],decrypt_allowlist_groups:[],bypass_groups:[],intercept_hosts:['*'],effective_bypass:[],auth_decrypt_groups:[],saas_bypass_groups:[]};
test('inspection controls require explicit scope, tenant, capabilities and complete settings',()=>{context.validatedInspectionPosture(settings,{tenant_id:'operator'});for(const body of [null,{}, {...settings,tenant_id:'other'},{...settings,scope:'tenant'},{...settings,configurable:undefined},{...settings,decrypt_allowlist_hosts:undefined},{...settings,auth_decrypt_groups:{}},{...settings,default_mode:'other'}]){if(body?.decrypt_allowlist_hosts===undefined&&body)delete body.decrypt_allowlist_hosts;assert.throws(()=>context.validatedInspectionPosture(body,{tenant_id:'operator'}))};assert.throws(()=>context.validatedInspectionPosture(settings,{}))});
test('a successful write must match the chosen inspection fields',()=>{context.validatedInspectionMutation({ok:true,status:200,body:{...settings,default_mode:'bypass_default'}},settings,{mode:'bypass_default'});for(const response of [{ok:true,status:202,body:settings},{ok:true,status:200,body:{}},{ok:true,status:200,body:settings},{ok:true,status:200,body:{...settings,tenant_id:'other',default_mode:'bypass_default'}}])assert.throws(()=>context.validatedInspectionMutation(response,settings,{mode:'bypass_default'}));assert.throws(()=>context.validatedInspectionMutation({ok:false,status:500,body:{error:'save failed'}},settings,{}),/save failed/)});
test('allowlist response matching accepts normalization but rejects missing selections',()=>{context.validatedInspectionMutation({ok:true,status:200,body:{...settings,decrypt_allowlist_hosts:['wiki.invalid']}},settings,{decrypt_allowlist_hosts:[' WIKI.invalid ','wiki.invalid']});assert.throws(()=>context.validatedInspectionMutation({ok:true,status:200,body:settings},settings,{decrypt_allowlist_groups:['openai']}))});
test('pending operation suppresses another write and restores original disabled controls',async()=>{const control={disabled:false},readonly={disabled:true},result={querySelectorAll:s=>s==='.posture-error'?[]:[control,readonly],isConnected:true};let release,calls=0;const a=context.inspectionPostureMutation(result,()=>{calls++;return new Promise(r=>release=r)});assert.equal(control.disabled,true);await context.inspectionPostureMutation(result,()=>calls++);assert.equal(calls,1);release(false);await a;assert.equal(control.disabled,false);assert.equal(readonly.disabled,true)});
test('detached view never submits a deferred posture change',async()=>{let calls=0;context.apiFetch=async()=>calls++;await context.saveInspectionPatch({isConnected:false},settings,{},'saved');assert.equal(calls,0)});
test('device-dependent and absent inspection decisions are not presented as inspected',()=>{context.uiBadge=(text,kind)=>({text,kind});for(const [decision,text,kind]of [['depends_on_device','Depends on the device','warn'],['bypass','Not inspected','warn'],['inspect','Inspected','ok'],['unknown','Not determined','off'],[undefined,'Not determined','off']]){assert.deepEqual(context.epInspectionBadge({decision}),{text,kind})}});
test('optional device scope must be boolean when supplied',()=>{context.validatedInspectionPosture({...settings,device_scoped:true},{tenant_id:'operator'});for(const value of ['false',1,{},null])assert.throws(()=>context.validatedInspectionPosture({...settings,device_scoped:value},{tenant_id:'operator'}))});

test('legacy service selection is separate from a tenant bypass and operator cleanup',async()=>{
 const mk=(tag,attrs={},...children)=>({tag,...attrs,children:children.flat(Infinity).filter(Boolean),events:{},addEventListener(name,fn){this.events[name]=fn}});
 context.el=mk;context.uiBadge=(text,kind)=>mk('badge',{text,kind});context.apiFetch=async()=>({ok:true,body:[]});
 const walk=n=>[n,...(n.children||[]).flatMap(walk)];
 for(const configurable of [false,true]){
  const data={...settings,configurable,saas_bypass_groups:[{name:'google_optimize',selected:true}]};
  const tree=await context.buildSaasBypassSection(data,{}),nodes=walk(tree);
  const toggle=nodes.find(n=>n.tag==='button'&&n.text==='Do not inspect it');assert.ok(toggle);assert.equal(toggle.disabled,false);
  const clear=nodes.find(n=>n.tag==='button'&&n.text==='Clear older selection');assert.ok(clear);assert.equal(clear.disabled,!configurable);
  assert.ok(nodes.some(n=>n.text==='No service bypass'));assert.ok(nodes.some(n=>n.text?.includes('It does not grant a bypass.')));
 }
 context.apiFetch=async()=>({ok:true,body:[{id:'current',tenant_id:'operator',destination:['bi-grp-google_optimize'],action:{inspection:'bypass'},status:'active'}]});
 const nodes=walk(await context.buildSaasBypassSection({...settings,saas_bypass_groups:[{name:'google_optimize',selected:true}]},{}));
 assert.ok(nodes.some(n=>n.text==='Bypass rule saved'));assert.ok(nodes.some(n=>n.text==='Inspect it'));
});
test('clearing a legacy selection retains other selections and does not submit a rule mutation',async()=>{
 const originalMutation=context.inspectionPostureMutation,originalSave=context.saveInspectionPatch;let saved;
 try{
 context.inspectionPostureMutation=async(_result,fn)=>fn();context.saveInspectionPatch=async(_result,_data,patch)=>{saved=patch;return true};context.apiFetch=async()=>({ok:true,body:[]});
 const tree=await context.buildSaasBypassSection({...settings,saas_bypass_groups:[{name:'google_optimize',selected:true},{name:'m365_optimize',selected:true}]},{});
 const walk=n=>[n,...(n.children||[]).flatMap(walk)];const clear=walk(tree).find(n=>n.tag==='button'&&n.text==='Clear older selection');await clear.events.click();
 assert.deepEqual(JSON.parse(JSON.stringify(saved)),{bypass_groups:['m365_optimize']});
 }finally{context.inspectionPostureMutation=originalMutation;context.saveInspectionPatch=originalSave}
});
