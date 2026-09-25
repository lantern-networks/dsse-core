import test from 'node:test';import assert from 'node:assert/strict';import vm from 'node:vm';import {readFileSync} from 'node:fs';
const source=readFileSync(new URL('./networkzones.js',import.meta.url),'utf8');
const context=apiFetch=>{const c=vm.createContext({apiFetch});vm.runInContext(source,c);return c;};
test('membership includes every site and supports IDs that coincide with object properties',async()=>{
 const c=context(async(method,path)=>({ok:true,body:path==='/admin/sites'?{sites:[{site_id:'a',name:'Site A'},{site_id:'b'}]}:{networks:path.includes('/a/')?[{kind:'network',network_id:'net-1'},{kind:'network',network_id:'__proto__'},{kind:'fqdn',fqdn:'wiki.example'}]:[{kind:'network',network_id:'net-1'}]}}));
 const result=await c.nzSiteMembership();assert.deepEqual(JSON.parse(JSON.stringify(result)),{'net-1':['Site A','b'],['__proto__']:['Site A']});
});
test('HTTP failures and incomplete catalog responses never become an empty membership result',async()=>{
 for(const reply of [{ok:false,status:503},{ok:true,body:{}},{ok:true,body:{networks:{}}},{ok:true,body:{networks:[{}]}},{ok:true,body:{networks:[{kind:'network'}]}},{ok:true,body:{networks:[{kind:'fqdn'}]}}]){
  const c=context(async(method,path)=>path==='/admin/sites'?{ok:true,body:{sites:[{site_id:'a'}]}}:reply);await assert.rejects(c.nzSiteMembership());
 }
 for(const sites of [undefined,{},[{}],[{site_id:'a',name:{}}]]){const c=context(async()=>({ok:true,body:{sites}}));await assert.rejects(c.nzSiteMembership());}
 const offline=context(async()=>{throw Error('offline');});await assert.rejects(offline.nzSiteMembership());
});
test('an explicit empty or null slice is a valid empty catalog',async()=>{
 for(const sites of [[],null]){const c=context(async()=>({ok:true,body:{sites}}));assert.equal(Object.keys(await c.nzSiteMembership()).length,0);}
 for(const networks of [[],null]){const c=context(async(method,path)=>({ok:true,body:path==='/admin/sites'?{sites:[{site_id:'a'}]}:{networks}}));assert.equal(Object.keys(await c.nzSiteMembership()).length,0);}
});
test('failed membership reads show Retry before creating catalog mutation controls',async()=>{
 const states=[];const c=context(async(method,path)=>path==='/admin/vlan-objects'?{ok:true,body:{objects:[{id:'net',cidrs:['192.0.2.0/24']}]}}:path==='/admin/sites'?{ok:true,body:{sites:[{site_id:'a'}]}}:{ok:false,status:503});
 c.uiState=(host,state,message,action)=>states.push({state,message,action});c.freshRender=()=>()=>true;c.bl=v=>v.en;
 await c.renderZones({appendChild(){assert.fail('mutation UI rendered with unknown membership');}});assert.deepEqual(states.map(s=>s.state),['loading','error']);assert.equal(states[1].action.label,'Retry');assert.equal(typeof states[1].action.onClick,'function');
});
test('an obsolete failed read cannot replace the current screen',async()=>{
 const states=[];const c=context(async()=>{throw Error('old failure');});c.uiState=(host,state)=>states.push(state);c.freshRender=()=>()=>false;await c.renderZones({});assert.deepEqual(states,['loading']);
});
test('network create requires a matching acknowledgement and catalog readback',()=>{
 const c=context(async()=>({ok:true}));
 const request={id:'net-new',name:'New network',class:'server',cidrs:['192.0.2.0/24']};
 const saved={...request,tenant_id:'tenant_lab'};
 for(const response of [null,{ok:true,status:200,body:null},{ok:true,status:200,body:{}},
  {ok:true,status:200,body:{...saved,name:'Other'}},{ok:true,status:202,body:saved}]) {
  assert.equal(c.nzSavedObject(response,request),false);
 }
 assert.equal(c.nzSavedObject({ok:true,status:200,body:saved},request),true);
 for(const response of [{ok:false,status:503},{ok:true,body:{}}]) assert.throws(()=>c.nzObjectReadback(response,request));
 for(const response of [{ok:true,body:{objects:[{}]}},{ok:true,body:{objects:[{...saved,name:'Other'}]}},
  {ok:true,body:{objects:[saved,saved]}}]) assert.equal(c.nzObjectReadback(response,request),false);
 assert.equal(c.nzObjectReadback({ok:true,body:{objects:[saved]}},request),true);
});
test('network delete requires the targeted acknowledgement and absence in a valid catalog',()=>{
 const c=context(async()=>({ok:true}));
 const id='net-old';
 for(const response of [{ok:false,status:503},{ok:true,body:{}}]) assert.throws(()=>c.nzDeletionReadback(response,id));
 assert.equal(c.nzDeletionReadback({ok:true,body:{objects:[{}]}},id),false);
 assert.equal(c.nzDeletionReadback({ok:true,body:{objects:[{id}]}},id),false);
 assert.equal(c.nzDeletionReadback({ok:true,body:{objects:[{id:'net-other'}]}},id),true);
});
