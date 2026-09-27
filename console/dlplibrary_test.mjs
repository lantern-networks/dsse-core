import {readFileSync} from 'node:fs';import vm from 'node:vm';import assert from 'node:assert/strict';import test from 'node:test';
const shared=readFileSync(new URL('./dlplibrary.js',import.meta.url),'utf8');
const definitions={
 classifiers:{file:'dlpclassifiers.js',render:'renderDLPClassifiersView',path:'/admin/dlp-classifiers',add:'+ Add identifier',valid:[{name:'project_code',kind:'keyword',keywords:['BLUEFIN']}]},
 values:{file:'dlpallowlist.js',render:'renderDLPAllowlistView',path:'/admin/dlp-allowlist',add:'+ Add value',valid:['BLUEFIN']},
 datasets:{file:'dlpfingerprints.js',render:'renderDLPFingerprintsView',path:'/admin/dlp-fingerprints',add:'+ Add dataset',valid:[{name:'customer_record',count:1}]},
};
const response=(key,rows,tenant='tenant')=>({ok:true,status:200,body:{tenant_id:tenant,[key]:rows}});
const organization={ok:true,status:200,body:{tenant_id:'tenant'}};
function fixture(key,initial){
 const states=[],buttons=[],writes=[],fields={},modals=[],toasts=[];const def=definitions[key];
 const el=(tag,props={},children=[])=>{const n={tag,...props,style:{},isConnected:true,children:[].concat(children),appendChild(c){this.children.push(c)},querySelectorAll:()=>[],scrollIntoView(){}};if(tag==='button')buttons.push(n);return n};
 const context=vm.createContext({el,bl:v=>v.en,operateTenant:'tenant',freshRender:h=>{const seq=h.seq=(h.seq||0)+1;return ()=>seq===h.seq},uiState:(node,state,message,retry)=>states.push({node,state,message,retry}),emptyBox:()=>el('div'),simpleTable:()=>el('table'),uiBadge:()=>el('span'),uiConfirm:async()=>true,
  uiToast:(...args)=>toasts.push(args),uiField:o=>{const f={value:o.value||'',el:{querySelector:()=>({addEventListener(){}})},get(){return this.value},validate:()=>true,focus(){},setError(){}};fields[o.name]=f;return f},uiModal:o=>{const m={...o,closed:false,close(){this.closed=true}};modals.push(m);return m},
  apiFetch:async(method,path,body)=>{if(path==='/admin/tenant')return organization;if(method==='GET')return initial||response(key,def.valid);writes.push({method,path,body});return response(key,body?.[key]||[])}});
 vm.runInContext(shared,context);vm.runInContext(readFileSync(new URL('./'+def.file,import.meta.url),'utf8'),context);
 const host=el('div');return {context,host,states,buttons,writes,fields,modals,toasts,def,render:()=>context[def.render](host)};
}
for(const [key,def]of Object.entries(definitions)){
 const malformed={http:{ok:false,status:503},missing:{ok:true,status:200,body:{tenant_id:'tenant'}},nullBody:{ok:true,status:200,body:null},wrongShape:response(key,{}),wrongEntry:response(key,[42]),wrongTenant:response(key,def.valid,'foreign'),missingTenant:{ok:true,status:200,body:{[key]:def.valid}}};
 for(const [kind,r]of Object.entries(malformed))test(`${key}: ${kind} refuses editing, then valid reload restores it`,async()=>{const f=fixture(key,r);await f.render();assert.equal(f.states.at(-1).state,'error');assert.equal(f.buttons.some(b=>b.text===def.add),false);f.context.apiFetch=async(_method,path)=>path==='/admin/tenant'?organization:response(key,def.valid);await f.states.at(-1).retry.onClick();assert.equal(f.buttons.some(b=>b.text===def.add),true)});
 test(`${key}: explicit null empty slice can be edited`,async()=>{const f=fixture(key,response(key,null));await f.render();assert.equal(f.buttons.some(b=>b.text===def.add),true)});
 test(`${key}: a late read does not render into a discarded view`,async()=>{const f=fixture(key);let resolve;f.context.apiFetch=async(_method,path)=>path==='/admin/tenant'?organization:new Promise(r=>resolve=r);const task=f.render();f.host.isConnected=false;resolve(response(key,def.valid));await task;assert.deepEqual(f.states.map(s=>s.state),['loading']);assert.equal(f.buttons.length,0)});
}
test('invalid classifier details, duplicate names and invalid counts are rejected without echoing values',()=>{
 const f=fixture('classifiers');const bad={classifiers:[[{name:'project_code',kind:'regex',pattern:42}],[{name:'project_code',kind:'keyword',keywords:'PRIVATE-INPUT'}],[{name:'project_code',kind:'keyword',keywords:['PRIVATE-INPUT'],case_insensitive:'true'}]],datasets:[[{name:'records',count:-1}],[{name:'records',count:1.5}],[{name:'records',count:9007199254740992}]],values:[[''],['PRIVATE-INPUT','PRIVATE-INPUT']]};
 for(const [key,lists]of Object.entries(bad))for(const rows of lists)assert.throws(()=>f.context.dlpLibraryList(response(key,rows),key,'tenant'),e=>!e.message.includes('PRIVATE-INPUT'));
});
test('tenant change during write preflight sends no mutation',async()=>{
 const f=fixture('values');await f.render();f.buttons.find(b=>b.text===f.def.add).onClick();f.fields.value.value='NEW';
 f.context.apiFetch=async(method,path,body)=>{if(method==='GET')return {...organization,body:{tenant_id:'foreign'}};f.writes.push(body);return response('values',body.values)};
 await f.modals.at(-1).footer.find(b=>b.text==='Add').onClick();assert.equal(f.writes.length,0);assert.equal(f.modals.at(-1).closed,false);
});
test('unknown successful write is not reported saved and cannot be resent before reload',async()=>{
 const f=fixture('values');await f.render();f.buttons.find(b=>b.text===f.def.add).onClick();f.fields.value.value='NEW';const save=f.modals.at(-1).footer.find(b=>b.text==='Add');
 f.context.apiFetch=async(method,path,body)=>{if(method==='GET')return organization;f.writes.push(body);return {ok:true,status:200,body:{tenant_id:'tenant'}}};
 await save.onClick();await save.onClick();assert.equal(f.writes.length,1);assert.equal(f.writes[0].expected_tenant_id,'tenant');assert.equal(f.toasts.length,0);assert.equal(f.modals.at(-1).closed,false);assert.equal(f.fields.value.value,'NEW');assert.equal(f.states.at(-1).state,'error');
});
test('a detached editor cannot send, and an old completion cannot show success in the next page',async()=>{
 const f=fixture('values');await f.render();f.buttons.find(b=>b.text===f.def.add).onClick();f.fields.value.value='NEW';const save=f.modals.at(-1).footer.find(b=>b.text==='Add');f.host.isConnected=false;await save.onClick();assert.equal(f.writes.length,0);
 f.host.isConnected=true;let resolve;f.context.apiFetch=async(method,path,body)=>{if(method==='GET')return organization;f.writes.push(body);return new Promise(r=>resolve=r)};const task=save.onClick();await new Promise(r=>setImmediate(r));f.host.isConnected=false;resolve(response('values',['BLUEFIN','NEW']));await task;assert.equal(f.toasts.length,0);assert.equal(f.writes.length,1);
});
