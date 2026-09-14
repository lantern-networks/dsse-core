import {readFileSync} from 'node:fs';import vm from 'node:vm';import assert from 'node:assert/strict';import test from 'node:test';
const source=readFileSync(new URL('./dlppolicies.js',import.meta.url),'utf8');
function fixture(overrides={}){
 const states=[],buttons=[];const defaults={policies:[],classifiers:[],datasets:[],domains:[]};
 const el=(tag,props={},children=[])=>{if(tag==='button')buttons.push(props.text);return {appendChild(){},innerHTML:'',style:{}}};
 const context=vm.createContext({el,bl:x=>x.en,uiState:(_node,state,_message,retry)=>states.push({state,retry}),freshRender:()=>()=>true,emptyBox:()=>({}),apiFetch:async(_method,path)=>{const key={'/admin/dlp-policies':'policies','/admin/dlp-classifiers':'classifiers','/admin/dlp-fingerprints':'datasets','/admin/organization-domains':'domains'}[path];return overrides[key]||{ok:true,status:200,body:{[key]:defaults[key]}};}});
 vm.runInContext(source,context);return {context,states,buttons,el};
}
for(const key of ['policies','classifiers','datasets','domains']){
 for(const [name,response] of Object.entries({http:{ok:false,status:503},missing:{ok:true,body:{}},shape:{ok:true,body:{[key]:{}}},entry:{ok:true,body:{[key]:[42]}}})){
 test(`${key} ${name} failure disables editing and offers retry`,async()=>{const f=fixture({[key]:response});await f.context.renderDLPPoliciesView(f.el('div'));assert.equal(f.states.at(-1).state,'error');assert.equal(f.states.at(-1).retry.label,'Retry');assert.equal(f.buttons.includes('+ Add policy'),false);});
 }
}
test('explicit null empty slices are valid, and successful empty data enables creation',async()=>{const f=fixture(Object.fromEntries(['policies','classifiers','datasets','domains'].map(key=>[key,{ok:true,body:{[key]:null}}])));await f.context.renderDLPPoliciesView(f.el('div'));assert.equal(f.buttons.includes('+ Add policy'),true);assert.equal(f.states.some(s=>s.state==='error'),false);});
test('obsolete request failure does not replace a newer render',async()=>{const f=fixture({classifiers:{ok:false,status:503}});f.context.freshRender=()=>()=>false;await f.context.renderDLPPoliciesView(f.el('div'));assert.deepEqual(f.states.map(s=>s.state),['loading']);});

test('risk counts require nonnegative safe whole numbers',()=>{const f=fixture();for(const value of ['', '12x','1.5','-1','1e3','Infinity','9007199254740992'])assert.equal(f.context.dlpWholeCount(value),null,value);for(const [value,want]of [['0',0],['12',12],[' 12 ',12],['9007199254740991',9007199254740991]])assert.equal(f.context.dlpWholeCount(value),want);});
function saveFixture(raw='12',types='2'){
 const fields={},writes=[],submit={disabled:false},saveError={style:{},scrollIntoView(){}};
 const field=(name,value)=>({get:()=>value,validate:()=>true,focus(){},setError:message=>fields[name]=message});
 const context=vm.createContext({bl:x=>x.en,submit,saveError,nameF:field('name','Observe'),idFields:[{id:'email',f:{get:()=>true}}],drEnableF:{get:()=>true},drCountF:field('count',raw),drTypesF:field('types',types),drSameF:{get:()=>true},drWinF:{get:()=> '300'},drClassF:{get:()=> 'any'},actionF:{get:()=> 'observe'},scopeF:{get:()=> 'any'},existing:null,m:{close(){}},render(){},uiToast(){},_policies:[],apiFetch:async(...args)=>{writes.push(args);return {ok:true,body:{policies:[]}}}});
 vm.runInContext(source.slice(source.indexOf('function dlpWholeCount'),source.indexOf('async function renderDLPPoliciesView')),context);
 const start=source.indexOf('    async function onSave()');const end=source.indexOf('\n  }\n\n  async function remove',start);vm.runInContext(source.slice(start,end),context);
 return {context,writes,fields,submit,saveError};
}
test('invalid risk input and all-zero thresholds do not submit',async()=>{for(const [a,b]of [['12x','2'],['12','1.2'],['0','0']]){const f=saveFixture(a,b);await f.context.onSave();assert.equal(f.writes.length,0);assert.ok(Object.values(f.fields).some(Boolean));assert.equal(f.submit.disabled,false);}});
test('in-flight saves coalesce and an error stays in the editor with retry enabled',async()=>{const f=saveFixture();let reject;f.context.apiFetch=(...args)=>{f.writes.push(args);return new Promise((_resolve,r)=>reject=r)};const first=f.context.onSave();assert.equal(f.submit.disabled,true);await f.context.onSave();assert.equal(f.writes.length,1);reject(new Error('save unavailable'));await first;assert.equal(f.saveError.textContent,'save unavailable');assert.equal(f.saveError.style.display,'');assert.equal(f.submit.disabled,false);f.context.apiFetch=async(...args)=>{f.writes.push(args);return {ok:true,body:{policies:[]}}};await f.context.onSave();assert.equal(f.writes.length,2);assert.equal(f.writes[1][2].device_risk[0].min_count,12);});
