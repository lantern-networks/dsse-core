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
